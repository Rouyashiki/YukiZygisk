/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Anonymous ioctl control file.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#include <linux/cred.h>
#include <linux/anon_inodes.h>
#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/magic.h>
#include <linux/pid.h>
#include <linux/printk.h>
#include <linux/rwsem.h>
#include <linux/ptrace.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include "feature/api.h"
#include "core/bootstrap.h"
#include "core/auth.h"
#include "core/control.h"
#include "host/host.h"
#include "host/runtime.h"
#include "uapi/yukizygisk.h"
#include "uapi/viola.h"

static atomic_t yz_control_available = ATOMIC_INIT(0);
static DECLARE_RWSEM(yz_control_sem);

#define YZ_PER_USER_RANGE 100000

#ifndef fd_file
#define fd_file(fd) ((fd).file)
#endif

static bool yz_is_appuid(uid_t uid)
{
	return uid % YZ_PER_USER_RANGE >= 10000;
}

static int yz_ioctl_set_dlopen(void __user *arg)
{
	struct yz_dlopen_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	yz_config_set_linker_offsets(cmd.dlopen_offset, cmd.dlsym_offset);
	return 0;
}

static int yz_ioctl_set_dlopen32(void __user *arg)
{
	struct yz_dlopen_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	yz_config_set_compat_linker_offsets(cmd.dlopen_offset,
					    cmd.dlsym_offset);
	return 0;
}

static int yz_ioctl_set_yukilinker(void __user *arg)
{
	struct yz_yukilinker_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	yz_config_set_first_stage_loader(cmd.enabled != 0);
	return 0;
}

static int yz_ioctl_set_native_targets(void __user *arg)
{
	struct yz_native_targets_cmd *cmd;
	int ret;

	cmd = memdup_user(arg, sizeof(*cmd));
	if (IS_ERR(cmd))
		return PTR_ERR(cmd);
	ret = yz_config_set_native_targets(cmd);
	kfree(cmd);
	return ret;
}

static int yz_ioctl_restore_native_load_policy(void __user *arg)
{
	struct yz_native_load_policy_cmd cmd;
	struct task_struct *task;
	int ret;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	rcu_read_lock();
	task = get_pid_task(find_vpid(cmd.pid), PIDTYPE_PID);
	rcu_read_unlock();
	ret = task ? yz_auth_target_task(task) : yz_auth_target_report(cmd.pid, 0);
	if (task)
		put_task_struct(task);
	if (ret)
		return ret;
	return yz_load_policy_restore_native((pid_t)cmd.pid);
}

static int yz_ioctl_allow_module_load_policy(void __user *arg)
{
	struct yz_module_load_policy_cmd cmd;
	struct task_struct *task;
	const struct cred *cred;
	struct fd payload;
	struct file *file;
	bool directory;
	bool source_image;
	int ret;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	if (!cmd.pid || cmd.dirfd < 0)
		return -EINVAL;
	rcu_read_lock();
	task = get_pid_task(find_vpid(cmd.pid), PIDTYPE_PID);
	rcu_read_unlock();
	if (!task)
		return -ESRCH;
	ret = yz_auth_target_task(task);
	if (ret) {
		put_task_struct(task);
		return ret;
	}
	cred = get_task_cred(task);
	payload = fdget(cmd.dirfd);
	file = fd_file(payload);
	if (!file) {
		ret = -EBADF;
		goto out_cred;
	}
	directory = S_ISDIR(file_inode(file)->i_mode);
	source_image = S_ISREG(file_inode(file)->i_mode) &&
		       file_inode(file)->i_sb->s_magic == TMPFS_MAGIC &&
		       (file->f_mode & FMODE_READ) &&
		       !(file->f_mode & FMODE_WRITE);
	if (!directory && !source_image) {
		ret = -EINVAL;
		goto out_fd;
	}
	if (!yz_host_is_zygote(cred) &&
	    !(source_image &&
	      yz_runtime_is_native(task->tgid,
				   READ_ONCE(task->start_boottime)))) {
		ret = -EPERM;
		goto out_fd;
	}
	ret = yz_load_policy_allow_module(task, file, cred);
out_fd:
	fdput(payload);
out_cred:
	put_cred(cred);
	put_task_struct(task);
	pr_info("yukizygisk: module load policy request pid=%u fd=%d err=%d\n",
		cmd.pid, cmd.dirfd, ret);
	return ret;
}

static int yz_ioctl_get_safemode(void __user *arg)
{
	struct yz_safemode_status_cmd cmd;
	int ret;

	ret = yz_safemode_get_status(&cmd);
	if (ret)
		return ret;
	if (copy_to_user(arg, &cmd, sizeof(cmd)))
		return -EFAULT;
	return 0;
}

static int yz_ioctl_get_zygote_variants(void __user *arg)
{
	struct yz_zygote_variants_cmd cmd;
	int ret;

	ret = yz_safemode_get_variants(&cmd);
	if (ret)
		return ret;
	if (copy_to_user(arg, &cmd, sizeof(cmd)))
		return -EFAULT;
	return 0;
}

static int yz_ioctl_get_runtime(void __user *arg)
{
	struct yz_runtime_query_cmd cmd;
	struct yz_runtime_record *entries = NULL;
	void __user *user_entries;
	u32 capacity;
	int ret;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	if (cmd.capacity > YZ_RUNTIME_RECORD_MAX)
		return -EINVAL;
	capacity = cmd.capacity;
	user_entries = u64_to_user_ptr(cmd.entries);
	if (capacity && !user_entries)
		return -EINVAL;
	if (capacity) {
		entries = kvcalloc(capacity, sizeof(*entries), GFP_KERNEL);
		if (!entries)
			return -ENOMEM;
	}

	cmd.count = 0;
	ret = yz_runtime_query(entries, capacity, &cmd);
	if (!ret && cmd.count &&
	    copy_to_user(user_entries, entries, cmd.count * sizeof(*entries)))
		ret = -EFAULT;
	if (!ret && copy_to_user(arg, &cmd, sizeof(cmd)))
		ret = -EFAULT;
	kvfree(entries);
	return ret;
}

static int yz_ioctl_report_runtime(void __user *arg)
{
	struct yz_runtime_report_cmd cmd;
	int ret;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	ret = yz_auth_target_report(cmd.pid, cmd.generation);
	if (ret)
		return ret;
	cmd.module_id[sizeof(cmd.module_id) - 1] = '\0';
	return yz_runtime_report(&cmd);
}

static int yz_ioctl_get_root_status(void __user *arg)
{
	struct yz_host_root_status status = { 0 };
	struct yz_root_status_cmd cmd = { 0 };

	yz_host_get_root_status(&status);
	cmd.owner = status.owner;
	cmd.mask = status.mask;
	cmd.flags = status.flags;
	if (yz_host_policy_uses_fallback() &&
	    !yz_host_policy_cache_ready())
		yz_events_emit_policy_refresh(status.owner,
					      YZ_POLICY_REFRESH_ALL);

	if (copy_to_user(arg, &cmd, sizeof(cmd)))
		return -EFAULT;
	return 0;
}

static int yz_ioctl_uid_should_umount(void __user *arg)
{
	struct yz_uid_policy_cmd cmd;
	bool should_umount;
	int ret;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	ret = yz_host_uid_should_umount((uid_t)cmd.uid, &should_umount);
	if (ret) {
		if (ret == -EAGAIN) {
			struct yz_host_root_status status = { 0 };

			yz_host_get_root_status(&status);
			yz_events_emit_policy_refresh(status.owner, cmd.uid);
		}
		return ret;
	}
	cmd.should_umount = should_umount ? 1 : 0;
	if (copy_to_user(arg, &cmd, sizeof(cmd)))
		return -EFAULT;
	return 0;
}

static int yz_ioctl_set_policy_cache(void __user *arg)
{
	struct yz_policy_cache_cmd cmd;
	struct fd fd;
	int ret;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	if (cmd.fd < 0 || cmd.reserved != 0)
		return -EINVAL;

	fd = fdget(cmd.fd);
	if (!fd_file(fd))
		return -EBADF;
	ret = yz_host_install_policy_cache(fd_file(fd));
	fdput(fd);
	return ret;
}

static int yz_ioctl_umount_pid(void __user *arg)
{
	struct yz_umount_pid_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	return yz_host_umount_pid((pid_t)cmd.pid);
}

struct yz_unmap_tw {
	struct callback_head cb;
	struct yz_auth_ticket ticket;
	struct mm_struct *mm;
	unsigned long addr[YZ_MAX_UNMAP_SEGS];
	unsigned long size[YZ_MAX_UNMAP_SEGS];
	unsigned int n;
	unsigned int retry;
};

static void yz_unmap_tw_func(struct callback_head *cb)
{
	struct yz_unmap_tw *tw = container_of(cb, struct yz_unmap_tw, cb);
	struct pt_regs *regs = task_pt_regs(current);
	unsigned long pc = regs ? instruction_pointer(regs) : 0;
	unsigned int i;

	if (current->flags & PF_EXITING || current->mm != tw->mm ||
	    !yz_auth_ticket_begin(&tw->ticket))
		goto out;

	for (i = 0; i < tw->n; i++) {
		if (pc >= tw->addr[i] && pc < tw->addr[i] + tw->size[i]) {
			if (++tw->retry < 16) {
				init_task_work(&tw->cb, yz_unmap_tw_func);
				if (!yz_task_work_add(current, &tw->cb,
						      TWA_RESUME)) {
					yz_auth_end();
					return;
				}
			}
			pr_warn("yukizygisk: yz_unmap pc=0x%lx still in core "
				"after %u tries, skip pid=%d\n",
				pc, tw->retry, current->pid);
			goto unlock;
		}
	}

	for (i = 0; i < tw->n; i++) {
		pr_info("yukizygisk: yz_unmap [0x%lx +0x%lx] pid=%d\n",
			tw->addr[i], tw->size[i], current->pid);
		vm_munmap(tw->addr[i], tw->size[i]);
	}
unlock:
	yz_auth_end();
out:
	mmdrop(tw->mm);
	kfree(tw);
	module_put(THIS_MODULE);
}

static int yz_unmap_work_init(struct yz_unmap_tw *tw, struct task_struct *task)
{
	int ret = yz_auth_current_ticket(&tw->ticket);

	if (ret)
		return ret;
	task_lock(task);
	tw->mm = task->mm;
	if (tw->mm)
		mmgrab(tw->mm);
	task_unlock(task);
	if (!tw->mm)
		return -ESRCH;
	if (!try_module_get(THIS_MODULE)) {
		mmdrop(tw->mm);
		return -ENODEV;
	}
	init_task_work(&tw->cb, yz_unmap_tw_func);
	return 0;
}

static int yz_ioctl_unmap_pid(void __user *arg)
{
	struct yz_unmap_pid_cmd cmd;
	struct task_struct *task;
	struct yz_unmap_tw *tw;
	unsigned int i;
	int ret;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	if (cmd.n_segs == 0 || cmd.n_segs > YZ_MAX_UNMAP_SEGS)
		return -EINVAL;

	rcu_read_lock();
	task = get_pid_task(find_vpid(cmd.pid), PIDTYPE_PID);
	rcu_read_unlock();
	if (!task)
		return -ESRCH;
	ret = yz_auth_target_task(task);
	if (ret) {
		put_task_struct(task);
		return ret;
	}

	if (!yz_is_appuid(task_uid(task).val)) {
		pr_info("yukizygisk: yz_unmap_pid reject non-app pid=%u uid=%u\n",
			cmd.pid, task_uid(task).val);
		put_task_struct(task);
		return -EPERM;
	}

	tw = kzalloc(sizeof(*tw), GFP_KERNEL);
	if (!tw) {
		put_task_struct(task);
		return -ENOMEM;
	}
	ret = yz_unmap_work_init(tw, task);
	if (ret) {
		kfree(tw);
		put_task_struct(task);
		return ret;
	}
	tw->n = cmd.n_segs;
	for (i = 0; i < cmd.n_segs; i++) {
		tw->addr[i] = (unsigned long)cmd.addr[i];
		tw->size[i] = (unsigned long)cmd.size[i];
	}
	if (yz_task_work_add(task, &tw->cb, TWA_RESUME)) {
		mmdrop(tw->mm);
		module_put(THIS_MODULE);
		kfree(tw);
		put_task_struct(task);
		return -ESRCH;
	}
	put_task_struct(task);
	pr_info("yukizygisk: yz_unmap_pid scheduled %u seg(s) for pid=%u\n",
		cmd.n_segs, cmd.pid);
	return 0;
}

static int yz_ioctl_unmap_self(void __user *arg)
{
	struct yz_unmap_self_cmd cmd;
	struct yz_unmap_tw *tw;
	unsigned int i;
	int ret;

	if (!current->mm)
		return -EINVAL;
	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	if (cmd.n_segs == 0 || cmd.n_segs > YZ_MAX_UNMAP_SEGS)
		return -EINVAL;

	for (i = 0; i < cmd.n_segs; i++) {
		unsigned long a = (unsigned long)cmd.addr[i];
		unsigned long s = (unsigned long)cmd.size[i];

		if (a == 0 || s == 0 || a >= TASK_SIZE || s > TASK_SIZE ||
		    a + s < a || a + s > TASK_SIZE) {
			pr_warn("yukizygisk: yz_unmap_self bad seg "
				"[0x%lx +0x%lx] pid=%d\n",
				a, s, current->pid);
			return -EINVAL;
		}
	}

	tw = kzalloc(sizeof(*tw), GFP_KERNEL);
	if (!tw)
		return -ENOMEM;
	ret = yz_unmap_work_init(tw, current);
	if (ret) {
		kfree(tw);
		return ret;
	}
	tw->n = cmd.n_segs;
	for (i = 0; i < cmd.n_segs; i++) {
		tw->addr[i] = (unsigned long)cmd.addr[i];
		tw->size[i] = (unsigned long)cmd.size[i];
	}
	if (yz_task_work_add(current, &tw->cb, TWA_RESUME)) {
		mmdrop(tw->mm);
		module_put(THIS_MODULE);
		kfree(tw);
		return -ESRCH;
	}
	pr_info("yukizygisk: yz_unmap_self armed %u seg(s) pid=%d\n",
		cmd.n_segs, current->pid);
	return 0;
}

static int yz_ioctl_patch_text(void __user *arg)
{
	struct yz_patch_text_cmd cmd;
	struct task_struct *task;
	int n;
	int ret;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	if (cmd.len == 0 || cmd.len > YZ_PATCH_TEXT_MAX)
		return -EINVAL;
	if (cmd.addr == 0 || cmd.addr >= TASK_SIZE ||
	    cmd.addr + cmd.len < cmd.addr || cmd.addr + cmd.len > TASK_SIZE)
		return -EINVAL;

	rcu_read_lock();
	task = get_pid_task(find_vpid(cmd.pid), PIDTYPE_PID);
	rcu_read_unlock();
	if (!task)
		return -ESRCH;
	ret = yz_auth_target_task(task);
	if (ret) {
		put_task_struct(task);
		return ret;
	}

	n = access_process_vm(task, (unsigned long)cmd.addr, cmd.bytes, cmd.len,
			      FOLL_FORCE | FOLL_WRITE);
	put_task_struct(task);
	if (n != (int)cmd.len) {
		pr_warn("yukizygisk: yz_patch_text wrote %d/%u @0x%llx pid=%u\n",
			n, cmd.len, cmd.addr, cmd.pid);
		return -EFAULT;
	}
	pr_info("yukizygisk: yz_patch_text %u byte(s) @0x%llx pid=%u\n",
		cmd.len, cmd.addr, cmd.pid);
	return 0;
}

static long yukizygisk_ioctl_dispatch(struct file *file,
				      unsigned int request, unsigned long arg)
{
	void __user *uarg = (void __user *)arg;

	switch (request) {
	case YZ_IOCTL_HANDOFF:
		return yz_fd_handoff_submit(uarg);
	case YZ_IOCTL_SET_DLOPEN:
		return yz_ioctl_set_dlopen(uarg);
	case YZ_IOCTL_SET_DLOPEN32:
		return yz_ioctl_set_dlopen32(uarg);
	case YZ_IOCTL_RELOAD:
		yz_events_emit_reload();
		return 0;
	case YZ_IOCTL_SET_YUKILINKER:
		return yz_ioctl_set_yukilinker(uarg);
	case YZ_IOCTL_UMOUNT_PID:
		return yz_ioctl_umount_pid(uarg);
	case YZ_IOCTL_UNMAP_PID:
		return yz_ioctl_unmap_pid(uarg);
	case YZ_IOCTL_UNMAP_SELF:
		return yz_ioctl_unmap_self(uarg);
	case YZ_IOCTL_PATCH_TEXT:
		return yz_ioctl_patch_text(uarg);
	case YZ_IOCTL_SET_NATIVE_TARGETS:
		return yz_ioctl_set_native_targets(uarg);
	case YZ_IOCTL_RESTORE_NATIVE_LOAD_POLICY:
		return yz_ioctl_restore_native_load_policy(uarg);
	case YZ_IOCTL_GET_SAFEMODE:
		return yz_ioctl_get_safemode(uarg);
	case YZ_IOCTL_GET_ROOT_STATUS:
		return yz_ioctl_get_root_status(uarg);
	case YZ_IOCTL_UID_SHOULD_UMOUNT:
		return yz_ioctl_uid_should_umount(uarg);
	case YZ_IOCTL_SET_POLICY_CACHE:
		return yz_ioctl_set_policy_cache(uarg);
	case YZ_IOCTL_GET_ZYGOTE_VARIANTS:
		return yz_ioctl_get_zygote_variants(uarg);
	case YZ_IOCTL_PREPARE_RUNTIME_POLICY:
		return yz_host_prepare_runtime_policy();
	case YZ_IOCTL_ALLOW_MODULE_LOAD_POLICY:
		return yz_ioctl_allow_module_load_policy(uarg);
	case YZ_IOCTL_GET_RUNTIME:
		return yz_ioctl_get_runtime(uarg);
	case YZ_IOCTL_GET_EXIT_HISTORY_FD:
		return yz_exit_history_get_fd(uarg);
	case YZ_IOCTL_GET_HEALTH:
		return yz_exit_history_get_health(uarg);
	case YZ_IOCTL_REPORT_RUNTIME:
		return yz_ioctl_report_runtime(uarg);
	case YZ_IOCTL_DAEMON_READY:
		return -EPERM; /* Authenticated control dispatch handles readiness. */
	default:
		return -ENOTTY;
	}
}

static long yukizygisk_ioctl(struct file *file, unsigned int request,
			     unsigned long arg)
{
	long ret;

	if (request == YZ_IOCTL_GET_HEALTH ||
	    request == YZ_IOCTL_VIOLA_DAEMON_IDENTITY) {
		if (!down_read_trylock(&yz_control_sem))
			return -EAGAIN;
	} else {
		down_read(&yz_control_sem);
	}
	if (!atomic_read(&yz_control_available)) {
		ret = -ENODEV;
	} else if (request == YZ_IOCTL_DAEMON_READY ||
		   request == YZ_IOCTL_VIOLA_DAEMON_IDENTITY ||
		   request == YZ_IOCTL_VIOLA_STATUS ||
		   request == YZ_IOCTL_VIOLA_CATALOG ||
		   request == YZ_IOCTL_VIOLA_PIN_EXEC ||
		   request == YZ_IOCTL_VIOLA_ARM_EXEC ||
		   request == YZ_IOCTL_VIOLA_CLAIM ||
		   request == YZ_IOCTL_VIOLA_DELEGATE ||
		   request == YZ_IOCTL_VIOLA_COMPAT_READY ||
		   request == YZ_IOCTL_VIOLA_RECOVER_COMPAT ||
		   request == YZ_IOCTL_VIOLA_TAKE_RECOVERY ||
		   request == YZ_IOCTL_VIOLA_FINISH_RECOVERY) {
		ret = yz_auth_ioctl(file->private_data, request, (void __user *)arg);
	} else {
		ret = yz_auth_begin(file->private_data, request, (void __user *)arg);
		if (!ret) {
			ret = yukizygisk_ioctl_dispatch(file, request, arg);
			yz_auth_end();
		}
	}
	up_read(&yz_control_sem);
	return ret;
}

static int yukizygisk_release(struct inode *inode, struct file *file)
{
	(void)inode;
	yz_auth_release(file->private_data);
	module_put(THIS_MODULE);
	return 0;
}

static const struct file_operations yukizygisk_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = yukizygisk_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = yukizygisk_ioctl,
#endif
	.release = yukizygisk_release,
};

int yukizygisk_control_init(void)
{
	down_write(&yz_control_sem);
	atomic_set(&yz_control_available, 1);
	up_write(&yz_control_sem);
	pr_info("yukizygisk: anonymous control fd backend ready\n");
	return 0;
}

void yukizygisk_control_exit(void)
{
	down_write(&yz_control_sem);
	atomic_set(&yz_control_available, 0);
	up_write(&yz_control_sem);
}

bool yukizygisk_control_available(void)
{
	return atomic_read(&yz_control_available) != 0;
}

int yukizygisk_control_install_session(struct yz_auth_session *session)
{
	struct file *file;
	int fd;

	if (!yukizygisk_control_available())
		return -ENODEV;
	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0)
		return fd;
	if (!try_module_get(THIS_MODULE)) {
		put_unused_fd(fd);
		return -ENODEV;
	}

	file = anon_inode_getfile("ctl", &yukizygisk_fops, session,
				  O_RDWR | O_CLOEXEC);
	if (IS_ERR(file)) {
		module_put(THIS_MODULE);
		put_unused_fd(fd);
		return PTR_ERR(file);
	}

	fd_install(fd, file);
	return fd;
}

int yukizygisk_control_install_fd(bool launcher)
{
	struct yz_auth_session *session = yz_auth_open(launcher);
	int fd;

	if (IS_ERR(session))
		return PTR_ERR(session);
	fd = yukizygisk_control_install_session(session);
	if (fd < 0)
		yz_auth_release(session);
	return fd;
}
