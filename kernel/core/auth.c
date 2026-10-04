/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Viola process-bound control and payload admission.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include <linux/binfmts.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/elf.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/pid.h>
#include <linux/random.h>
#include <linux/rculist.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/tracepoint.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include <trace/events/sched.h>
#include <asm/ptrace.h>

#include <viola.h>
#include <viola_build.h>
#include <viola_loader.h>
#include "feature/api.h"
#include "core/auth.h"
#include "core/control.h"
#include "host/runtime.h"
#include "uapi/viola.h"
#include "uapi/viola_health.h"
#include "uapi/yukizygisk.h"

#ifndef VIOLA_KMI_ID
#error "VIOLA_KMI_ID must name this kernel build's authenticated KMI"
#endif

#define YZ_AUTH_IMAGE_MAX (64u << 20)
#define YZ_AUTH_TIMEOUT (30 * HZ)

struct yz_auth_session {
	struct list_head list;
	struct pid *owner;
	struct mm_struct *mm;
	struct file *image;
	atomic_t revoked;
	atomic_t exec_seen;
	u64 generation;
	u64 parent_generation;
	unsigned long deadline;
	u32 role;
	u32 exec_id;
	bool ready;
	bool compat_required;
	bool translated_exec; /* Kernel-observed binfmt handoff of the pinned image. */
	u8 recovery; /* 0 idle, 1 requested, 2 owned by the main daemon. */
	int recovery_error;
};

static DEFINE_MUTEX(yz_auth_lock);
static LIST_HEAD(yz_auth_sessions);
static struct yz_auth_session __rcu *yz_auth_main;
static struct yz_auth_session __rcu *yz_auth_compat;
static struct pid *yz_auth_loader_pid;
static struct mm_struct *yz_auth_loader_mm;
static struct tracepoint *yz_auth_exit_tp;
static struct tracepoint *yz_auth_exec_tp;
static bool yz_auth_exit_registered;
static bool yz_auth_exec_registered;
static bool yz_auth_enabled;
static bool yz_auth_initial_claimed;
static void *yz_auth_manifest;
static struct viola_manifest_view yz_auth_catalog;
static u64 yz_auth_epoch;
static u64 yz_auth_generation;
static int yz_auth_last_error;
static u32 yz_auth_failed_role;
static u32 yz_auth_failed_stage;
static u32 yz_auth_main_history;
static u32 yz_auth_compat_history;
static const struct {
	u32 namesz, descsz, type;
	char name[8];
	struct {
		u8 magic[8];
		u8 sha512[64];
	} descriptor;
} __packed yz_auth_loader_note
__attribute__((section(".note.viola.loader"), used, aligned(4))) = {
	6, 72, 2, { 'V', 'I', 'O', 'L', 'A', 0, 0, 0 },
	{ { 'V', 'I', 'O', 'L', 'A', 'L', 'D', 'R' }, VIOLA_LOADER_SHA512_BYTES }
};
#define yz_auth_loader_hash yz_auth_loader_note.descriptor.sha512
static const u8 yz_auth_release_id[32] = VIOLA_RELEASE_ID_BYTES;
static const u8 yz_auth_trust[32] = VIOLA_TRUST_ID_BYTES;
static const char *const yz_auth_system_names[] = {
	"/system/bin/linker64",
	"/system/lib64/libc.so",
	"/system/lib64/libm.so",
	"/system/lib64/libdl.so",
	"/apex/com.android.runtime/bin/linker64",
	"/apex/com.android.runtime/lib64/bionic/libc.so",
	"/apex/com.android.runtime/lib64/bionic/libm.so",
	"/apex/com.android.runtime/lib64/bionic/libdl.so",
};
static struct path yz_auth_system_paths[ARRAY_SIZE(yz_auth_system_names)];
static struct path yz_auth_tango_path;
/* These roots are captured from the boot image before any daemon claim.  They
 * cover the release-dependent set of Bionic libraries without trusting an
 * arbitrary read-only mount or a same-named replacement elsewhere. */
static const char *const yz_auth_system_root_names[] = {
	"/system/lib64",
	"/system/lib",
	"/apex/com.android.runtime/lib64/bionic",
	"/apex/com.android.runtime/lib/bionic",
};
static struct path yz_auth_system_roots[ARRAY_SIZE(yz_auth_system_root_names)];
/* Newer Android kernels keep is_subdir() outside their exported KMI.  Use
 * its exact KCFI-checked type.  On 5.x, retain the exported call so the module
 * loader supplies the old-CFI entry rather than a raw kallsyms address. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
static typeof(&is_subdir) yz_auth_is_subdir;
#else
#define yz_auth_is_subdir is_subdir
#endif

struct yz_auth_exec_record {
	struct pid *owner;
	struct mm_struct *mm; /* Compared only with the live, referenced owner. */
	struct file *image;
	u32 exec_id;
	unsigned long deadline;
	bool valid;
};
static DEFINE_SPINLOCK(yz_auth_exec_lock);
static struct yz_auth_exec_record yz_auth_exec_records[32];

static void yz_auth_cleanup_work_fn(struct work_struct *work);
static void yz_auth_timeout_work_fn(struct work_struct *work);
static DECLARE_WORK(yz_auth_cleanup_work, yz_auth_cleanup_work_fn);
static DECLARE_DELAYED_WORK(yz_auth_timeout_work, yz_auth_timeout_work_fn);

/* All image references have one matching deny_write_access reference. */
static void yz_auth_drop_image(struct yz_auth_session *s)
{
	struct file *image = s->image;

	WRITE_ONCE(s->image, NULL);
	if (image) {
		/* An exec tracepoint can still be comparing this pinned inode. */
		synchronize_rcu();
		allow_write_access(image);
		fput(image);
	}
}

static bool yz_auth_alive(const struct yz_auth_session *s)
{
	struct yz_auth_session *parent;

	if (!s || atomic_read(&s->revoked))
		return false;
	if (!READ_ONCE(s->ready) && READ_ONCE(s->role) >= YZ_VIOLA_LAUNCHER64 &&
	    time_after_eq(jiffies, s->deadline))
		return false;
	if (s->parent_generation) {
		parent = rcu_dereference_check(yz_auth_main,
			lockdep_is_held(&yz_auth_lock));
		if (!parent || atomic_read(&parent->revoked) ||
		    parent->generation != s->parent_generation)
			return false;
	}
	return true;
}

static void yz_auth_revoke(struct yz_auth_session *s)
{
	if (s)
		atomic_set(&s->revoked, 1);
}

static u32 yz_auth_session_payload(u32 role)
{
	if (role == YZ_VIOLA_ARMED64 || role == YZ_VIOLA_ARMED32 ||
	    role == YZ_VIOLA_DAEMON64 || role == YZ_VIOLA_DAEMON32)
		return VIOLA_ROLE_DAEMON;
	if (role == YZ_VIOLA_LAUNCHER64 || role == YZ_VIOLA_LAUNCHER32 ||
	    role == YZ_VIOLA_DELEGATED32)
		return VIOLA_ROLE_VIOLA;
	return role == YZ_VIOLA_ADMIN ? VIOLA_ROLE_CTL : 0;
}

static int yz_auth_error(u32 stage, u32 role, int error)
{
	yz_auth_failed_stage = stage;
	yz_auth_failed_role = role;
	yz_auth_last_error = error;
	return error;
}

static int yz_auth_read_image(struct file *file, void **bytes, size_t *size)
{
	loff_t length, pos = 0;
	ssize_t n;
	void *data;

	if (!S_ISREG(file_inode(file)->i_mode) ||
	    !(file->f_mode & FMODE_READ) || (file->f_mode & FMODE_WRITE))
		return -EINVAL;
	length = i_size_read(file_inode(file));
	if (length < EI_NIDENT || length > YZ_AUTH_IMAGE_MAX)
		return -EFBIG;
	data = kvmalloc(length, GFP_KERNEL);
	if (!data)
		return -ENOMEM;
	while (pos < length) {
		n = yz_kernel_read(file, data + pos, length - pos, &pos);
		if (n <= 0) {
			kvfree(data);
			return n < 0 ? n : -EIO;
		}
	}
	if (memcmp(data, ELFMAG, SELFMAG)) {
		kvfree(data);
		return -ENOEXEC;
	}
	*bytes = data;
	*size = length;
	return 0;
}

static int yz_auth_check_image(struct file *file, unsigned int role, bool compat)
{
	struct viola_entry entry;
	u8 digest[64];
	void *bytes = NULL;
	size_t size;
	int ret;

	ret = yz_auth_read_image(file, &bytes, &size);
	if (ret)
		return ret;
	if (((u8 *)bytes)[EI_CLASS] != (compat ? ELFCLASS32 : ELFCLASS64)) {
		ret = -ENOEXEC;
		goto out;
	}
	if (role == VIOLA_ROLE_VIOLA) {
		ret = viola_hash(digest, bytes, size) ||
		      memcmp(digest, yz_auth_loader_hash, sizeof(digest)) ?
		      -EKEYREJECTED : 0;
	} else if (!yz_auth_manifest ||
		   viola_manifest_find(&yz_auth_catalog, role,
			compat ? VIOLA_ABI_ARM32 : VIOLA_ABI_ARM64,
			0, &entry) || viola_check_payload(&entry, bytes, size)) {
		ret = -EKEYREJECTED;
	} else {
		ret = 0;
	}
out:
	kvfree(bytes);
	return ret;
}

static int yz_auth_freeze(struct file *file, unsigned int role, bool compat)
{
	int ret = deny_write_access(file);

	if (ret)
		return ret;
	ret = yz_auth_check_image(file, role, compat);
	if (ret)
		allow_write_access(file);
	return ret;
}

static bool yz_auth_same_image(const struct file *a, const struct file *b)
{
	return a && b && file_inode(a) == file_inode(b) &&
	       a->f_path.mnt == b->f_path.mnt;
}

static bool yz_auth_readonly_path(const struct path *path)
{
	struct inode *inode;

	if (!path || !path->dentry)
		return false;
	inode = d_inode(path->dentry);
	return inode && (sb_rdonly(inode->i_sb) ||
				(path->mnt && (path->mnt->mnt_flags & MNT_READONLY)));
}

static bool yz_auth_tango_image(const struct file *file)
{
	const struct path *path = &yz_auth_tango_path;

	/* binfmt_misc F pins its interpreter before mount namespaces are cloned.
	 * The immutable system inode remains the same across them. */
	return file && path->dentry &&
	       S_ISREG(file_inode(file)->i_mode) &&
	       sb_rdonly(file_inode(file)->i_sb) &&
	       d_inode(path->dentry) == file_inode(file);
}

/* Called at sched_process_exec, before the new program can run. The execfd
 * is selected and installed by binfmt_misc, not supplied by the interpreter.
 * Inspect it under file_lock: no allocation, hashing or reference destruction
 * is permitted in this tracepoint. s->image stays frozen for the session. */
static bool yz_auth_record_exec(struct yz_auth_session *s,
				struct linux_binprm *bprm)
{
	struct file *image = READ_ONCE(s->image);
	u32 role = READ_ONCE(s->role);
	bool translated = false;

	if ((role != YZ_VIOLA_ARMED64 && role != YZ_VIOLA_ARMED32 &&
	     role != YZ_VIOLA_DELEGATED32) || !image || !bprm->file)
		return false;
	if (!yz_auth_same_image(image, bprm->file)) {
		struct files_struct *files = current->files;
		struct fdtable *fdt;

		if (role != YZ_VIOLA_ARMED32 || !yz_auth_tango_image(bprm->file) ||
		    !bprm->have_execfd || bprm->execfd < 0 || !files)
			return false;
		spin_lock(&files->file_lock);
		fdt = files_fdtable(files);
		if ((unsigned int)bprm->execfd < fdt->max_fds)
			translated = yz_auth_same_image(image,
				rcu_dereference_raw(fdt->fd[bprm->execfd]));
		spin_unlock(&files->file_lock);
		if (!translated)
			return false;
	}
	if (atomic_cmpxchg(&s->exec_seen, 0, 1))
		return false;
	WRITE_ONCE(s->translated_exec, translated);
	return true;
}

static bool yz_auth_claim_image(const struct yz_auth_session *s,
				const struct file *exe)
{
	if (READ_ONCE(s->translated_exec))
		return s->role == YZ_VIOLA_ARMED32 && yz_auth_tango_image(exe);
	return yz_auth_same_image(s->image, exe);
}

static bool yz_auth_system_image(const struct file *file)
{
	struct inode *inode;
	unsigned int i;

	if (!file)
		return false;
	inode = file_inode(file);
	if (!S_ISREG(inode->i_mode) || !yz_auth_readonly_path(&file->f_path))
		return false;
	for (i = 0; i < ARRAY_SIZE(yz_auth_system_paths); ++i) {
		const struct path *path = &yz_auth_system_paths[i];

		if (path->dentry && path->mnt == file->f_path.mnt &&
		    d_inode(path->dentry) == file_inode(file))
			return true;
	}
	for (i = 0; i < ARRAY_SIZE(yz_auth_system_roots); ++i) {
		const struct path *root = &yz_auth_system_roots[i];

		if (root->dentry && root->mnt == file->f_path.mnt &&
		    yz_auth_is_subdir(file->f_path.dentry, root->dentry))
			return true;
	}
	return false;
}

static int yz_auth_check_mappings(struct file *exe, bool admission)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned long pc = instruction_pointer(task_pt_regs(current));
	unsigned int count = 0;
	bool caller = false, mapped = false;
	int ret = -EACCES;

	if (!mm)
		return ret;
	mmap_read_lock(mm);
	/* Inspect actual executable VMAs and the saved syscall PC. Neither a
	 * replacement exe_file nor mutable PR_SET_MM metadata proves execution. */
	for (vma = find_vma(mm, 0); vma;
	     vma = find_vma(mm, vma->vm_end)) {
		if (++count > 512)
			goto out;
		if (!(vma->vm_flags & VM_EXEC))
			continue;
		if (vma->vm_flags & VM_WRITE)
			goto out;
		if (yz_auth_same_image(vma->vm_file, exe)) {
			if (vma->vm_flags & VM_SHARED)
				goto out;
			mapped = true;
			if (pc >= vma->vm_start && pc < vma->vm_end)
				caller = true;
			continue;
		}
		if (yz_auth_system_image(vma->vm_file))
			continue;
		/* The arm64 vDSO is the sole permitted anonymous executable image.
		 * Its address is kernel-owned mm context, not PR_SET_MM metadata. */
		if (!vma->vm_file &&
		    vma->vm_start == (unsigned long)mm->context.vdso &&
		    vma->vm_end - vma->vm_start <= 16 * PAGE_SIZE &&
		    vma->vm_ops && vma->vm_private_data &&
		    (vma->vm_flags & VM_DONTEXPAND))
			continue;
		goto out;
	}
	if (mapped && (!admission || caller))
		ret = 0;
out:
	mmap_read_unlock(mm);
	return ret;
}

static int yz_auth_check_current(unsigned int role)
{
	struct file *exe = yz_get_current_exe_file();
	int ret;

	if (!exe)
		return -EACCES;
	ret = yz_auth_freeze(exe, role, false);
	if (!ret) {
		ret = yz_auth_check_mappings(exe, true);
		allow_write_access(exe);
	}
	fput(exe);
	return ret;
}

static bool yz_auth_observed_exec(void)
{
	struct file *exe = yz_get_current_exe_file();
	unsigned long flags;
	unsigned int i;
	bool observed = false;

	spin_lock_irqsave(&yz_auth_exec_lock, flags);
	for (i = 0; i < ARRAY_SIZE(yz_auth_exec_records); ++i) {
		struct yz_auth_exec_record *r = &yz_auth_exec_records[i];

		if (r->valid && r->owner == task_tgid(current) &&
		    r->mm == current->mm &&
		    r->exec_id == READ_ONCE(current->self_exec_id) &&
		    time_before(jiffies, r->deadline) && yz_auth_same_image(r->image, exe)) {
			r->valid = false; /* A single launcher claim per observed exec. */
			observed = true;
			break;
		}
	}
	spin_unlock_irqrestore(&yz_auth_exec_lock, flags);
	if (exe)
		fput(exe);
	schedule_work(&yz_auth_cleanup_work);
	return observed;
}

static struct yz_auth_session *yz_auth_alloc(struct task_struct *owner, u32 role)
{
	struct yz_auth_session *s = kzalloc(sizeof(*s), GFP_KERNEL);

	if (!s)
		return ERR_PTR(-ENOMEM);
	s->owner = get_task_pid(owner, PIDTYPE_TGID);
	task_lock(owner);
	s->mm = owner->mm;
	if (s->mm)
		mmgrab(s->mm);
	task_unlock(owner);
	if (!s->owner || !s->mm) {
		if (s->mm)
			mmdrop(s->mm);
		if (s->owner)
			put_pid(s->owner);
		kfree(s);
		return ERR_PTR(-ESRCH);
	}
	s->role = role;
	s->generation = ++yz_auth_generation;
	s->exec_id = READ_ONCE(owner->self_exec_id);
	s->deadline = jiffies + YZ_AUTH_TIMEOUT;
	atomic_set(&s->revoked, 0);
	atomic_set(&s->exec_seen, 0);
	list_add_tail_rcu(&s->list, &yz_auth_sessions);
	return s;
}

static bool yz_auth_owner_alive(const struct yz_auth_session *s)
{
	struct task_struct *task;
	bool alive = false;

	if (!s)
		return false;
	rcu_read_lock();
	task = pid_task(s->owner, PIDTYPE_TGID);
	if (task)
		alive = atomic_read(&task->signal->live) > 0;
	rcu_read_unlock();
	return alive;
}

struct yz_auth_session *yz_auth_open(bool launcher)
{
	struct yz_auth_session *s, *main;
	struct task_struct *loader;
	bool original_loader_alive;
	int ret = -EPERM;
	u32 role = YZ_VIOLA_ADMIN;

	if (!current->mm || !uid_eq(current_euid(), GLOBAL_ROOT_UID))
		return ERR_PTR(-EPERM);
	mutex_lock(&yz_auth_lock);
	if (!yz_auth_enabled) {
		ret = -ENODEV;
		goto fail;
	}
	if (launcher) {
		main = rcu_dereference_protected(yz_auth_main,
			lockdep_is_held(&yz_auth_lock));
		if (yz_auth_alive(main) || yz_auth_owner_alive(main) ||
		    yz_auth_owner_alive(rcu_dereference_protected(
			yz_auth_compat, lockdep_is_held(&yz_auth_lock)))) {
			ret = -EBUSY;
			goto fail;
		}
		/* The first session belongs to the exact module-loading process. */
		if (!yz_auth_initial_claimed &&
		    (task_tgid(current) != yz_auth_loader_pid ||
		     current->mm != yz_auth_loader_mm)) {
			rcu_read_lock();
			loader = pid_task(yz_auth_loader_pid, PIDTYPE_TGID);
			original_loader_alive = loader &&
				!(READ_ONCE(loader->flags) & PF_EXITING);
			rcu_read_unlock();
			if (original_loader_alive)
				goto fail;
		}
		ret = yz_auth_check_current(VIOLA_ROLE_VIOLA);
		if (ret)
			goto fail;
		if ((yz_auth_initial_claimed || task_tgid(current) != yz_auth_loader_pid ||
		     current->mm != yz_auth_loader_mm) && !yz_auth_observed_exec()) {
			ret = -EACCES;
			goto fail;
		}
		role = YZ_VIOLA_LAUNCHER64;
	}
	s = yz_auth_alloc(current, role);
	if (IS_ERR(s)) {
		ret = PTR_ERR(s);
		goto fail;
	}
	if (launcher) {
		yz_auth_initial_claimed = true;
		yz_auth_main_history = YZ_VIOLA_STARTING;
		rcu_assign_pointer(yz_auth_main, s);
		schedule_delayed_work(&yz_auth_timeout_work, YZ_AUTH_TIMEOUT);
	}
	mutex_unlock(&yz_auth_lock);
	return s;
fail:
	mutex_unlock(&yz_auth_lock);
	return ERR_PTR(ret);
}

void yz_auth_release(struct yz_auth_session *s)
{
	if (!s)
		return;
	mutex_lock(&yz_auth_lock);
	yz_auth_revoke(s);
	if (rcu_access_pointer(yz_auth_main) == s) {
		yz_auth_main_history = YZ_VIOLA_LOST;
		RCU_INIT_POINTER(yz_auth_main, NULL);
	}
	if (rcu_access_pointer(yz_auth_compat) == s) {
		yz_auth_compat_history = YZ_VIOLA_LOST;
		RCU_INIT_POINTER(yz_auth_compat, NULL);
	}
	list_del_rcu(&s->list);
	synchronize_rcu();
	yz_auth_drop_image(s);
	mutex_unlock(&yz_auth_lock);
	mmdrop(s->mm);
	put_pid(s->owner);
	kfree(s);
	schedule_work(&yz_auth_cleanup_work);
}

static bool yz_auth_is_owner(const struct yz_auth_session *s, bool check_mm)
{
	return yz_auth_alive(s) && task_tgid(current) == s->owner &&
	       uid_eq(current_euid(), GLOBAL_ROOT_UID) &&
	       (!check_mm || current->mm == s->mm);
}

static bool yz_auth_query_request(unsigned int request)
{
	return request == YZ_IOCTL_GET_SAFEMODE ||
	       request == YZ_IOCTL_GET_ROOT_STATUS ||
	       request == YZ_IOCTL_GET_RUNTIME ||
	       request == YZ_IOCTL_GET_EXIT_HISTORY_FD ||
	       request == YZ_IOCTL_GET_HEALTH ||
	       request == YZ_IOCTL_GET_ZYGOTE_VARIANTS ||
	       request == YZ_IOCTL_UID_SHOULD_UMOUNT;
}

int yz_auth_begin(struct yz_auth_session *s, unsigned int request,
		  void __user *arg)
{
	int ret = -EPERM;

	(void)arg;

	if (request == YZ_IOCTL_GET_HEALTH) {
		if (!mutex_trylock(&yz_auth_lock))
			return -EAGAIN;
	} else {
		mutex_lock(&yz_auth_lock);
	}
	if (!yz_auth_enabled || !s || !yz_auth_is_owner(s, true))
		goto fail;
	if (yz_auth_query_request(request))
		return 0;
	if (s->role == YZ_VIOLA_ADMIN && request == YZ_IOCTL_RELOAD)
		return 0;
	if (s->role != YZ_VIOLA_DAEMON64 && s->role != YZ_VIOLA_DAEMON32)
		goto fail;
	switch (request) {
	case YZ_IOCTL_SET_DLOPEN:
	case YZ_IOCTL_SET_NATIVE_TARGETS:
	case YZ_IOCTL_SET_YUKILINKER:
	case YZ_IOCTL_SET_POLICY_CACHE:
	case YZ_IOCTL_PREPARE_RUNTIME_POLICY:
		if (s->role == YZ_VIOLA_DAEMON64)
			return 0;
		break;
	case YZ_IOCTL_SET_DLOPEN32:
		if (s->role == YZ_VIOLA_DAEMON32)
			return 0;
		break;
	case YZ_IOCTL_HANDOFF:
	case YZ_IOCTL_UMOUNT_PID:
	case YZ_IOCTL_UNMAP_PID:
	case YZ_IOCTL_UNMAP_SELF:
	case YZ_IOCTL_PATCH_TEXT:
	case YZ_IOCTL_RESTORE_NATIVE_LOAD_POLICY:
	case YZ_IOCTL_ALLOW_MODULE_LOAD_POLICY:
	case YZ_IOCTL_REPORT_RUNTIME:
		/* The handler validates the target from its single command copy,
		 * after pinning that actual task. Never double-fetch a user pid. */
		return 0;
	default:
		break;
	}
fail:
	mutex_unlock(&yz_auth_lock);
	return ret;
}

void yz_auth_end(void)
{
	mutex_unlock(&yz_auth_lock);
}

int yz_auth_current_ticket(struct yz_auth_ticket *ticket)
{
	struct yz_auth_session *s;

	lockdep_assert_held(&yz_auth_lock);
	list_for_each_entry(s, &yz_auth_sessions, list) {
		if ((s->role == YZ_VIOLA_DAEMON64 || s->role == YZ_VIOLA_DAEMON32) &&
		    yz_auth_is_owner(s, true)) {
			ticket->epoch = yz_auth_epoch;
			ticket->generation = s->generation;
			return 0;
		}
	}
	return -EPERM;
}

bool yz_auth_ticket_begin(const struct yz_auth_ticket *ticket)
{
	struct yz_auth_session *s;

	mutex_lock(&yz_auth_lock);
	if (yz_auth_enabled && ticket->epoch == yz_auth_epoch) {
		list_for_each_entry(s, &yz_auth_sessions, list) {
			if (s->generation == ticket->generation && yz_auth_alive(s) &&
			    (s->role == YZ_VIOLA_DAEMON64 || s->role == YZ_VIOLA_DAEMON32))
				return true;
		}
	}
	mutex_unlock(&yz_auth_lock);
	return false;
}

int yz_auth_query_ticket(struct yz_auth_ticket *ticket)
{
	struct yz_auth_session *s;

	lockdep_assert_held(&yz_auth_lock);
	list_for_each_entry (s, &yz_auth_sessions, list) {
		if (yz_auth_is_owner(s, true)) {
			ticket->epoch = yz_auth_epoch;
			ticket->generation = s->generation;
			return 0;
		}
	}
	return -EPERM;
}

bool yz_auth_query_ticket_begin(const struct yz_auth_ticket *ticket)
{
	struct yz_auth_session *s;

	mutex_lock(&yz_auth_lock);
	if (yz_auth_enabled && ticket->epoch == yz_auth_epoch) {
		list_for_each_entry (s, &yz_auth_sessions, list) {
			if (s->generation == ticket->generation &&
			    yz_auth_is_owner(s, true))
				return true;
		}
	}
	mutex_unlock(&yz_auth_lock);
	return false;
}

static int yz_auth_target_abi(u8 abi)
{
	struct yz_auth_session *s;

	lockdep_assert_held(&yz_auth_lock);
	if (!abi)
		return -ESRCH;
	list_for_each_entry(s, &yz_auth_sessions, list) {
		if (yz_auth_is_owner(s, true) &&
		    ((s->role == YZ_VIOLA_DAEMON32 && abi == YZ_RUNTIME_ABI_32) ||
		     (s->role == YZ_VIOLA_DAEMON64 && abi == YZ_RUNTIME_ABI_64)))
			return 0;
	}
	return -EPERM;
}

int yz_auth_target_task(struct task_struct *task)
{
	return yz_auth_target_abi(yz_runtime_task_abi(task));
}

int yz_auth_target_report(u32 pid, u32 generation)
{
	return yz_auth_target_abi(yz_runtime_report_abi(pid, generation));
}

static int yz_auth_catalog_install(void __user *arg)
{
	struct yz_viola_catalog_cmd cmd;
	struct viola_manifest_view view;
	struct viola_entry entry;
	void *data, *signature;
	int ret;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	if (cmd.size != sizeof(cmd) || cmd.version != YZ_VIOLA_VERSION ||
	    !cmd.manifest_size || cmd.manifest_size > VIOLA_MANIFEST_MAX ||
	    !cmd.signature_size || cmd.signature_size > VIOLA_SIGNATURE_MAX)
		return -EINVAL;
	data = memdup_user(u64_to_user_ptr(cmd.manifest), cmd.manifest_size);
	if (IS_ERR(data))
		return PTR_ERR(data);
	signature = memdup_user(u64_to_user_ptr(cmd.signature), cmd.signature_size);
	if (IS_ERR(signature)) {
		kfree(data);
		return PTR_ERR(signature);
	}
	ret = viola_manifest_verify(data, cmd.manifest_size, signature,
		cmd.signature_size, &view) ? -EKEYREJECTED : 0;
	kfree(signature);
	if (!ret && (viola_manifest_find(&view, VIOLA_ROLE_KO,
		VIOLA_ABI_ARM64, VIOLA_KMI_ID, &entry) ||
		viola_manifest_find(&view, VIOLA_ROLE_VIOLA,
		VIOLA_ABI_ARM64, 0, &entry) ||
		memcmp(entry.sha512, yz_auth_loader_hash, sizeof(yz_auth_loader_hash))))
		ret = -EKEYREJECTED;
	if (!ret && yz_auth_manifest) {
		/* One immutable catalog per loaded KO, including restarts. */
		if (yz_auth_catalog.size != view.size ||
		    memcmp(yz_auth_manifest, data, view.size))
			ret = -EKEYREJECTED;
	} else if (!ret) {
		yz_auth_catalog = view;
		smp_store_release(&yz_auth_manifest, data);
		data = NULL;
	}
	kfree(data);
	return ret;
}

static int yz_auth_pin_exec(struct yz_auth_session *s, void __user *arg)
{
	struct yz_viola_exec_cmd cmd;
	struct file *file;
	int ret;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	if (cmd.size != sizeof(cmd) || cmd.version != YZ_VIOLA_VERSION ||
	    cmd.reserved || cmd.image_fd < 0)
		return -EINVAL;
	if (s->image)
		return -EALREADY;
	file = fget(cmd.image_fd);
	if (!file)
		return -EBADF;
	ret = yz_auth_freeze(file, VIOLA_ROLE_DAEMON,
			     s->role == YZ_VIOLA_LAUNCHER32);
	if (ret) {
		fput(file);
		return ret;
	}
	WRITE_ONCE(s->image, file);
	return 0;
}

static int yz_auth_claim(struct yz_auth_session *s)
{
	struct file *exe;
	struct mm_struct *old_mm;
	int ret = -EACCES;

	if (!yz_auth_is_owner(s, false) || current->mm == s->mm ||
	    !current->mm || atomic_read(&s->exec_seen) != 1 ||
	    READ_ONCE(current->self_exec_id) != s->exec_id + 1 || !s->image)
		return -EACCES;
	if (s->role != YZ_VIOLA_ARMED64 && s->role != YZ_VIOLA_ARMED32 &&
	    s->role != YZ_VIOLA_DELEGATED32)
		return -EPERM;
	exe = yz_get_current_exe_file();
	if (!exe)
		return -EACCES;
	if (yz_auth_claim_image(s, exe)) {
		if (s->role == YZ_VIOLA_DELEGATED32 &&
		    yz_auth_check_mappings(exe, true))
			goto out;
		old_mm = s->mm;
		mmgrab(current->mm);
		WRITE_ONCE(s->mm, current->mm);
		s->exec_id = READ_ONCE(current->self_exec_id);
		atomic_set(&s->exec_seen, 0);
		if (s->role == YZ_VIOLA_DELEGATED32) {
			WRITE_ONCE(s->role, YZ_VIOLA_LAUNCHER32);
			yz_auth_drop_image(s);
		} else {
			WRITE_ONCE(s->role, s->role == YZ_VIOLA_ARMED64 ?
				   YZ_VIOLA_DAEMON64 : YZ_VIOLA_DAEMON32);
		}
		mmdrop(old_mm);
		ret = 0;
	}
out:
	fput(exe);
	return ret;
}

static int yz_auth_delegate(struct yz_auth_session *parent, void __user *arg)
{
	struct yz_viola_delegate_cmd cmd;
	struct yz_auth_session *s, *existing;
	struct task_struct *child;
	struct file *image;
	bool is_child;
	int ret, fd;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	if (cmd.size != sizeof(cmd) || cmd.version != YZ_VIOLA_VERSION ||
	    cmd.reserved || !cmd.child_pid || cmd.viola_fd < 0)
		return -EINVAL;
	existing = rcu_dereference_protected(yz_auth_compat,
		lockdep_is_held(&yz_auth_lock));
	if (yz_auth_alive(existing) || yz_auth_owner_alive(existing))
		return -EBUSY;
	image = fget(cmd.viola_fd);
	if (!image)
		return -EBADF;
	ret = yz_auth_freeze(image, VIOLA_ROLE_VIOLA, false);
	if (ret) {
		fput(image);
		return ret;
	}
	rcu_read_lock();
	child = get_pid_task(find_vpid(cmd.child_pid), PIDTYPE_PID);
	is_child = child && task_tgid(rcu_dereference(child->real_parent)) ==
		parent->owner && child->pid == child->tgid &&
		!(READ_ONCE(child->flags) & PF_EXITING);
	rcu_read_unlock();
	if (!is_child) {
		ret = -ESRCH;
		goto fail_child;
	}
	s = yz_auth_alloc(child, YZ_VIOLA_DELEGATED32);
	if (IS_ERR(s)) {
		ret = PTR_ERR(s);
		goto fail_child;
	}
	s->image = image;
	s->parent_generation = parent->generation;
	parent->compat_required = true;
	yz_auth_compat_history = YZ_VIOLA_STARTING;
	rcu_assign_pointer(yz_auth_compat, s);
	put_task_struct(child);
	/* Install in the parent; it sends this child-bound capability via
	 * SCM_RIGHTS. Merely possessing it does not authorize the parent. */
	fd = yukizygisk_control_install_session(s);
	if (fd < 0) {
		ret = fd;
		goto fail_session;
	}
	cmd.control_fd = fd;
	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		/* Closing invokes release, which takes yz_auth_lock. */
		mutex_unlock(&yz_auth_lock);
		yz_close_fd(fd);
		mutex_lock(&yz_auth_lock);
		return -EFAULT;
	}
	schedule_delayed_work(&yz_auth_timeout_work, YZ_AUTH_TIMEOUT);
	return 0;
fail_session:
	mutex_unlock(&yz_auth_lock);
	yz_auth_release(s);
	mutex_lock(&yz_auth_lock);
	return ret;
fail_child:
	if (child)
		put_task_struct(child);
	allow_write_access(image);
	fput(image);
	return ret;
}

static u32 yz_auth_state(struct yz_auth_session *s)
{
	if (!s)
		return YZ_VIOLA_ABSENT;
	if (!yz_auth_alive(s))
		return YZ_VIOLA_LOST;
	return s->ready ? YZ_VIOLA_READY : YZ_VIOLA_STARTING;
}

static int yz_auth_daemon_identity(void __user *arg)
{
	struct yz_viola_daemon_identity_cmd cmd;
	struct yz_auth_session *session;
	struct task_struct *task;
	bool valid;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	if (cmd.size != sizeof(cmd) ||
	    cmd.version != YZ_VIOLA_DAEMON_IDENTITY_VERSION ||
	    (cmd.abi != YZ_RUNTIME_ABI_32 && cmd.abi != YZ_RUNTIME_ABI_64) ||
	    cmd.reserved || cmd.pid || cmd.state || cmd.owner_alive ||
	    cmd.role || cmd.start_boottime_ns || cmd.epoch || cmd.generation)
		return -EINVAL;
	session = cmd.abi == YZ_RUNTIME_ABI_32
		      ? rcu_dereference_protected(
			    yz_auth_compat, lockdep_is_held(&yz_auth_lock))
		      : rcu_dereference_protected(
			    yz_auth_main, lockdep_is_held(&yz_auth_lock));
	cmd.epoch = yz_auth_epoch;
	cmd.state = session
			? yz_auth_state(session)
			: (cmd.abi == YZ_RUNTIME_ABI_32 ? yz_auth_compat_history
							: yz_auth_main_history);
	if (session) {
		cmd.pid = pid_nr(session->owner);
		cmd.generation = session->generation;
		cmd.role = session->role;
		task = get_pid_task(session->owner, PIDTYPE_TGID);
		valid = false;
		if (task) {
			cmd.start_boottime_ns = READ_ONCE(task->start_boottime);
			cmd.owner_alive = atomic_read(&task->signal->live) > 0;
			task_lock(task);
			valid =
			    cmd.owner_alive && !(task->flags & PF_EXITING) &&
			    task->mm == session->mm &&
			    READ_ONCE(task->self_exec_id) == session->exec_id;
			task_unlock(task);
			put_task_struct(task);
		}
		if (!valid && cmd.state == YZ_VIOLA_READY)
			cmd.state = YZ_VIOLA_LOST;
	}
	return copy_to_user(arg, &cmd, sizeof(cmd)) ? -EFAULT : 0;
}

static int yz_auth_recover(struct yz_auth_session *s,
			  struct yz_auth_session *main,
			  struct yz_auth_session *compat,
			  unsigned int request, void __user *arg)
{
	struct yz_viola_recover_cmd cmd;

	if (!yz_auth_alive(main) || !main->ready)
		return -ESRCH;
	if (request == YZ_IOCTL_VIOLA_TAKE_RECOVERY) {
		if (s != main || s->role != YZ_VIOLA_DAEMON64)
			return -EPERM;
		if (main->recovery != 1)
			return -EAGAIN;
		if (yz_auth_owner_alive(compat)) {
			main->recovery = 0;
			main->recovery_error = -EBUSY;
			return -EBUSY;
		}
		main->recovery = 2;
		return 0;
	}
	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	if (cmd.size != sizeof(cmd) || cmd.version != YZ_VIOLA_VERSION ||
	    cmd.reserved || cmd.epoch != yz_auth_epoch ||
	    cmd.generation != main->generation)
		return -ESTALE;
	if (request == YZ_IOCTL_VIOLA_FINISH_RECOVERY) {
		if (s != main || s->role != YZ_VIOLA_DAEMON64 || main->recovery != 2)
			return -EPERM;
		if (cmd.result > 0 ||
		    (!cmd.result && (!yz_auth_alive(compat) || !compat->ready)))
			return -EINVAL;
		main->recovery = 0;
		main->recovery_error = cmd.result;
		if (cmd.result)
			yz_auth_error(YZ_VIOLA_STAGE_SESSION, VIOLA_ROLE_DAEMON, cmd.result);
		return 0;
	}
	if (s->role != YZ_VIOLA_ADMIN || cmd.result)
		return -EPERM;
	if (!main->compat_required)
		return -ENODEV;
	if (yz_auth_alive(compat))
		return 0;
	if (yz_auth_owner_alive(compat))
		return -EBUSY;
	if (!main->recovery) {
		main->recovery = 1;
		main->recovery_error = 0;
	}
	/* A repeated request can retry a dropped notification, without granting
	 * any daemon capability to its root management caller. */
	if (main->recovery == 1)
		yz_events_emit_viola_recovery(pid_nr(main->owner));
	return 0;
}

long yz_auth_ioctl(struct yz_auth_session *s, unsigned int request,
		   void __user *arg)
{
	struct yz_viola_status status;
	struct yz_auth_session *main, *compat;
	long ret = -EPERM;
	u32 failed_stage = YZ_VIOLA_STAGE_SESSION;
	u32 failed_role = s ? yz_auth_session_payload(s->role) : 0;

	if (request == YZ_IOCTL_VIOLA_DAEMON_IDENTITY) {
		if (!mutex_trylock(&yz_auth_lock))
			return -EAGAIN;
	} else {
		mutex_lock(&yz_auth_lock);
	}
	if (!yz_auth_enabled || !s)
		goto out;
	if (request == YZ_IOCTL_VIOLA_CLAIM) {
		failed_stage = YZ_VIOLA_STAGE_EXEC_CLAIM;
		failed_role = s->role == YZ_VIOLA_DELEGATED32 ?
			VIOLA_ROLE_VIOLA : VIOLA_ROLE_DAEMON;
		ret = yz_auth_claim(s);
		goto out;
	}
	if (!yz_auth_is_owner(s, true))
		goto out;
	main = rcu_dereference_protected(yz_auth_main,
		lockdep_is_held(&yz_auth_lock));
	compat = rcu_dereference_protected(yz_auth_compat,
		lockdep_is_held(&yz_auth_lock));
	switch (request) {
	case YZ_IOCTL_VIOLA_DAEMON_IDENTITY:
		ret = yz_auth_daemon_identity(arg);
		break;
	case YZ_IOCTL_VIOLA_STATUS:
		if (copy_from_user(&status, arg, sizeof(status))) {
			ret = -EFAULT;
			break;
		}
		if (status.size != sizeof(status) || status.version != YZ_VIOLA_VERSION ||
		    status.reserved || status.compat_required || status.compat_recovering ||
		    status.recovery_error) {
			ret = -EINVAL;
			break;
		}
		memset(&status, 0, sizeof(status));
		status.size = sizeof(status);
		status.version = YZ_VIOLA_VERSION;
		status.profile = VIOLA_PROFILE;
		status.catalog_ready = !!yz_auth_manifest;
		status.daemon64 = main ? yz_auth_state(main) : yz_auth_main_history;
		status.daemon32 = compat ? yz_auth_state(compat) : yz_auth_compat_history;
		status.role = s->role;
		status.owner_pid = pid_nr(s->owner);
		status.epoch = yz_auth_epoch;
		status.generation = s->generation;
		if (s->role == YZ_VIOLA_QUERY || s->role == YZ_VIOLA_ADMIN) {
			status.owner_pid = main ? pid_nr(main->owner) : 0;
			status.generation = main ? main->generation : 0;
		}
		memcpy(status.release_id, yz_auth_release_id, sizeof(status.release_id));
		memcpy(status.trust_id, yz_auth_trust, sizeof(status.trust_id));
		status.last_error = yz_auth_last_error;
		status.failed_role = yz_auth_failed_role;
		status.failed_stage = yz_auth_failed_stage;
		status.compat_required = main && main->compat_required;
		status.compat_recovering = main && main->recovery;
		status.recovery_error = main ? main->recovery_error : 0;
		ret = copy_to_user(arg, &status, sizeof(status)) ? -EFAULT : 0;
		break;
	case YZ_IOCTL_VIOLA_CATALOG:
		failed_stage = YZ_VIOLA_STAGE_CATALOG;
		failed_role = 0;
		if (s->role == YZ_VIOLA_LAUNCHER64)
			ret = yz_auth_catalog_install(arg);
		break;
	case YZ_IOCTL_VIOLA_PIN_EXEC:
		failed_stage = YZ_VIOLA_STAGE_EXEC_IMAGE;
		failed_role = VIOLA_ROLE_DAEMON;
		if (s->role == YZ_VIOLA_LAUNCHER64 || s->role == YZ_VIOLA_LAUNCHER32)
			ret = yz_auth_pin_exec(s, arg);
		break;
	case YZ_IOCTL_VIOLA_ARM_EXEC:
		failed_stage = YZ_VIOLA_STAGE_EXEC_IMAGE;
		failed_role = VIOLA_ROLE_DAEMON;
		if (s->image && (s->role == YZ_VIOLA_LAUNCHER64 ||
				s->role == YZ_VIOLA_LAUNCHER32)) {
			WRITE_ONCE(s->role, s->role == YZ_VIOLA_LAUNCHER64 ?
				   YZ_VIOLA_ARMED64 : YZ_VIOLA_ARMED32);
			ret = 0;
		}
		break;
	case YZ_IOCTL_VIOLA_DELEGATE:
		failed_role = VIOLA_ROLE_VIOLA;
		if (s->role == YZ_VIOLA_DAEMON64)
			ret = yz_auth_delegate(s, arg);
		if (ret == -EKEYREJECTED || ret == -ENOEXEC || ret == -ETXTBSY)
			failed_stage = YZ_VIOLA_STAGE_EXEC_IMAGE;
		break;
	case YZ_IOCTL_VIOLA_RECOVER_COMPAT:
	case YZ_IOCTL_VIOLA_TAKE_RECOVERY:
	case YZ_IOCTL_VIOLA_FINISH_RECOVERY:
		ret = yz_auth_recover(s, main, compat, request, arg);
		break;
	case YZ_IOCTL_DAEMON_READY:
		if (s->role == YZ_VIOLA_DAEMON64 && yz_auth_manifest &&
		    (!compat || compat->parent_generation != s->generation ||
		     (yz_auth_alive(compat) && compat->ready))) {
			WRITE_ONCE(s->ready, true);
			ret = 0;
		}
		break;
	case YZ_IOCTL_VIOLA_COMPAT_READY:
		if (s->role == YZ_VIOLA_DAEMON32 && yz_auth_manifest) {
			WRITE_ONCE(s->ready, true);
			ret = 0;
		}
		break;
	default:
		ret = -ENOTTY;
		break;
	}
out:
	if (ret && s && task_tgid(current) == s->owner &&
	    s->role >= YZ_VIOLA_LAUNCHER64)
		yz_auth_error(failed_stage, failed_role, ret);
	mutex_unlock(&yz_auth_lock);
	return ret;
}

bool yz_auth_catalog_ready(void)
{
	return READ_ONCE(yz_auth_enabled) && smp_load_acquire(&yz_auth_manifest);
}

bool yz_auth_injection_allowed(bool early_native, bool compat)
{
	struct yz_auth_session *s;
	bool allowed = false;

	if (!yz_auth_catalog_ready())
		return false;
	if (early_native)
		return true;
	rcu_read_lock();
	s = compat ? rcu_dereference(yz_auth_compat) : rcu_dereference(yz_auth_main);
	if (yz_auth_alive(s) && READ_ONCE(s->ready))
		allowed = true;
	rcu_read_unlock();
	return allowed;
}

bool yz_auth_injection_ticket(bool early_native, bool compat,
			      struct yz_auth_ticket *ticket)
{
	struct yz_auth_session *s;
	bool allowed = false;

	if (!yz_auth_catalog_ready())
		return false;
	ticket->epoch = yz_auth_epoch;
	ticket->generation = 0;
	if (early_native)
		return true;
	rcu_read_lock();
	s = compat ? rcu_dereference(yz_auth_compat) : rcu_dereference(yz_auth_main);
	if (yz_auth_alive(s) && READ_ONCE(s->ready)) {
		ticket->generation = s->generation;
		allowed = true;
	}
	rcu_read_unlock();
	return allowed;
}

bool yz_auth_injection_ticket_alive(const struct yz_auth_ticket *ticket)
{
	struct yz_auth_session *s;
	bool alive = false;

	if (!yz_auth_catalog_ready() || ticket->epoch != yz_auth_epoch)
		return false;
	if (!ticket->generation)
		return true; /* Independently authenticated early-native image path. */
	rcu_read_lock();
	list_for_each_entry_rcu(s, &yz_auth_sessions, list) {
		if (s->generation == ticket->generation && yz_auth_alive(s) &&
		    READ_ONCE(s->ready)) {
			alive = true;
			break;
		}
	}
	rcu_read_unlock();
	return alive;
}

int yz_auth_check_payload(unsigned int role, bool compat,
			  const void *bytes, size_t size)
{
	struct viola_entry entry;
	int ret;

	mutex_lock(&yz_auth_lock);
	ret = !yz_auth_manifest ||
	      viola_manifest_find(&yz_auth_catalog, role,
		compat ? VIOLA_ABI_ARM32 : VIOLA_ABI_ARM64, 0, &entry) ||
	      viola_check_payload(&entry, bytes, size) ? -EKEYREJECTED : 0;
	if (ret)
		yz_auth_error(YZ_VIOLA_STAGE_PAYLOAD, role, ret);
	mutex_unlock(&yz_auth_lock);
	return ret;
}

int yz_auth_seal_image(struct file *file)
{
	struct inode *inode = file_inode(file);
	int ret;

	/* Only called for a new, private shmem_file_setup image, before any FD
	 * or mapping can expose it. That constructor already sets F_SEAL_SEAL;
	 * initialise its complete seal set here instead of using F_ADD_SEALS. */
	inode_lock(inode);
	ret = mapping_deny_writable(inode->i_mapping);
	if (!ret)
		SHMEM_I(inode)->seals = F_SEAL_SEAL | F_SEAL_SHRINK |
			F_SEAL_GROW | F_SEAL_WRITE;
	inode_unlock(inode);
	return ret;
}

static void yz_auth_cleanup_execs(bool all)
{
	unsigned long flags;
	unsigned int i;
	bool pending = false;

	for (i = 0; i < ARRAY_SIZE(yz_auth_exec_records); ++i) {
		struct yz_auth_exec_record old = { 0 };
		struct yz_auth_exec_record *r = &yz_auth_exec_records[i];

		spin_lock_irqsave(&yz_auth_exec_lock, flags);
		if (r->owner && (all || !r->valid || time_after_eq(jiffies, r->deadline))) {
			old = *r;
			memset(r, 0, sizeof(*r));
		} else if (r->owner) {
			pending = true;
		}
		spin_unlock_irqrestore(&yz_auth_exec_lock, flags);
		if (old.owner) {
			fput(old.image);
			put_pid(old.owner);
		}
	}
	if (pending)
		schedule_delayed_work(&yz_auth_timeout_work, YZ_AUTH_TIMEOUT);
}

static void yz_auth_cleanup_work_fn(struct work_struct *work)
{
	struct yz_auth_session *s;

	(void)work;
	mutex_lock(&yz_auth_lock);
	list_for_each_entry(s, &yz_auth_sessions, list) {
		if (!yz_auth_alive(s)) {
			yz_auth_revoke(s);
			yz_auth_drop_image(s);
		}
	}
	mutex_unlock(&yz_auth_lock);
	yz_auth_cleanup_execs(false);
}

static void yz_auth_timeout_work_fn(struct work_struct *work)
{
	struct yz_auth_session *s;
	unsigned long next = 0;

	(void)work;
	mutex_lock(&yz_auth_lock);
	list_for_each_entry(s, &yz_auth_sessions, list) {
		if (atomic_read(&s->revoked) || s->ready || s->role <= YZ_VIOLA_ADMIN)
			continue;
		if (time_after_eq(jiffies, s->deadline)) {
			yz_auth_revoke(s);
			yz_auth_error(YZ_VIOLA_STAGE_TIMEOUT,
				yz_auth_session_payload(s->role), -ETIMEDOUT);
		} else if (!next || time_before(s->deadline, next)) {
			next = s->deadline;
		}
	}
	mutex_unlock(&yz_auth_lock);
	schedule_work(&yz_auth_cleanup_work);
	if (next)
		mod_delayed_work(system_wq, &yz_auth_timeout_work,
				 max_t(long, 1, next - jiffies));
}

static void yz_auth_on_exit(void *data, struct task_struct *task
#ifdef YZ_EXIT_HAS_GROUP_DEAD
			    , bool group_dead
#endif
)
{
	struct yz_auth_session *s;
	unsigned long flags;
	unsigned int i;
	bool changed = false;

	(void)data;
#ifdef YZ_EXIT_HAS_GROUP_DEAD
	(void)group_dead;
#endif
	if (task->pid != task->tgid)
		return;
	spin_lock_irqsave(&yz_auth_exec_lock, flags);
	for (i = 0; i < ARRAY_SIZE(yz_auth_exec_records); ++i)
		if (yz_auth_exec_records[i].owner == task_tgid(task)) {
			yz_auth_exec_records[i].valid = false;
			changed = true;
		}
	spin_unlock_irqrestore(&yz_auth_exec_lock, flags);
	rcu_read_lock();
	list_for_each_entry_rcu(s, &yz_auth_sessions, list)
		if (s->owner == task_tgid(task)) {
			yz_auth_revoke(s);
			changed = true;
		}
	rcu_read_unlock();
	if (changed)
		schedule_work(&yz_auth_cleanup_work);
}

static void yz_auth_on_exec(void *data, struct task_struct *task, pid_t old_pid,
			    struct linux_binprm *bprm)
{
	struct yz_auth_session *s;
	unsigned long flags;
	unsigned int i, slot = ARRAY_SIZE(yz_auth_exec_records);
	bool changed = false;

	(void)data;
	(void)old_pid;
	/* Fixed-size evidence records only: hashing and reference destruction run
	 * in process/worker context, never in this atomic-sensitive tracepoint. */
	spin_lock_irqsave(&yz_auth_exec_lock, flags);
	for (i = 0; i < ARRAY_SIZE(yz_auth_exec_records); ++i) {
		struct yz_auth_exec_record *r = &yz_auth_exec_records[i];

		if (r->owner == task_tgid(task))
			r->valid = false;
		if (!r->owner)
			slot = i;
	}
	if (slot < ARRAY_SIZE(yz_auth_exec_records) && bprm->file && task->mm &&
	    uid_eq(task_euid(task), GLOBAL_ROOT_UID) &&
	    !strcmp(bprm->file->f_path.dentry->d_name.name, "viola")) {
		struct yz_auth_exec_record *r = &yz_auth_exec_records[slot];

		r->owner = get_pid(task_tgid(task));
		r->mm = task->mm;
		r->image = get_file(bprm->file);
		r->exec_id = READ_ONCE(task->self_exec_id);
		r->deadline = jiffies + YZ_AUTH_TIMEOUT;
		r->valid = true;
	}
	spin_unlock_irqrestore(&yz_auth_exec_lock, flags);
	schedule_work(&yz_auth_cleanup_work);
	rcu_read_lock();
	list_for_each_entry_rcu(s, &yz_auth_sessions, list) {
		if (s->owner != task_tgid(task) || atomic_read(&s->revoked))
			continue;
		if (!yz_auth_record_exec(s, bprm)) {
			yz_auth_revoke(s);
			changed = true;
		}
	}
	rcu_read_unlock();
	if (changed)
		schedule_work(&yz_auth_cleanup_work);
}

static void yz_auth_find_tracepoint(struct tracepoint *tp, void *data)
{
	(void)data;
	if (!strcmp(tp->name, "sched_process_exit"))
		yz_auth_exit_tp = tp;
	else if (!strcmp(tp->name, "sched_process_exec"))
		yz_auth_exec_tp = tp;
}

int yz_auth_init(void)
{
	unsigned int i;
	int ret;

	if (!current->mm || !uid_eq(current_euid(), GLOBAL_ROOT_UID))
		return -EPERM;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	yz_auth_is_subdir = (typeof(yz_auth_is_subdir))
		yz_lookup_callable_quiet("is_subdir");
	if (!yz_auth_is_subdir) {
		pr_err("yukizygisk: is_subdir unavailable for Viola admission\n");
		return -EOPNOTSUPP;
	}
#endif
	/* Pin the host linker and approved Bionic libraries by file identity.
	 * A same-named module library or writable replacement is not a host root. */
	for (i = 0; i < ARRAY_SIZE(yz_auth_system_names); ++i) {
		struct path *path = &yz_auth_system_paths[i];

		ret = yz_kern_path(yz_auth_system_names[i], LOOKUP_FOLLOW, path);
		if (ret) {
			memset(path, 0, sizeof(*path));
			continue;
		}
		if (!S_ISREG(d_inode(path->dentry)->i_mode) ||
		    !yz_auth_readonly_path(path)) {
			yz_path_put(path);
			memset(path, 0, sizeof(*path));
		}
	}
	for (i = 0; i < ARRAY_SIZE(yz_auth_system_root_names); ++i) {
		struct path *path = &yz_auth_system_roots[i];

		ret = yz_kern_path(yz_auth_system_root_names[i], LOOKUP_FOLLOW,
				   path);
		if (ret)
			continue;
		if (!S_ISDIR(d_inode(path->dentry)->i_mode) ||
		    !yz_auth_readonly_path(path)) {
			yz_path_put(path);
			memset(path, 0, sizeof(*path));
		}
	}
	/* Optional host translator; never admit a writable module replacement.
	 * Keep it separate from the executable mappings allowed inside Viola. */
	ret = yz_kern_path("/system_ext/bin/tango_translator", LOOKUP_FOLLOW,
			   &yz_auth_tango_path);
	if (ret) {
		memset(&yz_auth_tango_path, 0, sizeof(yz_auth_tango_path));
	} else if (!S_ISREG(d_inode(yz_auth_tango_path.dentry)->i_mode) ||
		   !sb_rdonly(d_inode(yz_auth_tango_path.dentry)->i_sb)) {
		yz_path_put(&yz_auth_tango_path);
		memset(&yz_auth_tango_path, 0, sizeof(yz_auth_tango_path));
	}
	ret = yz_auth_check_current(VIOLA_ROLE_VIOLA);
	if (ret) {
		yz_auth_error(YZ_VIOLA_STAGE_LOADER, VIOLA_ROLE_VIOLA, ret);
		pr_err("yukizygisk: Viola loader authentication failed: %d\n", ret);
		goto fail;
	}
	yz_auth_loader_pid = get_task_pid(current, PIDTYPE_TGID);
	yz_auth_loader_mm = current->mm;
	mmgrab(yz_auth_loader_mm);
	get_random_bytes(&yz_auth_epoch, sizeof(yz_auth_epoch));
	if (!yz_auth_epoch)
		yz_auth_epoch = 1;
#ifdef CONFIG_TRACEPOINTS
	for_each_kernel_tracepoint(yz_auth_find_tracepoint, NULL);
	if (!yz_auth_exit_tp || !yz_auth_exec_tp) {
		ret = -EOPNOTSUPP;
		goto fail;
	}
	check_trace_callback_type_sched_process_exit(yz_auth_on_exit);
	ret = tracepoint_probe_register(yz_auth_exit_tp, (void *)yz_auth_on_exit, NULL);
	if (ret)
		goto fail;
	yz_auth_exit_registered = true;
	check_trace_callback_type_sched_process_exec(yz_auth_on_exec);
	ret = tracepoint_probe_register(yz_auth_exec_tp, (void *)yz_auth_on_exec, NULL);
	if (ret)
		goto fail;
	yz_auth_exec_registered = true;
#else
	ret = -EOPNOTSUPP;
	goto fail;
#endif
	WRITE_ONCE(yz_auth_enabled, true);
	return 0;
fail:
	yz_auth_exit();
	return ret;
}

void yz_auth_exit(void)
{
	unsigned int i;
	WRITE_ONCE(yz_auth_enabled, false);
#ifdef CONFIG_TRACEPOINTS
	if (yz_auth_exec_registered) {
		tracepoint_probe_unregister(yz_auth_exec_tp, (void *)yz_auth_on_exec, NULL);
		yz_auth_exec_registered = false;
	}
	if (yz_auth_exit_registered) {
		tracepoint_probe_unregister(yz_auth_exit_tp, (void *)yz_auth_on_exit, NULL);
		yz_auth_exit_registered = false;
	}
	tracepoint_synchronize_unregister();
#endif
	cancel_delayed_work_sync(&yz_auth_timeout_work);
	cancel_work_sync(&yz_auth_cleanup_work);
	/* cleanup can schedule the expiry worker before it completes. */
	cancel_delayed_work_sync(&yz_auth_timeout_work);
	yz_auth_cleanup_execs(true);
	if (yz_auth_tango_path.dentry)
		yz_path_put(&yz_auth_tango_path);
	memset(&yz_auth_tango_path, 0, sizeof(yz_auth_tango_path));
	for (i = 0; i < ARRAY_SIZE(yz_auth_system_paths); ++i) {
		if (yz_auth_system_paths[i].dentry)
			yz_path_put(&yz_auth_system_paths[i]);
		memset(&yz_auth_system_paths[i], 0, sizeof(struct path));
	}
	for (i = 0; i < ARRAY_SIZE(yz_auth_system_roots); ++i) {
		if (yz_auth_system_roots[i].dentry)
			yz_path_put(&yz_auth_system_roots[i]);
		memset(&yz_auth_system_roots[i], 0, sizeof(struct path));
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	yz_auth_is_subdir = NULL;
#endif
	if (yz_auth_loader_mm) {
		mmdrop(yz_auth_loader_mm);
		yz_auth_loader_mm = NULL;
	}
	if (yz_auth_loader_pid) {
		put_pid(yz_auth_loader_pid);
		yz_auth_loader_pid = NULL;
	}
	kfree(yz_auth_manifest);
	yz_auth_manifest = NULL;
}
