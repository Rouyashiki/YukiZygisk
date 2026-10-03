/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Authenticated module fd handoff.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/task_work.h>
#include <linux/uaccess.h>

#include "internal.h"
#include "core/auth.h"
#include "host/runtime.h"
#include "klog.h"

struct yz_fd_handoff_pending {
	struct list_head list;
	struct callback_head twork;
	struct yz_auth_ticket ticket;
	struct mm_struct *mm;
	pid_t pid;
	bool cancelled;
	u32 n;
	struct file *files[YZ_MAX_MODULE_FDS];
};

#define YZ_FD_HANDOFF_MAX_PENDING 64
static LIST_HEAD(yz_fd_handoff_pending_list);
static DEFINE_SPINLOCK(yz_fd_handoff_lock);
static u32 yz_fd_handoff_pending_count;

static void yz_fd_handoff_deliver(struct callback_head *head)
{
	struct yz_fd_handoff_pending *p =
	    container_of(head, struct yz_fd_handoff_pending, twork);
	unsigned long flags;
	u32 i;
	int fd;
	bool cancelled;

	spin_lock_irqsave(&yz_fd_handoff_lock, flags);
	list_del(&p->list);
	yz_fd_handoff_pending_count--;
	cancelled = p->cancelled;
	spin_unlock_irqrestore(&yz_fd_handoff_lock, flags);
	if (cancelled || current->flags & PF_EXITING || current->mm != p->mm ||
	    !yz_auth_ticket_begin(&p->ticket))
		goto out;
	for (i = 0; i < p->n; i++) {
		fd = get_unused_fd_flags(O_CLOEXEC);
		if (fd < 0)
			continue;
		fd_install(fd, p->files[i]);
		p->files[i] = NULL;
	}
	yz_auth_end();
out:
	for (i = 0; i < p->n; i++)
		if (p->files[i])
			fput(p->files[i]);
	mmdrop(p->mm);
	kfree(p);
	module_put(THIS_MODULE);
}

int yz_fd_handoff_submit(void __user *arg)
{
	struct yz_handoff_cmd cmd;
	struct yz_fd_handoff_pending *p, *old;
	struct task_struct *task;
	unsigned long flags;
	u32 i;
	int ret;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	if (!cmd.pid || cmd.n_fds > YZ_MAX_MODULE_FDS)
		return -EINVAL;
	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		return -ENOMEM;
	ret = yz_auth_current_ticket(&p->ticket);
	if (ret)
		goto fail;
	p->pid = cmd.pid;
	p->n = cmd.n_fds;
	for (i = 0; i < p->n; i++) {
		p->files[i] = fget(cmd.fds[i]);
		if (!p->files[i]) {
			ret = -EBADF;
			goto fail;
		}
	}
	rcu_read_lock();
	task = get_pid_task(find_vpid(cmd.pid), PIDTYPE_PID);
	rcu_read_unlock();
	if (!task) {
		ret = -ESRCH;
		goto fail;
	}
	ret = yz_auth_target_task(task);
	if (ret)
		goto fail_task;
	task_lock(task);
	p->mm = task->mm;
	if (p->mm)
		mmgrab(p->mm);
	task_unlock(task);
	if (!p->mm) {
		ret = -ESRCH;
		goto fail_task;
	}
	if (!try_module_get(THIS_MODULE)) {
		ret = -ENODEV;
		goto fail_task;
	}
	init_task_work(&p->twork, yz_fd_handoff_deliver);
	spin_lock_irqsave(&yz_fd_handoff_lock, flags);
	if (yz_fd_handoff_pending_count >= YZ_FD_HANDOFF_MAX_PENDING) {
		spin_unlock_irqrestore(&yz_fd_handoff_lock, flags);
		module_put(THIS_MODULE);
		ret = -ENOSPC;
		goto fail_task;
	}
	/* A replaced callback keeps its own allocation until it runs. Never
	 * overwrite/requeue the callback_head of an already queued handoff. */
	list_for_each_entry (old, &yz_fd_handoff_pending_list, list)
		if (old->pid == p->pid)
			old->cancelled = true;
	list_add_tail(&p->list, &yz_fd_handoff_pending_list);
	yz_fd_handoff_pending_count++;
	spin_unlock_irqrestore(&yz_fd_handoff_lock, flags);
	ret = yz_task_work_add(task, &p->twork, TWA_RESUME);
	put_task_struct(task);
	if (!ret)
		return 0;
	spin_lock_irqsave(&yz_fd_handoff_lock, flags);
	list_del(&p->list);
	yz_fd_handoff_pending_count--;
	spin_unlock_irqrestore(&yz_fd_handoff_lock, flags);
	module_put(THIS_MODULE);
	goto fail;
fail_task:
	put_task_struct(task);
fail:
	for (i = 0; i < p->n; i++)
		if (p->files[i])
			fput(p->files[i]);
	if (p->mm)
		mmdrop(p->mm);
	kfree(p);
	return ret;
}

void yz_fd_handoff_release(pid_t pid)
{
	struct yz_fd_handoff_pending *p;
	unsigned long flags;

	spin_lock_irqsave(&yz_fd_handoff_lock, flags);
	list_for_each_entry (p, &yz_fd_handoff_pending_list, list)
		if (p->pid == pid)
			p->cancelled = true;
	spin_unlock_irqrestore(&yz_fd_handoff_lock, flags);
}

void yz_fd_handoff_init(void)
{
	pr_info("yukizygisk: fd_handoff: authenticated fd broker armed\n");
}

void yz_fd_handoff_exit(void)
{
	/* Every queued callback pins THIS_MODULE and owns its files/mm until
	 * execution or task exit; module exit cannot race its code lifetime. */
	WARN_ON(!list_empty(&yz_fd_handoff_pending_list));
}
