/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - prctl bootstrap and root control sessions.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>

#include "core/bootstrap.h"
#include "core/control.h"
#include "host/runtime.h"
#include "uapi/viola.h"
#include "uapi/yukizygisk.h"

enum yz_prctl_abi {
	YZ_PRCTL_ABI_ARM64_WRAPPER,
	YZ_PRCTL_ABI_DIRECT,
};

struct yz_control_session {
	struct callback_head twork;
	void __user *out_fd;
	bool launcher;
};

static struct kprobe yz_bootstrap_kp;
static enum yz_prctl_abi yz_bootstrap_abi;
static bool yz_bootstrap_registered;

/* The probe only queues bounded work. Image reads, hashing and authorization
 * run after returning to process context, never inside the kprobe callback. */
static void yz_bootstrap_task_work(struct callback_head *head)
{
	struct yz_control_session *session =
		container_of(head, struct yz_control_session, twork);
	int fd = -ECANCELED;

	if (!(current->flags & PF_EXITING))
		fd = yukizygisk_control_install_fd(session->launcher);
	if (copy_to_user(session->out_fd, &fd, sizeof(fd)) && fd >= 0)
		yz_close_fd(fd);
	module_put(THIS_MODULE);
	kfree(session);
}

static void yz_queue_control_session(void __user *out_fd, bool launcher)
{
	struct yz_control_session *session;

	if (!out_fd || !current->mm ||
	    !uid_eq(current_euid(), GLOBAL_ROOT_UID) ||
	    !yukizygisk_control_available() || !try_module_get(THIS_MODULE))
		return;
	session = kzalloc(sizeof(*session), GFP_ATOMIC);
	if (!session) {
		module_put(THIS_MODULE);
		return;
	}
	session->out_fd = out_fd;
	session->launcher = launcher;
	init_task_work(&session->twork, yz_bootstrap_task_work);
	if (yz_task_work_add(current, &session->twork, TWA_RESUME)) {
		kfree(session);
		module_put(THIS_MODULE);
	}
}

static int yz_bootstrap_prctl_pre(struct kprobe *kp, struct pt_regs *regs)
{
#if defined(CONFIG_ARM64)
	struct pt_regs copied;
	const struct pt_regs *sysregs = regs;
	unsigned long option, magic, out_fd;

	(void)kp;
	if (yz_bootstrap_abi == YZ_PRCTL_ABI_ARM64_WRAPPER) {
		if (copy_from_kernel_nofault(&copied,
				(void *)regs->regs[0], sizeof(copied)))
			return 0;
		sysregs = &copied;
	}
	option = sysregs->regs[0];
	magic = sysregs->regs[1];
	out_fd = sysregs->regs[2];
	if ((u32)option == YZ_PRCTL_VIOLA_OPTION &&
	    (u32)magic == YZ_PRCTL_VIOLA_MAGIC)
		yz_queue_control_session((void __user *)out_fd, true);
	else if ((u32)option == YZ_PRCTL_CONTROL_OPTION &&
		 (u32)magic == YZ_PRCTL_CONTROL_MAGIC)
		yz_queue_control_session((void __user *)out_fd, false);
#else
	(void)kp;
	(void)regs;
#endif
	return 0;
}

struct yz_prctl_candidate {
	const char *symbol;
	enum yz_prctl_abi abi;
};

static int yz_bootstrap_register_prctl_hook(void)
{
#if defined(CONFIG_ARM64)
	static const struct yz_prctl_candidate candidates[] = {
		{ "__se_sys_prctl", YZ_PRCTL_ABI_DIRECT },
		{ "__arm64_sys_prctl", YZ_PRCTL_ABI_ARM64_WRAPPER },
	};
	int ret = -ENOENT;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(candidates); i++) {
		memset(&yz_bootstrap_kp, 0, sizeof(yz_bootstrap_kp));
		yz_bootstrap_kp.symbol_name = candidates[i].symbol;
		yz_bootstrap_kp.pre_handler = yz_bootstrap_prctl_pre;
		yz_bootstrap_abi = candidates[i].abi;
		ret = register_kprobe(&yz_bootstrap_kp);
		if (!ret) {
			yz_bootstrap_registered = true;
			pr_info("yukizygisk: prctl control hook armed on %s\n",
				candidates[i].symbol);
			return 0;
		}
	}

	return ret;
#else
	return -EOPNOTSUPP;
#endif
}

int yukizygisk_bootstrap_init(void)
{
	return yz_bootstrap_register_prctl_hook();
}

void yukizygisk_bootstrap_exit(void)
{
	if (yz_bootstrap_registered) {
		unregister_kprobe(&yz_bootstrap_kp);
		yz_bootstrap_registered = false;
	}
}
