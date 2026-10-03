/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Exec hook registration and injection target detection.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#include <linux/binfmts.h>
#include <linux/compat.h>
#include <linux/compiler.h>
#include <linux/cred.h>
#include <linux/moduleparam.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/version.h>

#include "internal.h"
#include "klog.h"
#include "host/host.h"
#include "core/auth.h"
#include "tango.h"

static const char app_process[] = "app_process";

#define YZ_ENABLE_LSM_INJECTOR 1

static bool yz_exec_lsm_enabled = true;
module_param_named(probe_lsm, yz_exec_lsm_enabled, bool, 0644);
MODULE_PARM_DESC(probe_lsm, "Enable the zygote bprm LSM injector");

/* 6.12 made bprm_committed_creds const. */
#define YZ_BPRM_HOOK_TARGET "selinux_bprm_committed_creds"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#define YZ_BPRM_HOOK_CONST 1
#define YZ_BPRM_HOOK_ABI "const struct linux_binprm *"
#else
#define YZ_BPRM_HOOK_CONST 0
#define YZ_BPRM_HOOK_ABI "struct linux_binprm *"
#endif // #if LINUX_VERSION_CODE >= KERNEL_VERSIO...

#if YZ_BPRM_HOOK_CONST
typedef const struct linux_binprm yz_bprm_arg_t;
#else
typedef struct linux_binprm yz_bprm_arg_t;
#endif // #if YZ_BPRM_HOOK_CONST

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define YZ_BPRM_HOOK_CFI "kcfi"
#else
#define YZ_BPRM_HOOK_CFI "clang-cfi/.cfi_jt"
#endif // #if LINUX_VERSION_CODE >= KERNEL_VERSIO...

static void yz_exec_bprm_committed_creds(yz_bprm_arg_t *bprm);
static struct yz_host_lsm_hook yz_exec_hook = YZ_HOST_LSM_HOOK_INIT(
    bprm_committed_creds, YZ_BPRM_HOOK_TARGET, yz_exec_bprm_committed_creds, 0);

typedef void (*bprm_committed_creds_fn)(yz_bprm_arg_t *bprm);

static bool yz_exec_is_app_process_path(const char *filename)
{
	const char *base;

	if (!filename)
		return false;
	base = strrchr(filename, '/');
	base = base ? base + 1 : filename;
	return !strncmp(base, app_process, sizeof(app_process) - 1);
}

static bool yz_exec_is_init_child(void)
{
	struct task_struct *parent;
	bool is_init_child;

	rcu_read_lock();
	parent = rcu_dereference(current->real_parent);
	is_init_child = parent && task_pid_nr(parent) == 1;
	rcu_read_unlock();
	return is_init_child;
}

static void __nocfi yz_exec_bprm_committed_creds(yz_bprm_arg_t *bprm)
{
	const char *filename = bprm ? bprm->filename : NULL;
	char native_label[YZ_NATIVE_TARGET_VALUE_MAX] = {};
	u8 native_target_type = 0;
	bool early_native = false;
	bool by_sid;
	bool by_path;
	bool by_native;
	bool live_native;
	bool compat = false;

	((bprm_committed_creds_fn)yz_exec_hook.original)(bprm);

	if (!yz_auth_catalog_ready())
		return;
#ifdef CONFIG_COMPAT
	compat = is_compat_task();
#endif

	by_sid = yz_host_is_zygote(current_cred());
	by_path = yz_exec_is_app_process_path(filename);
	live_native =
	    !by_path && yz_config_match_native_target(filename, native_label,
						      sizeof(native_label),
						      &native_target_type);
	by_native = live_native && yz_exec_is_init_child();
	if (!by_path && !by_native &&
	    yz_early_native_match(filename, native_label, sizeof(native_label),
				  &native_target_type)) {
		by_native = true;
		early_native = true;
	}
	if (unlikely(by_sid || by_path || by_native)) {
		if (by_native)
			pr_info("yukizygisk: exec: native exec pid=%d tgid=%d "
				"file=%s target=%s early=%d\n",
				current->pid, current->tgid,
				filename ?: "(null)", native_label,
				early_native ? 1 : 0);

		pr_debug("yukizygisk: exec: exec pid=%d tgid=%d "
			 "file=%s [sid=%d path=%d native=%d]\n",
			 current->pid, current->tgid, filename ?: "(null)",
			 by_sid, by_path, by_native);

		/* Defer auxv rewrite to task_work. */
		if (by_path || by_native) {
			yz_injector_schedule(by_native, native_target_type,
					     early_native, compat,
					     native_label);
		}
	}
}

void yz_exec_init(void)
{
#if YZ_ENABLE_LSM_INJECTOR
	int ret;

	if (!yz_exec_lsm_enabled) {
		pr_info("yukizygisk: exec: LSM injector disabled by module "
			"parameter\n");
		return;
	}

	ret = yz_tango_enable();
	if (ret)
		pr_warn("yukizygisk: Tango hook unavailable err=%d\n", ret);
	ret = yz_host_register_lsm_hook(&yz_exec_hook);

	if (ret)
		pr_err("yukizygisk: exec: failed to register bprm hook: %d\n",
		       ret);
	else {
		pr_info("yukizygisk: exec: bprm hook ABI=%s resolver=%s\n",
			YZ_BPRM_HOOK_ABI, YZ_BPRM_HOOK_CFI);
		pr_info("yukizygisk: exec: armed (lazy side effects)\n");
	}
#else
	pr_info(
	    "yukizygisk: exec: LSM injector disabled for bootloop isolation\n");
#endif // #if YZ_ENABLE_LSM_INJECTOR
}

void yz_exec_exit(void)
{
	yz_tango_disable();
	yz_load_policy_cleanup();
#if YZ_ENABLE_LSM_INJECTOR
	if (yz_exec_lsm_enabled)
		yz_host_unregister_lsm_hook(&yz_exec_hook);
#endif // #if YZ_ENABLE_LSM_INJECTOR
}

bool yz_exec_injection_enabled(void)
{
	return READ_ONCE(yz_exec_lsm_enabled);
}
