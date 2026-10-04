/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Standalone LKM entry point.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/printk.h>

#include "feature/api.h"
#include "feature/process_exit.h"
#include "core/bootstrap.h"
#include "core/auth.h"
#include "core/control.h"
#include "core/lifecycle.h"
#include "host/host.h"
#include "uapi/yukizygisk.h"
#include <viola.h>
#include <viola_identity.h>

VIOLA_EMBED_IDENTITY(VIOLA_ROLE_KO, VIOLA_ABI_ARM64, VIOLA_BUILD_KMI);

static unsigned int yz_init_stage_mask = 0x3f;
module_param_named(init_stage_mask, yz_init_stage_mask, uint, 0644);
MODULE_PARM_DESC(init_stage_mask,
		 "Debug stage mask: 0x01 exec, 0x02 events, 0x04 lifecycle, "
		 "0x08 fd_handoff, 0x10 control, 0x20 bootstrap");

#define YZ_INIT_STAGE_EXEC 0x01u
#define YZ_INIT_STAGE_EVENTS 0x02u
#define YZ_INIT_STAGE_LIFECYCLE 0x04u
#define YZ_INIT_STAGE_FD_HANDOFF 0x08u
#define YZ_INIT_STAGE_CONTROL 0x10u
#define YZ_INIT_STAGE_BOOTSTRAP 0x20u

static bool yz_stage_exec_active;
static bool yz_stage_events_active;
static bool yz_stage_lifecycle_active;
static bool yz_stage_fd_handoff_active;
static bool yz_stage_control_active;
static bool yz_stage_bootstrap_active;
static bool yz_stage_lsm_active;
static bool yz_stage_host_active;
static bool yz_stage_auth_active;
static bool yz_stage_process_exit_active;
static bool yz_stage_history_active;
static bool yz_stage_policy_active;
static DEFINE_MUTEX(yz_lifecycle_lock);

static void yukizygisk_deactivate_locked(bool skip_bootstrap)
{
	if (yz_stage_bootstrap_active) {
		if (!skip_bootstrap) {
			yukizygisk_bootstrap_exit();
			yz_stage_bootstrap_active = false;
		}
	}
	if (yz_stage_control_active) {
		yukizygisk_control_exit();
		yz_stage_control_active = false;
	}
	if (yz_stage_fd_handoff_active) {
		yz_fd_handoff_exit();
		yz_stage_fd_handoff_active = false;
	}
	if (yz_stage_lifecycle_active) {
		yz_lifecycle_exit();
		yz_stage_lifecycle_active = false;
	}
	if (yz_stage_exec_active) {
		yz_exec_exit();
		yz_stage_exec_active = false;
	}
	if (yz_stage_process_exit_active) {
		yz_process_exit_disable();
		yz_stage_process_exit_active = false;
	}
	if (yz_stage_history_active) {
		yz_exit_history_exit();
		yz_stage_history_active = false;
	}
	if (yz_stage_events_active) {
		yz_events_exit();
		yz_stage_events_active = false;
	}
	if (yz_stage_lsm_active) {
		yz_host_lsm_exit();
		yz_stage_lsm_active = false;
	}
	if (yz_stage_auth_active) {
		yz_auth_exit();
		yz_stage_auth_active = false;
	}
	if (yz_stage_policy_active) {
		yz_load_policy_disable();
		/* A failed restore retains its module reference and retry
		 * state. Fail-close must keep the host available until that
		 * lease is restored; normal unload cannot enter with those
		 * references. */
		if (!yz_load_policy_busy()) {
			yz_load_policy_exit();
			yz_stage_policy_active = false;
		}
	}
	if (yz_stage_host_active && !yz_stage_policy_active) {
		yz_host_exit();
		yz_stage_host_active = false;
	}
}

void yukizygisk_bootstrap_fail_closed(void)
{
	mutex_lock(&yz_lifecycle_lock);
	yukizygisk_deactivate_locked(true);
	mutex_unlock(&yz_lifecycle_lock);
}

static int __init yukizygisk_init(void)
{
	int ret;

	pr_info("yukizygisk: standalone LKM initializing\n");

	pr_info("yukizygisk: init step host\n");
	ret = yz_host_init();
	if (ret) {
		pr_err("yukizygisk: init step host failed: %d\n", ret);
		return ret;
	}
	yz_stage_host_active = true;
	pr_info("yukizygisk: init step host done\n");

	/* Authentication precedes every business hook. Debug stage masks do
	 * not bypass the loader check or turn off the control permission gate. */
	ret = yz_auth_init();
	if (ret)
		goto err_control;
	yz_stage_auth_active = true;
	yz_exit_history_init();
	yz_stage_history_active = true;
	ret = yz_process_exit_enable();
	if (ret)
		goto err_control;
	yz_stage_process_exit_active = true;
	yz_load_policy_enable();
	yz_stage_policy_active = true;

	pr_info("yukizygisk: init step lsm\n");
	yz_host_lsm_init();
	yz_stage_lsm_active = true;
	pr_info("yukizygisk: init step lsm done\n");

	if (yz_init_stage_mask & YZ_INIT_STAGE_EXEC) {
		pr_info("yukizygisk: init step exec\n");
		yz_exec_init();
		yz_stage_exec_active = true;
		pr_info("yukizygisk: init step exec done\n");
	} else {
		pr_info("yukizygisk: init step exec skipped\n");
	}
	if (yz_init_stage_mask & YZ_INIT_STAGE_EVENTS) {
		pr_info("yukizygisk: init step events\n");
		yz_events_init();
		yz_stage_events_active = true;
		if (yz_host_policy_uses_fallback()) {
			struct yz_host_root_status status = { 0 };

			yz_host_get_root_status(&status);
			yz_events_emit_policy_refresh(status.owner,
						      YZ_POLICY_REFRESH_ALL);
		}
		pr_info("yukizygisk: init step events done\n");
	} else {
		pr_info("yukizygisk: init step events skipped\n");
	}
	if (yz_init_stage_mask & YZ_INIT_STAGE_LIFECYCLE) {
		pr_info("yukizygisk: init step lifecycle\n");
		yz_lifecycle_init();
		yz_stage_lifecycle_active = true;
		pr_info("yukizygisk: init step lifecycle done\n");
	} else {
		pr_info("yukizygisk: init step lifecycle skipped\n");
	}
	if (yz_init_stage_mask & YZ_INIT_STAGE_FD_HANDOFF) {
		pr_info("yukizygisk: init step fd_handoff\n");
		yz_fd_handoff_init();
		yz_stage_fd_handoff_active = true;
		pr_info("yukizygisk: init step fd_handoff done\n");
	} else {
		pr_info("yukizygisk: init step fd_handoff skipped\n");
	}

	{
		pr_info("yukizygisk: init step control\n");
		ret = yukizygisk_control_init();
		if (ret) {
			pr_err("yukizygisk: control backend init failed: %d\n",
			       ret);
			goto err_control;
		}
		yz_stage_control_active = true;
		pr_info("yukizygisk: init step control done\n");
	}

	{
		pr_info("yukizygisk: init step bootstrap\n");
		ret = yukizygisk_bootstrap_init();
		if (ret) {
			pr_err("yukizygisk: bootstrap init failed: %d\n", ret);
			goto err_bootstrap;
		}
		yz_stage_bootstrap_active = true;
		pr_info("yukizygisk: init step bootstrap done\n");
	}

	pr_info("yukizygisk: standalone LKM initialized\n");
	return 0;

err_bootstrap:
err_control:
	mutex_lock(&yz_lifecycle_lock);
	yukizygisk_deactivate_locked(false);
	mutex_unlock(&yz_lifecycle_lock);
	return ret;
}

static void __exit yukizygisk_exit(void)
{
	pr_info("yukizygisk: standalone LKM exiting\n");

	/*
	 * The guard enters fail-close through yz_lifecycle_lock. Cancel it before
	 * taking that lock so module exit cannot wait on a worker waiting on us.
	 */
	yukizygisk_bootstrap_exit();
	mutex_lock(&yz_lifecycle_lock);
	yz_stage_bootstrap_active = false;
	yukizygisk_deactivate_locked(true);
	mutex_unlock(&yz_lifecycle_lock);
}

module_init(yukizygisk_init);
module_exit(yukizygisk_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anatdx");
MODULE_DESCRIPTION("Standalone YukiZygisk kernel LKM");
