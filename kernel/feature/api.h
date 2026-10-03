/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Kernel feature interfaces used by the standalone core.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#ifndef YZ_FEATURE_API_H
#define YZ_FEATURE_API_H

#include <linux/types.h>

struct cred;
struct file;
struct task_struct;
struct yz_native_targets_cmd;
struct yz_runtime_query_cmd;
struct yz_runtime_record;
struct yz_runtime_report_cmd;
struct yz_safemode_status_cmd;
struct yz_zygote_variants_cmd;

void yz_exec_init(void);
void yz_exec_exit(void);
void yz_events_init(void);
void yz_events_exit(void);
void yz_lifecycle_init(void);
void yz_lifecycle_exit(void);
void yz_fd_handoff_init(void);
void yz_fd_handoff_exit(void);
int yz_fd_handoff_submit(void __user *arg);
void yz_events_emit_reload(void);
void yz_events_emit_viola_recovery(u32 owner);
void yz_events_emit_policy_refresh(u32 owner, u32 uid);

void yz_config_set_linker_offsets(u64 dlopen_off, u64 dlsym_off);
void yz_config_set_compat_linker_offsets(u64 dlopen_off, u64 dlsym_off);
void yz_config_set_first_stage_loader(bool enabled);
int yz_config_set_native_targets(const struct yz_native_targets_cmd *cmd);
int yz_load_policy_restore_native(pid_t tgid);
int yz_load_policy_allow_module(pid_t tgid, struct file *dir,
				const struct cred *cred);
int yz_safemode_get_status(struct yz_safemode_status_cmd *cmd);
int yz_safemode_get_variants(struct yz_zygote_variants_cmd *cmd);
int yz_runtime_query(struct yz_runtime_record *entries, u32 capacity,
		     struct yz_runtime_query_cmd *query);
int yz_runtime_report(const struct yz_runtime_report_cmd *report);
bool yz_runtime_is_native(pid_t pid, u64 start_boottime);
u8 yz_runtime_task_abi(struct task_struct *task);
u8 yz_runtime_report_abi(u32 pid, u32 generation);

#endif
