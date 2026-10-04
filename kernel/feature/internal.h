/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Private interfaces between kernel feature units.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#ifndef YZ_FEATURE_INTERNAL_H
#define YZ_FEATURE_INTERNAL_H

#include "api.h"
#include "process_exit.h"
#include "uapi/yukizygisk.h"

struct mm_struct;
struct yz_file_load_policy;

#define YZ_LOADER_NAME64 "libyukilinker64.so"
#define YZ_LOADER_NAME32 "libyukilinker32.so"
#define YZ_CORE_NAME64 "libzygisk64.so"
#define YZ_CORE_NAME32 "libzygisk32.so"
#define YZ_NATIVE_CORE_NAME64 "libyukizncore64.so"
#define YZ_NATIVE_CORE_NAME32 "libyukizncore32.so"
#define YZ_LOADER_PATH "/data/adb/yukizygisk/lib/" YZ_LOADER_NAME64
#define YZ_LOADER32_PATH "/data/adb/yukizygisk/lib/" YZ_LOADER_NAME32
#define YZ_CORE_PATH "/data/adb/yukizygisk/lib/" YZ_CORE_NAME64
#define YZ_CORE32_PATH "/data/adb/yukizygisk/lib/" YZ_CORE_NAME32
#define YZ_NATIVE_CORE_PATH "/data/adb/yukizygisk/lib/" YZ_NATIVE_CORE_NAME64
#define YZ_NATIVE_CORE32_PATH "/data/adb/yukizygisk/lib/" YZ_NATIVE_CORE_NAME32
#define YZ_SYSTEM_LINKER64 "/system/bin/linker64"
#define YZ_SYSTEM_LINKER32 "/system/bin/linker"
#define YZ_EARLY_MANIFEST_DEFAULT "/metadata/yukizygisk/native_snapshot.bin"
#define YZ_EARLY_MANIFEST_LEGACY                                               \
	"/metadata/watchdog/ksu/yukizygisk/native_snapshot.bin"
#define YZ_EARLY_LOADER_DEFAULT "/metadata/yukizygisk/" YZ_LOADER_NAME64
#define YZ_EARLY_LOADER32_DEFAULT "/metadata/yukizygisk/" YZ_LOADER_NAME32
#define YZ_EARLY_LOADER_LEGACY                                                 \
	"/metadata/watchdog/ksu/yukizygisk/" YZ_LOADER_NAME64
#define YZ_EARLY_LOADER32_LEGACY                                               \
	"/metadata/watchdog/ksu/yukizygisk/" YZ_LOADER_NAME32
#define YZ_EARLY_NATIVE_CORE_DEFAULT                                           \
	"/metadata/yukizygisk/" YZ_NATIVE_CORE_NAME64
#define YZ_EARLY_NATIVE_CORE_LEGACY                                            \
	"/metadata/watchdog/ksu/yukizygisk/" YZ_NATIVE_CORE_NAME64
#define YZ_EARLY_NATIVE_CORE32_DEFAULT                                         \
	"/metadata/yukizygisk/" YZ_NATIVE_CORE_NAME32
#define YZ_EARLY_NATIVE_CORE32_LEGACY                                          \
	"/metadata/watchdog/ksu/yukizygisk/" YZ_NATIVE_CORE_NAME32
#define YZ_VMA_NAME "memfd:"
#define YZ_VMA_NAME_LEN sizeof(YZ_VMA_NAME)
#define YZ_LOADER_MAX_SZ (8u << 20) /* sanity cap on a payload image */
#define YZ_DLEXT_USE_LIBRARY_FD 0x10 /* android_dlextinfo.flags bit */
#define YZ_DLEXT_FORCE_LOAD 0x40

struct yz_early_packet_state {
	int packet_fd;
	int module_fds[YZ_NATIVE_TARGET_MAX];
	u32 module_fd_count;
};

void yz_events_emit_specialize(u32 pid, u32 appid);
void yz_events_emit_safemode(u32 pid, u32 crashes);
void yz_events_emit_zygote_exit(const struct yz_zygote_exit_event *event);
void yz_lifecycle_on_setresuid(uid_t old_uid, uid_t new_uid);
void yz_fd_handoff_release(struct task_struct *task);

const char *yz_basename(const char *path);
void yz_copy_name(char *dst, size_t dst_len, const char *src);
bool yz_config_match_native_target(const char *filename, char *label,
				   size_t label_len, u8 *target_type);
void yz_config_fill_linker_offsets(u64 dlopen, u64 dlsym, u64 dlopen32,
				   u64 dlsym32);
u64 yz_config_dlopen_offset(bool compat);
u64 yz_config_dlsym_offset(bool compat);
bool yz_config_first_stage_loader(void);
/* A successful begin is consumed exactly once by publish or restore. */
struct yz_file_load_policy *yz_load_policy_begin(void);
void yz_load_policy_restore_state(struct yz_file_load_policy *state);
void yz_load_policy_publish_native(struct yz_file_load_policy *state);
bool yz_safemode_is_active(void);
bool yz_safemode_should_skip(const char *name);
void yz_safemode_fill_runtime_query(struct yz_runtime_query_cmd *query);
bool yz_runtime_parse_zygote_args(struct mm_struct *mm, char *socket_name,
				  size_t socket_name_len);
void yz_runtime_read_process(struct mm_struct *mm, char *process,
			     size_t process_len);
u32 yz_runtime_begin(u8 kind, u8 abi, u8 target_type, u32 flags,
		     const char *process, const char *target);
void yz_runtime_set_state(u32 pid, u32 generation, u8 state);
u8 yz_runtime_abi(pid_t pid);
bool yz_early_native_match(const char *filename, char *label, size_t label_len,
			   u8 *target_type);
const char *yz_early_native_loader_path(bool compat);
const char *yz_early_native_core_path(bool compat);
void yz_early_native_packet_init(struct yz_early_packet_state *state);
void yz_early_native_packet_close(struct yz_early_packet_state *state);
int yz_early_native_stage_packet(u8 target_type, const char *target,
				 bool compat,
				 struct yz_early_packet_state *state);
void yz_payload_close_fd(int fd);
void yz_payload_cache_name(char *buf, size_t len);
int yz_payload_stage_image(const char *path, const char *name,
			   struct yz_file_load_policy *policy_state,
			   unsigned int core_role, bool compat);
int yz_payload_stage_fd(const char *path, const char *name,
			struct yz_file_load_policy *policy_state);
int yz_payload_stage_file_fd(const char *path,
			     struct yz_file_load_policy *policy_state);
bool yz_exec_injection_enabled(void);
void yz_injector_schedule(bool native, u8 target_type, bool early_native,
			  bool compat, const char *label);

bool yz_runtime_on_exit(struct task_struct *task);
void yz_runtime_reconcile(void);
bool yz_runtime_take_exit(struct yz_target_exit_event *event);
void yz_lifecycle_on_exit(struct task_struct *task);
enum yz_policy_reap_reason {
	YZ_POLICY_REAP_MISSING_OWNER,
	YZ_POLICY_REAP_OVERFLOW,
	YZ_POLICY_REAP_ENABLE,
};
void yz_load_policy_reap(enum yz_policy_reap_reason reason);
void yz_load_policy_fill_health(struct yz_health_policy *policy,
				struct yz_health_cleanup *cleanup);
void yz_load_policy_note_exit_work(void);
bool yz_load_policy_on_exit(struct task_struct *task);
void yz_load_policy_drain_exits(void);
void yz_exit_history_set_active(bool active);
void yz_exit_history_wake_readers(void);
void yz_exit_history_flush(void);
void yz_exit_history_append(const struct yz_runtime_record *record,
			    u64 start_boottime, u64 observed_boottime,
			    u32 status);
void yz_events_emit_target_exit(const struct yz_target_exit_event *event);

#endif
