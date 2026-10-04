/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Kernel/userspace UAPI.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _UAPI_YUKIZYGISK_H
#define _UAPI_YUKIZYGISK_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define YZ_NETLINK_PROTO 27
#define YZ_NL_GROUP_EVENTS 1
#define YZ_NL_MSG_EVENT 0x10

#define YZ_PRCTL_BOOTSTRAP_OPTION 0x595a0001
#define YZ_PRCTL_BOOTSTRAP_MAGIC_YUKIHOOK 0x6b6f6f68696b7579ULL
#define YZ_PRCTL_CONTROL_OPTION 0x595a0002
#define YZ_PRCTL_CONTROL_MAGIC 0x797a6374

enum yz_event_type {
	YZ_EV_SPECIALIZE = 1,
	YZ_EV_RELOAD = 2,
	YZ_EV_SAFEMODE = 3,
	YZ_EV_POLICY_REFRESH = 4,
	YZ_EV_ZYGOTE_EXIT = 5,
	YZ_EV_VIOLA_RECOVERY = 6,
	YZ_EV_TARGET_EXIT = 7,
};

#define YZ_POLICY_REFRESH_ALL ((__u32)~0U)

struct yz_event {
	__u32 type;
	__u32 pid;
	__u32 appid;
};

/* Only YZ_EV_ZYGOTE_EXIT uses this extended payload. */
struct yz_zygote_exit_event {
	struct yz_event event;
	__u32 generation;
	__aligned_u64 start_boottime;
	__aligned_u64 observed_boottime;
	__u8 abi;
	__u8 reserved[7];
};

/* Process-group exit observation; appid carries the observed wait status. */
struct yz_target_exit_event {
	struct yz_event event;
	__u32 generation;
	__aligned_u64 start_boottime;
	__aligned_u64 observed_boottime;
	__u8 abi;
	__u8 kind;
	__u8 reserved[6];
};

#define YZ_MAX_MODULE_FDS 8

#define YZ_IOCTL_MAGIC 'Y'

#define YZ_IOCTL_HANDOFF _IOC(_IOC_WRITE, YZ_IOCTL_MAGIC, 50, 0)

struct yz_handoff_cmd {
	__u32 pid;
	__u32 appid;
	__u32 n_fds;
	__u32 flags;
	__s32 fds[YZ_MAX_MODULE_FDS];
};

#define YZ_IOCTL_SET_DLOPEN _IOC(_IOC_WRITE, YZ_IOCTL_MAGIC, 51, 0)

struct yz_dlopen_cmd {
	__u64 dlopen_offset;
	__u64 dlsym_offset;
};

#define YZ_IOCTL_RELOAD _IOC(_IOC_WRITE, YZ_IOCTL_MAGIC, 52, 0)

#define YZ_IOCTL_SET_YUKILINKER _IOC(_IOC_WRITE, YZ_IOCTL_MAGIC, 53, 0)

struct yz_yukilinker_cmd {
	__u32 enabled;
};

#define YZ_IOCTL_UMOUNT_PID _IOC(_IOC_WRITE, YZ_IOCTL_MAGIC, 54, 0)

struct yz_umount_pid_cmd {
	__u32 pid;
};

#define YZ_IOCTL_UNMAP_PID _IOC(_IOC_WRITE, YZ_IOCTL_MAGIC, 55, 0)

#define YZ_MAX_UNMAP_SEGS 8

struct yz_unmap_pid_cmd {
	__u32 pid;
	__u32 n_segs;
	__u64 addr[YZ_MAX_UNMAP_SEGS];
	__u64 size[YZ_MAX_UNMAP_SEGS];
};

#define YZ_IOCTL_UNMAP_SELF _IOC(_IOC_WRITE, YZ_IOCTL_MAGIC, 56, 0)

struct yz_unmap_self_cmd {
	__u32 n_segs;
	__u32 reserved;
	__u64 addr[YZ_MAX_UNMAP_SEGS];
	__u64 size[YZ_MAX_UNMAP_SEGS];
};

#define YZ_IOCTL_PATCH_TEXT _IOC(_IOC_WRITE, YZ_IOCTL_MAGIC, 57, 0)

#define YZ_PATCH_TEXT_MAX 64

struct yz_patch_text_cmd {
	__u32 pid;
	__u32 len;
	__u64 addr;
	__u8 bytes[YZ_PATCH_TEXT_MAX];
};

#define YZ_IOCTL_SET_NATIVE_TARGETS _IOC(_IOC_WRITE, YZ_IOCTL_MAGIC, 58, 0)

#define YZ_NATIVE_TARGET_MAX 64
#define YZ_NATIVE_TARGET_VALUE_MAX 256
#define YZ_NATIVE_MODULE_ID_MAX 64
#define YZ_NATIVE_MODULE_PATH_MAX 512

enum yz_native_target_type {
	YZ_NATIVE_TARGET_NAME = 1,
	YZ_NATIVE_TARGET_PATH = 2,
};

struct yz_native_target {
	__u8 type;
	__u8 reserved[3];
	char value[YZ_NATIVE_TARGET_VALUE_MAX];
};

struct yz_native_targets_cmd {
	__u32 count;
	struct yz_native_target targets[YZ_NATIVE_TARGET_MAX];
};

#define YZ_EARLY_NATIVE_MAGIC 0x59454e5a /* YENZ */
#define YZ_EARLY_NATIVE_VERSION 2
#define YZ_EARLY_NATIVE_FLAG_ENABLED (1U << 0)
#define YZ_EARLY_NATIVE_FLAG_ABI32 (1U << 1)
#define YZ_EARLY_NATIVE_FLAG_ABI64 (1U << 2)
#define YZ_EARLY_NATIVE_ENTRY_ABI32 (1U << 0)
#define YZ_EARLY_NATIVE_ENTRY_ABI64 (1U << 1)

#define YZ_LOAD_CONFIG_VALID (1U << 0)
#define YZ_LOAD_YUKILINKER (1U << 1)
#define YZ_LOAD_ANONYMOUS (1U << 2)

struct yz_early_native_snapshot_header {
	__u32 magic;
	__u16 version;
	__u16 header_size;
	__u16 entry_size;
	__u16 load_flags;
	__u32 flags;
	__u32 count;
	__u64 dlopen_offset;
	__u64 dlsym_offset;
	__u64 linker_size;
	__u64 dlopen32_offset;
	__u64 dlsym32_offset;
	__u64 linker32_size;
};

struct yz_early_native_entry {
	__u8 target_type;
	__u8 flags;
	__u16 reserved;
	char module_id[YZ_NATIVE_MODULE_ID_MAX];
	char target[YZ_NATIVE_TARGET_VALUE_MAX];
	char lib_path[YZ_NATIVE_MODULE_PATH_MAX];
};

#define YZ_EARLY_NATIVE_PACKET_MAGIC 0x59504e5a /* YPNZ */

struct yz_early_native_packet_header {
	__u32 magic;
	__u16 version;
	__u16 header_size;
	__u16 entry_size;
	__u16 load_flags;
	__u32 count;
};

struct yz_early_native_packet_entry {
	struct yz_early_native_entry module;
	__s32 fd;
	__u32 reserved;
};

#define YZ_IOCTL_RESTORE_NATIVE_LOAD_POLICY                                  \
	_IOC(_IOC_WRITE, YZ_IOCTL_MAGIC, 59, 0)

struct yz_native_load_policy_cmd {
	__u32 pid;
};

#define YZ_IOCTL_GET_SAFEMODE _IOC(_IOC_READ, YZ_IOCTL_MAGIC, 60, 0)

#define YZ_ZYGOTE_NAME_MAX 64
#define YZ_ZYGOTE_CRASH_THRESHOLD 3

struct yz_safemode_status_cmd {
	__u32 active;
	__u32 zygote_crashes;
	char zygote[YZ_ZYGOTE_NAME_MAX];
};

#define YZ_IOCTL_GET_ROOT_STATUS _IOC(_IOC_READ, YZ_IOCTL_MAGIC, 61, 0)

enum yz_root_owner_uapi {
	YZ_ROOT_OWNER_UAPI_NONE = 0,
	YZ_ROOT_OWNER_UAPI_KERNELSU = 1,
	YZ_ROOT_OWNER_UAPI_KERNELPATCH = 2,
};

#define YZ_ROOT_STATUS_KSU_REDIRECT (1U << 0)
#define YZ_ROOT_STATUS_POLICY_KERNEL (1U << 1)
#define YZ_ROOT_STATUS_POLICY_FALLBACK (1U << 2)
#define YZ_ROOT_STATUS_POLICY_CACHE_READY (1U << 3)

struct yz_root_status_cmd {
	__u32 owner;
	__u32 mask;
	__u32 flags;
	__u32 reserved;
};

#define YZ_IOCTL_UID_SHOULD_UMOUNT                                  \
	_IOC(_IOC_READ | _IOC_WRITE, YZ_IOCTL_MAGIC, 62, 0)

struct yz_uid_policy_cmd {
	__u32 uid;
	__u32 should_umount;
};

#define YZ_POLICY_CACHE_MAGIC 0x43505a59U /* YZPC */
#define YZ_POLICY_CACHE_VERSION 1U
#define YZ_POLICY_CACHE_MAX_ENTRIES 8192U
#define YZ_POLICY_CACHE_F_COMPLETE (1U << 0)

struct yz_policy_cache_header {
	__u32 magic;
	__u16 version;
	__u16 header_size;
	__u16 entry_size;
	__u16 flags;
	__u32 owner;
	__u32 generation;
	__u32 count;
	__u32 default_should_umount;
	__u32 manager_appid;
};

struct yz_policy_cache_entry {
	__u32 uid;
	__u32 should_umount;
};

#define YZ_IOCTL_SET_POLICY_CACHE                                  \
	_IOC(_IOC_WRITE, YZ_IOCTL_MAGIC, 63, 0)

struct yz_policy_cache_cmd {
	__s32 fd;
	__u32 reserved;
};

#define YZ_ZYGOTE_VARIANT_MAX 4

struct yz_zygote_variant {
	__u32 pid;
	__u32 crashes;
	char name[YZ_ZYGOTE_NAME_MAX];
};

struct yz_zygote_variants_cmd {
	__u32 count;
	__u32 reserved;
	struct yz_zygote_variant entries[YZ_ZYGOTE_VARIANT_MAX];
};

#define YZ_IOCTL_GET_ZYGOTE_VARIANTS                                \
	_IOC(_IOC_READ, YZ_IOCTL_MAGIC, 64, 0)

#define YZ_IOCTL_PREPARE_RUNTIME_POLICY \
	_IOC(_IOC_NONE, YZ_IOCTL_MAGIC, 65, 0)

#define YZ_IOCTL_ALLOW_MODULE_LOAD_POLICY \
	_IOC(_IOC_WRITE, YZ_IOCTL_MAGIC, 66, 0)

struct yz_module_load_policy_cmd {
	__u32 pid;
	__s32 dirfd; // Module directory or read-only source memfd.
};

#define YZ_IOCTL_SET_DLOPEN32 _IOC(_IOC_WRITE, YZ_IOCTL_MAGIC, 67, 0)

#define YZ_RUNTIME_RECORD_MAX 128
#define YZ_RUNTIME_PROCESS_MAX 256

enum yz_runtime_kind {
	YZ_RUNTIME_KIND_ZYGOTE = 1,
	YZ_RUNTIME_KIND_NATIVE = 2,
};

enum yz_runtime_state {
	YZ_RUNTIME_STATE_DETECTED = 1,
	YZ_RUNTIME_STATE_REDIRECTED = 2,
	YZ_RUNTIME_STATE_INJECTED = 3,
	YZ_RUNTIME_STATE_FAILED = 4,
	YZ_RUNTIME_STATE_SAFEMODE = 5,
	YZ_RUNTIME_STATE_EXITED = 6,
};

enum yz_runtime_abi {
	YZ_RUNTIME_ABI_UNKNOWN = 0,
	YZ_RUNTIME_ABI_32 = 1,
	YZ_RUNTIME_ABI_64 = 2,
};

#define YZ_RUNTIME_F_EARLY_NATIVE (1U << 0)

/* Saved pre-exit state; meaningful with YZ_RUNTIME_CAP_INJECTION_STATE. */
#define YZ_RUNTIME_F_INJECTION_STATE_SHIFT 8
#define YZ_RUNTIME_F_INJECTION_STATE_MASK                                      \
	(7U << YZ_RUNTIME_F_INJECTION_STATE_SHIFT)

#define YZ_RUNTIME_CAP_MODULE_IMAGE_POLICY (1U << 0)
#define YZ_RUNTIME_CAP_ZYGOTE_MODULE_REPORT (1U << 1)
#define YZ_RUNTIME_CAP_INJECTION_STATE (1U << 2)
#define YZ_RUNTIME_CAP_EXIT_HISTORY (1U << 3)
#define YZ_RUNTIME_CAP_HEALTH (1U << 4)

#define YZ_HEALTH_VERSION 1
#define YZ_HEALTH_POLICY_NONE 0
#define YZ_HEALTH_POLICY_NATIVE 1
#define YZ_HEALTH_POLICY_MODULE 2

struct yz_health_history {
	__aligned_u64 epoch;
	__aligned_u64 oldest_sequence;
	__aligned_u64 newest_sequence;
	__aligned_u64 coverage_generation;
	__u32 count;
	__u32 observer_active;
};

struct yz_health_policy {
	__u32 enabled;
	__u32 states_current;
	__u32 states_peak;
	__u32 preparing;
	__u32 native_active;
	__u32 module_groups_active;
	__u32 holders_current;
	__u32 holders_peak;
	__u32 retired_current;
	__u32 restore_inflight;
	__u32 retry_waiting;
	__u32 reserved;
	__aligned_u64 oldest_retired_boottime;
	__aligned_u64 last_restore_boottime;
	__aligned_u64 restore_attempts;
	__aligned_u64 restore_failures;
	__aligned_u64 restore_successes;
	__s32 last_restore_errno;
	__u32 last_restore_kind;
};

struct yz_health_cleanup {
	__u32 queued_owners;
	__u32 inflight_owners;
	__u32 queue_peak;
	__u32 reconcile_pending;
	__aligned_u64 queue_enqueued;
	__aligned_u64 queue_overflows;
	__aligned_u64 owner_cleanup_calls;
	__aligned_u64 owner_index_visits;
	__aligned_u64 watch_index_visits;
	__aligned_u64 fullscan_overflow;
	__aligned_u64 fullscan_enable;
	__aligned_u64 fullscan_missing_owner;
	__aligned_u64 fullscan_disable;
	__aligned_u64 fullscan_entries;
	__aligned_u64 alive_checks_publish;
	__aligned_u64 alive_checks_scan;
	__aligned_u64 exit_worker_runs;
	__aligned_u64 retry_worker_runs;
};

/* Sections are coherent separately within this boottime sampling window.
 * Counters survive feature toggles and belong to the loaded kernel component.
 */
struct yz_health_query_cmd {
	__u32 version;
	__u32 size;
	__u32 flags;
	__u32 reserved;
	__aligned_u64 sample_begin_boottime;
	__aligned_u64 sample_end_boottime;
	struct yz_health_history history;
	struct yz_health_policy policy;
	struct yz_health_cleanup cleanup;
};

#define YZ_IOCTL_GET_HEALTH _IOC(_IOC_READ | _IOC_WRITE, YZ_IOCTL_MAGIC, 82, 0)

#define YZ_EXIT_HISTORY_VERSION 1
#define YZ_EXIT_HISTORY_MAX 128
#define YZ_EXIT_HISTORY_BATCH_MAX 32
#define YZ_EXIT_HISTORY_F_RESET (1U << 0)
#define YZ_EXIT_HISTORY_F_OVERFLOW (1U << 1)

struct yz_exit_history_record {
	__aligned_u64 sequence;
	struct yz_target_exit_event event;
	__u32 runtime_flags;
	__u8 injection_state;
	__u8 target_type;
	__u8 reserved[2];
	char process[YZ_RUNTIME_PROCESS_MAX];
	char target[YZ_NATIVE_TARGET_VALUE_MAX];
};

struct yz_exit_history_header {
	__u32 version;
	__u32 record_size;
	__u32 count;
	__u32 flags;
	__aligned_u64 epoch;
	__aligned_u64 oldest_sequence;
	__aligned_u64 newest_sequence;
	__aligned_u64 next_sequence;
	__aligned_u64 lost_first;
	__aligned_u64 lost_last;
	__aligned_u64 coverage_generation;
	__u32 observer_active;
	__u32 reserved;
};

/* Each successful read returns one header followed by count records. */
struct yz_exit_history_fd_cmd {
	__aligned_u64 epoch;
	__aligned_u64 after_sequence;
	__s32 fd;
	__u32 flags;
};

#define YZ_IOCTL_GET_EXIT_HISTORY_FD                                           \
	_IOC(_IOC_READ | _IOC_WRITE, YZ_IOCTL_MAGIC, 81, 0)

struct yz_runtime_record {
	__u32 pid;
	__u32 generation;
	__u32 restarts;
	__u8 kind;
	__u8 state;
	__u8 abi;
	__u8 target_type;
	__u32 flags;
	char process[YZ_RUNTIME_PROCESS_MAX];
	char target[YZ_NATIVE_TARGET_VALUE_MAX];
	char module_id[YZ_NATIVE_MODULE_ID_MAX];
};

struct yz_runtime_query_cmd {
	__u32 capacity;
	__u32 count;
	__aligned_u64 entries;
	__u32 generation;
	__u32 safe_mode;
	__u32 zygote_crashes;
	__u32 capabilities; // Zero on kernels with directory-only load policy.
	char safe_mode_zygote[YZ_ZYGOTE_NAME_MAX];
};

struct yz_runtime_report_cmd {
	__u32 pid;
	__u32 generation;
	__u8 kind;
	__u8 module_state; // Zero preserves success-only reports from older daemons.
	__u8 reserved[2];
	char module_id[YZ_NATIVE_MODULE_ID_MAX];
};

#define YZ_IOCTL_GET_RUNTIME                                              \
	_IOC(_IOC_READ | _IOC_WRITE, YZ_IOCTL_MAGIC, 68, 0)
#define YZ_IOCTL_REPORT_RUNTIME _IOC(_IOC_WRITE, YZ_IOCTL_MAGIC, 69, 0)
#define YZ_IOCTL_DAEMON_READY _IOC(_IOC_NONE, YZ_IOCTL_MAGIC, 70, 0)

enum yz_memory_type {
	/* Zero preserves anonymous loading with older daemons. */
	YZ_MEMORY_ANONYMOUS = 0,
	YZ_MEMORY_FILE = 1,
};

struct yz_config {
	__u8 yukilinker;
	__u8 denylist_mode;
	__u8 dmesg_log;
	__u8 memory_type;
};

#include "viola_health.h"

#endif /* _UAPI_YUKIZYGISK_H */
