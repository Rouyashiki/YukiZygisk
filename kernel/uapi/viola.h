/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Viola startup authentication protocol.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef YUKIZYGISK_VIOLA_UAPI_H
#define YUKIZYGISK_VIOLA_UAPI_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define YZ_VIOLA_VERSION 2u
#define YZ_PRCTL_VIOLA_OPTION 0x595a0003u
#define YZ_PRCTL_VIOLA_MAGIC 0x76696f6cu
#define YZ_VIOLA_RELEASE_SIZE 32u

enum yz_viola_role {
	YZ_VIOLA_QUERY = 1,
	YZ_VIOLA_ADMIN,
	YZ_VIOLA_LAUNCHER64,
	YZ_VIOLA_ARMED64,
	YZ_VIOLA_DAEMON64,
	YZ_VIOLA_DELEGATED32,
	YZ_VIOLA_LAUNCHER32,
	YZ_VIOLA_ARMED32,
	YZ_VIOLA_DAEMON32,
};

enum yz_viola_state {
	YZ_VIOLA_ABSENT = 0,
	YZ_VIOLA_STARTING,
	YZ_VIOLA_READY,
	YZ_VIOLA_LOST,
};

enum yz_viola_failure_stage {
	YZ_VIOLA_STAGE_NONE = 0,
	YZ_VIOLA_STAGE_LOADER,
	YZ_VIOLA_STAGE_CATALOG,
	YZ_VIOLA_STAGE_EXEC_IMAGE,
	YZ_VIOLA_STAGE_EXEC_CLAIM,
	YZ_VIOLA_STAGE_SESSION,
	YZ_VIOLA_STAGE_PAYLOAD,
	YZ_VIOLA_STAGE_TIMEOUT,
};

struct yz_viola_status {
	__u32 size;
	__u32 version;
	__u32 profile;
	__u32 catalog_ready;
	__u32 daemon64;
	__u32 daemon32;
	__u32 role;
	__u32 owner_pid;
	__aligned_u64 epoch;
	__aligned_u64 generation;
	__u8 release_id[32];
	__u8 trust_id[32];
	__s32 last_error;
	__u32 failed_role;
	__u32 failed_stage;
	__u32 compat_required;
	__u32 compat_recovering;
	__s32 recovery_error;
	__u32 reserved;
};

struct yz_viola_catalog_cmd {
	__u32 size;
	__u32 version;
	__aligned_u64 manifest;
	__aligned_u64 signature;
	__u32 manifest_size;
	__u32 signature_size;
};

struct yz_viola_exec_cmd {
	__u32 size;
	__u32 version;
	__s32 image_fd;
	__u32 reserved;
};

struct yz_viola_delegate_cmd {
	__u32 size;
	__u32 version;
	__u32 child_pid;
	__s32 viola_fd;
	__s32 control_fd; /* Returned FD: usable only by the registered child. */
	__u32 reserved;
};

struct yz_viola_recover_cmd {
	__u32 size;
	__u32 version;
	__aligned_u64 epoch;
	__aligned_u64 generation;
	__s32 result;
	__u32 reserved;
};

#define YZ_IOCTL_VIOLA_STATUS _IOWR('Y', 71, struct yz_viola_status)
#define YZ_IOCTL_VIOLA_CATALOG _IOW('Y', 72, struct yz_viola_catalog_cmd)
#define YZ_IOCTL_VIOLA_PIN_EXEC _IOW('Y', 73, struct yz_viola_exec_cmd)
#define YZ_IOCTL_VIOLA_ARM_EXEC _IO('Y', 74)
#define YZ_IOCTL_VIOLA_CLAIM _IO('Y', 75)
#define YZ_IOCTL_VIOLA_DELEGATE _IOWR('Y', 76, struct yz_viola_delegate_cmd)
#define YZ_IOCTL_VIOLA_COMPAT_READY _IO('Y', 77)
#define YZ_IOCTL_VIOLA_RECOVER_COMPAT _IOW('Y', 78, struct yz_viola_recover_cmd)
#define YZ_IOCTL_VIOLA_TAKE_RECOVERY _IO('Y', 79)
#define YZ_IOCTL_VIOLA_FINISH_RECOVERY _IOW('Y', 80, struct yz_viola_recover_cmd)

#endif
