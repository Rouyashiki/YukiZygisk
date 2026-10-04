/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Authenticated daemon identity for health and recovery.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef YUKIZYGISK_VIOLA_HEALTH_UAPI_H
#define YUKIZYGISK_VIOLA_HEALTH_UAPI_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define YZ_VIOLA_DAEMON_IDENTITY_VERSION 1U

struct yz_viola_daemon_identity_cmd {
	__u32 size;
	__u32 version;
	__u32 abi;
	__u32 reserved;
	__u32 pid;
	__u32 state;
	__u32 owner_alive;
	__u32 role;
	__aligned_u64 start_boottime_ns;
	__aligned_u64 epoch;
	__aligned_u64 generation;
};

#define YZ_IOCTL_VIOLA_DAEMON_IDENTITY                                         \
	_IOWR('Y', 83, struct yz_viola_daemon_identity_cmd)

#endif
