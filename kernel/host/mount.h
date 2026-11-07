/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * YukiZygisk - Host mount namespace cleanup adapter declarations.
 *
 * Derived from YukiSU kernel_umount helpers.
 *
 * License: GPL-2.0-only
 *
 * Author: Rouyashiki Developers
 */
#ifndef _YUKIZYGISK_HOST_MOUNT_H
#define _YUKIZYGISK_HOST_MOUNT_H

#include <linux/types.h>

int yz_host_umount_pid(pid_t pid);

#endif /* _YUKIZYGISK_HOST_MOUNT_H */
