/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Portable types for the Viola verifier
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef YUKIZYGISK_VIOLA_PORT_H
#define YUKIZYGISK_VIOLA_PORT_H
#ifdef __KERNEL__
#include <linux/string.h>
#include <linux/types.h>
#else
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#endif
#endif
