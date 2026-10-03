/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Kernel build adapter for Monocypher's optional Ed25519.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
/* The included source retains its original BSD-2-Clause / CC0 licensing. */
#include <viola_port.h>
#define u8 viola_ed_u8
#define u64 viola_ed_u64
#include "../../shared/viola/vendor/monocypher-ed25519.c"
