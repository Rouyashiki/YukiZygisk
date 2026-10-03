/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Kernel build adapter for the unmodified Monocypher core.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
/* The included source retains its original BSD-2-Clause / CC0 licensing. */
#include <viola_port.h>
/* Vendor-local shorthand types must not redeclare Linux's u8/u32/u64
 * typedefs when older kernel targets compile as GNU C89. */
#define u8 viola_mono_u8
#define u32 viola_mono_u32
#define u64 viola_mono_u64
#include "../../shared/viola/vendor/monocypher.c"
