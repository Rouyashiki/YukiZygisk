/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Zygote exit diagnostics.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef YZ_ZYGOTE_EXIT_H
#define YZ_ZYGOTE_EXIT_H
#include <linux/types.h>
int yz_zygote_exit_enable(void);
void yz_zygote_exit_disable(void);
void yz_zygote_exit_track(u32 pid, u64 start, u32 generation, u8 abi);
#endif
