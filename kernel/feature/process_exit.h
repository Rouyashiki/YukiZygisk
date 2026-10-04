/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Process exit monitoring.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef YZ_PROCESS_EXIT_H
#define YZ_PROCESS_EXIT_H
#include <linux/types.h>
int yz_process_exit_enable(void);
void yz_process_exit_disable(void);
void yz_process_exit_schedule(void);
bool yz_process_exit_active(void);
#endif
