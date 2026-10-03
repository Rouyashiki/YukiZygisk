/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - One-shot prctl bootstrap declarations.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _YUKIZYGISK_BOOTSTRAP_H
#define _YUKIZYGISK_BOOTSTRAP_H

int yukizygisk_bootstrap_init(void);
void yukizygisk_bootstrap_exit(void);

#endif /* _YUKIZYGISK_BOOTSTRAP_H */
