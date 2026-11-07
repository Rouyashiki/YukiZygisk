/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * YukiZygisk - Kernel text and table patch helper.
 *
 * Derived from KernelSU hook/patch_memory.h and Kasumi patch memory helpers.
 *
 * License: GPL-2.0-only
 *
 * Author: bmax121 and Rouyashiki Developers
 */
#ifndef _YUKIZYGISK_HOST_PATCH_TEXT_H
#define _YUKIZYGISK_HOST_PATCH_TEXT_H

#include <linux/types.h>

#define YZ_PATCH_TEXT_FLUSH_DCACHE 1
#define YZ_PATCH_TEXT_FLUSH_ICACHE 2

int yz_patch_text(void *dst, void *src, size_t len, int flags);

#endif /* _YUKIZYGISK_HOST_PATCH_TEXT_H */
