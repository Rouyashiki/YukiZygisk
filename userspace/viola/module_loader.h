/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Authenticated kernel image loading adapter.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */
#ifndef YUKIZYGISK_VIOLA_MODULE_LOADER_H
#define YUKIZYGISK_VIOLA_MODULE_LOADER_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef long (*viola_module_syscall)(long, unsigned long, unsigned long,
                                    unsigned long);

/* Caller verifies the complete private image and makes it read-only first.
 * No package pathname is accepted. Compatibility changes affect only copies
 * of these authenticated bytes, never the signed package on disk. */
int viola_load_verified_kernel(const void *image, size_t size,
                               const char *parameters,
                               viola_module_syscall admission);

#ifdef __cplusplus
}
#endif
#endif
