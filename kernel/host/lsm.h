/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * YukiZygisk - Versioned LSM hook adapter declarations.
 *
 * Derived from KernelSU hook/lsm_hook.h.
 *
 * License: GPL-2.0-only
 *
 * Author: KernelSU contributors and Anatdx
 */
#ifndef _YUKIZYGISK_HOST_LSM_H
#define _YUKIZYGISK_HOST_LSM_H

#include <linux/lsm_hooks.h>
#include <linux/stddef.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#define YZ_LSM_HOOK_HEADS_TYPE struct lsm_static_calls_table
#else
#define YZ_LSM_HOOK_HEADS_TYPE struct security_hook_heads
#endif

struct yz_host_lsm_hook {
	const char *head_name;
	const char *target_name;
	size_t head_offset;
	size_t hook_offset;
	void *replacement;
	void *original;
	struct security_hook_list *entry;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	struct lsm_static_call *scall;
#endif
	int offset;
};

#define YZ_HOST_LSM_HOOK_INIT(member, target_symbol, replacement_fn, off)      \
	{                                                                      \
		.head_name = #member,                                          \
		.target_name = target_symbol,                                  \
		.head_offset = offsetof(YZ_LSM_HOOK_HEADS_TYPE, member),       \
		.hook_offset = offsetof(struct security_hook_list,             \
					hook.member),                          \
		.replacement = (void *)(replacement_fn),                       \
		.offset = off,                                                 \
	}

int yz_host_lsm_enter(void);
void yz_host_lsm_leave(int index);
void yz_host_lsm_init(void);
void yz_host_lsm_exit(void);
int yz_host_register_lsm_hook(struct yz_host_lsm_hook *hook);
void yz_host_unregister_lsm_hook(struct yz_host_lsm_hook *hook);

#endif /* _YUKIZYGISK_HOST_LSM_H */
