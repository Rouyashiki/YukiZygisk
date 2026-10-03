/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Runtime configuration and native target matching.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/mutex.h>
#include <linux/string.h>

#include "internal.h"
#include "klog.h"
#include "tango.h"

/* Dynamic linker symbol offsets, split by userspace ABI. */
static u64 yz_dlopen_off;
static u64 yz_dlsym_off;
static u64 yz_dlopen32_off;
static u64 yz_dlsym32_off;

void yz_config_set_linker_offsets(u64 dlopen_off, u64 dlsym_off)
{
	yz_dlopen_off = dlopen_off;
	yz_dlsym_off = dlsym_off;
	pr_info("yukizygisk: config: dlopen=0x%llx dlsym=0x%llx set\n",
		dlopen_off, dlsym_off);
}

void yz_config_set_compat_linker_offsets(u64 dlopen_off, u64 dlsym_off)
{
	yz_dlopen32_off = dlopen_off;
	yz_dlsym32_off = dlsym_off;
	pr_info("yukizygisk: config: compat dlopen=0x%llx dlsym=0x%llx set\n",
		dlopen_off, dlsym_off);
}

static bool yz_yukilinker_enabled;

static DEFINE_MUTEX(yz_native_targets_lock);
static struct yz_native_target yz_native_targets[YZ_NATIVE_TARGET_MAX];
static u32 yz_native_target_count;

void yz_config_set_first_stage_loader(bool enabled)
{
	yz_yukilinker_enabled = enabled;
	pr_info("yukizygisk: config: yukilinker first-stage = %d\n", enabled);
}

int yz_config_set_native_targets(const struct yz_native_targets_cmd *cmd)
{
	u32 i, n;

	if (!cmd)
		return -EINVAL;

	n = cmd->count;
	if (n > YZ_NATIVE_TARGET_MAX)
		n = YZ_NATIVE_TARGET_MAX;

	mutex_lock(&yz_native_targets_lock);
	yz_native_target_count = 0;
	for (i = 0; i < n; i++) {
		const struct yz_native_target *src = &cmd->targets[i];
		struct yz_native_target *dst =
		    &yz_native_targets[yz_native_target_count];

		if (src->type != YZ_NATIVE_TARGET_NAME &&
		    src->type != YZ_NATIVE_TARGET_PATH)
			continue;
		if (src->value[0] == '\0')
			continue;
		memcpy(dst, src, sizeof(*dst));
		dst->value[YZ_NATIVE_TARGET_VALUE_MAX - 1] = '\0';
		yz_native_target_count++;
	}
	mutex_unlock(&yz_native_targets_lock);

	pr_info("yukizygisk: config: native target count=%u\n",
		yz_native_target_count);
	return 0;
}

const char *yz_basename(const char *path)
{
	const char *base;

	if (!path)
		return NULL;
	base = strrchr(path, '/');
	return base ? base + 1 : path;
}

void yz_copy_name(char *dst, size_t dst_len, const char *src)
{
	size_t i;

	if (!dst_len)
		return;
	for (i = 0; i + 1 < dst_len && src[i]; i++)
		dst[i] = src[i];
	dst[i] = '\0';
}

bool yz_config_match_native_target(const char *filename, char *label,
				   size_t label_len, u8 *target_type)
{
	const char *base = yz_basename(filename);
	bool matched = false;
	u32 i;

	if (target_type)
		*target_type = 0;
	if (!filename || !base)
		return false;

	mutex_lock(&yz_native_targets_lock);
	for (i = 0; i < yz_native_target_count; i++) {
		const struct yz_native_target *t = &yz_native_targets[i];

		if (t->type == YZ_NATIVE_TARGET_NAME) {
			if (strcmp(base, t->value))
				continue;
		} else if (t->type == YZ_NATIVE_TARGET_PATH) {
			if (strcmp(filename, t->value))
				continue;
		} else {
			continue;
		}
		yz_copy_name(label, label_len, t->value);
		if (target_type)
			*target_type = t->type;
		matched = true;
		break;
	}
	mutex_unlock(&yz_native_targets_lock);
	return matched;
}

void yz_tango_linker_offsets(u64 *dlopen, u64 *dlsym)
{
	*dlopen = READ_ONCE(yz_dlopen32_off);
	*dlsym = READ_ONCE(yz_dlsym32_off);
}

void yz_config_fill_linker_offsets(u64 dlopen, u64 dlsym, u64 dlopen32,
				   u64 dlsym32)
{
	if (!yz_dlopen_off)
		yz_dlopen_off = dlopen;
	if (!yz_dlsym_off)
		yz_dlsym_off = dlsym;
	if (!yz_dlopen32_off)
		yz_dlopen32_off = dlopen32;
	if (!yz_dlsym32_off)
		yz_dlsym32_off = dlsym32;
}

u64 yz_config_dlopen_offset(bool compat)
{
	return compat ? yz_dlopen32_off : yz_dlopen_off;
}

u64 yz_config_dlsym_offset(bool compat)
{
	return compat ? yz_dlsym32_off : yz_dlsym_off;
}

bool yz_config_first_stage_loader(void)
{
	return yz_yukilinker_enabled;
}
