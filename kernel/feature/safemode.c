/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Zygote restart guards and safe-mode status.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/string.h>

#include "internal.h"
#include "klog.h"

struct yz_zygote_guard {
	char name[YZ_ZYGOTE_NAME_MAX];
	pid_t last_pid;
	u32 zygote_crashes;
};

#define YZ_ZYGOTE_GUARD_MAX 4
static DEFINE_SPINLOCK(yz_safemode_lock);
static struct yz_zygote_guard yz_zygote_guards[YZ_ZYGOTE_GUARD_MAX];
static bool yz_safemode_active;
static u32 yz_safemode_zygote_crashes;
static char yz_safemode_zygote[YZ_ZYGOTE_NAME_MAX];

bool yz_safemode_is_active(void)
{
	return READ_ONCE(yz_safemode_active);
}

static int yz_zygote_guard_slot_locked(const char *name, int *free_slot)
{
	int i;

	if (free_slot)
		*free_slot = -1;

	for (i = 0; i < YZ_ZYGOTE_GUARD_MAX; i++) {
		if (yz_zygote_guards[i].name[0] == '\0') {
			if (free_slot && *free_slot < 0)
				*free_slot = i;
			continue;
		}
		if (!strcmp(yz_zygote_guards[i].name, name))
			return i;
	}
	return -1;
}

bool yz_safemode_should_skip(const char *name)
{
	unsigned long flags;
	char zygote[YZ_ZYGOTE_NAME_MAX];
	pid_t pid = current->tgid;
	u32 crashes = 0;
	bool activate = false;
	bool skip = false;
	int free_slot;
	int slot;

	yz_copy_name(zygote, sizeof(zygote),
		     (name && name[0]) ? name : "zygote");

	spin_lock_irqsave(&yz_safemode_lock, flags);
	slot = yz_zygote_guard_slot_locked(zygote, &free_slot);
	if (slot < 0 && free_slot >= 0) {
		slot = free_slot;
		yz_copy_name(yz_zygote_guards[slot].name,
			     sizeof(yz_zygote_guards[slot].name), zygote);
	}
	if (yz_safemode_active) {
		if (slot >= 0)
			yz_zygote_guards[slot].last_pid = pid;
		skip = true;
		crashes = yz_safemode_zygote_crashes;
	} else if (slot >= 0) {
		struct yz_zygote_guard *guard = &yz_zygote_guards[slot];

		if (guard->last_pid == 0) {
			guard->last_pid = pid;
		} else if (guard->last_pid != pid) {
			guard->last_pid = pid;
			guard->zygote_crashes++;
			crashes = guard->zygote_crashes;
			if (crashes >= YZ_ZYGOTE_CRASH_THRESHOLD) {
				WRITE_ONCE(yz_safemode_active, true);
				yz_safemode_zygote_crashes = crashes;
				yz_copy_name(yz_safemode_zygote,
					     sizeof(yz_safemode_zygote),
					     zygote);
				activate = true;
				skip = true;
			}
		}
	}
	spin_unlock_irqrestore(&yz_safemode_lock, flags);

	if (activate) {
		pr_warn("yukizygisk: safemode: safemode enabled after %u %s "
			"restart(s); skip pid=%d\n",
			crashes, zygote, pid);
		yz_events_emit_safemode((u32)pid, crashes);
	} else if (skip) {
		pr_info(
		    "yukizygisk: safemode: safemode active, skip zygote pid=%d "
		    "name=%s crashes=%u\n",
		    pid, zygote, crashes);
	}
	return skip;
}

int yz_safemode_get_status(struct yz_safemode_status_cmd *cmd)
{
	unsigned long flags;

	if (!cmd)
		return -EINVAL;

	memset(cmd, 0, sizeof(*cmd));
	spin_lock_irqsave(&yz_safemode_lock, flags);
	cmd->active = yz_safemode_active ? 1 : 0;
	cmd->zygote_crashes = yz_safemode_zygote_crashes;
	yz_copy_name(cmd->zygote, sizeof(cmd->zygote), yz_safemode_zygote);
	spin_unlock_irqrestore(&yz_safemode_lock, flags);
	return 0;
}

int yz_safemode_get_variants(struct yz_zygote_variants_cmd *cmd)
{
	unsigned long flags;
	u32 count = 0;
	int i;

	if (!cmd)
		return -EINVAL;

	memset(cmd, 0, sizeof(*cmd));
	spin_lock_irqsave(&yz_safemode_lock, flags);
	for (i = 0; i < YZ_ZYGOTE_GUARD_MAX && count < YZ_ZYGOTE_VARIANT_MAX;
	     i++) {
		struct yz_zygote_guard *guard = &yz_zygote_guards[i];
		struct yz_zygote_variant *entry;

		if (!guard->name[0] || guard->last_pid <= 0)
			continue;
		entry = &cmd->entries[count++];
		entry->pid = (u32)guard->last_pid;
		entry->crashes = guard->zygote_crashes;
		yz_copy_name(entry->name, sizeof(entry->name), guard->name);
	}
	cmd->count = count;
	spin_unlock_irqrestore(&yz_safemode_lock, flags);
	return 0;
}

void yz_safemode_fill_runtime_query(struct yz_runtime_query_cmd *query)
{
	unsigned long flags;

	spin_lock_irqsave(&yz_safemode_lock, flags);
	query->safe_mode = yz_safemode_active ? 1 : 0;
	query->zygote_crashes = yz_safemode_zygote_crashes;
	yz_copy_name(query->safe_mode_zygote, sizeof(query->safe_mode_zygote),
		     yz_safemode_zygote);
	spin_unlock_irqrestore(&yz_safemode_lock, flags);
}
