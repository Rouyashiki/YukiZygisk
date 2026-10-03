/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Generation-bound runtime records and process ABI tracking.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#include <linux/errno.h>
#include <linux/compat.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "internal.h"
#include "klog.h"
#include "zygote_exit.h"

struct yz_runtime_entry {
	struct yz_runtime_record record;
	u64 start_boottime;
};

static DEFINE_MUTEX(yz_runtime_lock);
static struct yz_runtime_entry yz_runtime_records[YZ_RUNTIME_RECORD_MAX];
static u32 yz_runtime_generation;
static bool yz_runtime_next_arg(unsigned long *p, unsigned long end, char *arg,
				size_t arg_len)
{
	char c = '\0';
	int i = 0;

	if (!p || !arg || !arg_len || *p >= end)
		return false;

	while (*p < end && i < (int)arg_len - 1) {
		if (get_user(c, (const char __user *)*p))
			return false;
		(*p)++;
		if (!c)
			break;
		arg[i++] = c;
	}
	arg[i] = '\0';

	/* If the argument was truncated, consume it so the next iteration
	 * starts at the next argv entry. */
	while (*p < end && c) {
		if (get_user(c, (const char __user *)*p))
			return false;
		(*p)++;
	}

	return true;
}

bool yz_runtime_parse_zygote_args(struct mm_struct *mm, char *socket_name,
				  size_t socket_name_len)
{
	unsigned long p, end;
	char arg[96];
	bool found = false;
	int argc = 0;

	if (!mm)
		return false;
	if (socket_name_len)
		socket_name[0] = '\0';
	p = READ_ONCE(mm->arg_start);
	end = READ_ONCE(mm->arg_end);
	if (!p || end <= p)
		return false;

	while (p < end && argc++ < 64) {
		static const char socket_prefix[] = "--socket-name=";

		if (!yz_runtime_next_arg(&p, end, arg, sizeof(arg)))
			return false;
		if (!strcmp(arg, "-Xzygote"))
			found = true;
		else if (!strncmp(arg, socket_prefix,
				  sizeof(socket_prefix) - 1))
			yz_copy_name(socket_name, socket_name_len,
				     arg + sizeof(socket_prefix) - 1);
	}

	if (found && socket_name_len && socket_name[0] == '\0')
		yz_copy_name(socket_name, socket_name_len, "zygote");
	return found;
}

static u32 yz_runtime_next_generation_locked(void)
{
	yz_runtime_generation++;
	if (!yz_runtime_generation)
		yz_runtime_generation++;
	return yz_runtime_generation;
}

static int yz_runtime_get_task_start(u32 pid, u64 *start_boottime)
{
	struct task_struct *task;
	int ret = -ESRCH;

	rcu_read_lock();
	task = get_pid_task(find_vpid((pid_t)pid), PIDTYPE_PID);
	rcu_read_unlock();
	if (!task)
		return ret;

	if (!READ_ONCE(task->exit_state)) {
		*start_boottime = READ_ONCE(task->start_boottime);
		ret = 0;
	}
	put_task_struct(task);
	return ret;
}

static bool yz_runtime_task_alive(u32 pid, u64 start_boottime)
{
	u64 current_start;

	return !yz_runtime_get_task_start(pid, &current_start) &&
	       current_start == start_boottime;
}

static int yz_runtime_find_base_locked(u32 pid, u64 start_boottime, u8 kind,
				       u32 generation)
{
	int i;

	for (i = 0; i < YZ_RUNTIME_RECORD_MAX; i++) {
		const struct yz_runtime_entry *entry = &yz_runtime_records[i];

		if (entry->record.pid == pid &&
		    entry->start_boottime == start_boottime &&
		    entry->record.kind == kind &&
		    entry->record.generation == generation &&
		    !entry->record.module_id[0] &&
		    entry->record.state != YZ_RUNTIME_STATE_EXITED)
			return i;
	}
	return -1;
}

static int yz_runtime_find_native_pid_locked(u32 pid)
{
	int i;

	for (i = 0; i < YZ_RUNTIME_RECORD_MAX; i++) {
		const struct yz_runtime_record *record =
		    &yz_runtime_records[i].record;

		if (record->pid == pid &&
		    record->kind == YZ_RUNTIME_KIND_NATIVE &&
		    !record->module_id[0])
			return i;
	}
	return -1;
}

static int yz_runtime_find_zygote_locked(const char *target, u8 abi)
{
	int i;

	for (i = 0; i < YZ_RUNTIME_RECORD_MAX; i++) {
		const struct yz_runtime_record *record =
		    &yz_runtime_records[i].record;

		if (record->pid && record->kind == YZ_RUNTIME_KIND_ZYGOTE &&
		    record->abi == abi && !record->module_id[0] &&
		    !strcmp(record->target, target))
			return i;
	}
	return -1;
}

static int yz_runtime_find_module_locked(u32 pid, u64 start_boottime, u8 kind,
					 u32 generation, const char *module_id)
{
	int i;

	for (i = 0; i < YZ_RUNTIME_RECORD_MAX; i++) {
		const struct yz_runtime_entry *entry = &yz_runtime_records[i];

		if (entry->record.pid == pid && entry->record.kind == kind &&
		    entry->record.generation == generation &&
		    entry->start_boottime == start_boottime &&
		    !strcmp(entry->record.module_id, module_id))
			return i;
	}
	return -1;
}

static int yz_runtime_pick_slot_locked(int exclude)
{
	int exited = -1;
	int module = -1;
	int i;

	for (i = 0; i < YZ_RUNTIME_RECORD_MAX; i++) {
		const struct yz_runtime_record *record =
		    &yz_runtime_records[i].record;

		if (i == exclude)
			continue;
		if (!record->pid)
			return i;
		if (record->state == YZ_RUNTIME_STATE_EXITED &&
		    (exited < 0 ||
		     record->generation <
			 yz_runtime_records[exited].record.generation))
			exited = i;
		if (record->module_id[0] &&
		    (module < 0 ||
		     record->generation <
			 yz_runtime_records[module].record.generation))
			module = i;
	}
	return exited >= 0 ? exited : module;
}

static void yz_runtime_set_state_locked(struct yz_runtime_entry *entry,
					u8 state)
{
	if (entry->record.state == state)
		return;
	entry->record.state = state;
	yz_runtime_next_generation_locked();
}

static void yz_runtime_refresh_exited_locked(void)
{
	int i;

	for (i = 0; i < YZ_RUNTIME_RECORD_MAX; i++) {
		struct yz_runtime_entry *entry = &yz_runtime_records[i];

		if (!entry->record.pid ||
		    entry->record.state == YZ_RUNTIME_STATE_EXITED)
			continue;
		if (!yz_runtime_task_alive(entry->record.pid,
					   entry->start_boottime))
			yz_runtime_set_state_locked(entry,
						    YZ_RUNTIME_STATE_EXITED);
	}
}

u32 yz_runtime_begin(u8 kind, u8 abi, u8 target_type, u32 flags,
		     const char *process, const char *target)
{
	struct yz_runtime_entry *entry;
	u64 start_boottime = READ_ONCE(current->start_boottime);
	u32 pid = (u32)current->tgid;
	u32 restarts = 0;
	u32 generation = 0;
	bool matched = false;
	int slot;
	int i;

	mutex_lock(&yz_runtime_lock);
	yz_runtime_refresh_exited_locked();
	if (kind == YZ_RUNTIME_KIND_ZYGOTE) {
		slot = yz_runtime_find_zygote_locked(target, abi);
		matched = slot >= 0;
		if (slot < 0)
			slot = yz_runtime_pick_slot_locked(-1);
	} else {
		slot = yz_runtime_find_native_pid_locked(pid);
		for (i = 0; i < YZ_RUNTIME_RECORD_MAX; i++) {
			struct yz_runtime_entry *module =
			    &yz_runtime_records[i];

			if (module->record.pid == pid &&
			    module->record.kind == YZ_RUNTIME_KIND_NATIVE &&
			    module->record.module_id[0])
				yz_runtime_set_state_locked(
				    module, YZ_RUNTIME_STATE_EXITED);
		}
		if (slot < 0)
			slot = yz_runtime_pick_slot_locked(-1);
	}
	if (slot < 0)
		goto out;

	entry = &yz_runtime_records[slot];
	if (kind == YZ_RUNTIME_KIND_ZYGOTE && matched)
		restarts = entry->record.restarts + 1;

	memset(entry, 0, sizeof(*entry));
	entry->record.pid = pid;
	entry->record.generation = yz_runtime_next_generation_locked();
	entry->record.restarts = restarts;
	entry->record.kind = kind;
	entry->record.state = YZ_RUNTIME_STATE_DETECTED;
	entry->record.abi = abi;
	entry->record.target_type = target_type;
	entry->record.flags = flags;
	yz_copy_name(entry->record.process, sizeof(entry->record.process),
		     process);
	yz_copy_name(entry->record.target, sizeof(entry->record.target),
		     target);
	entry->start_boottime = start_boottime;
	generation = entry->record.generation;
	if (kind == YZ_RUNTIME_KIND_ZYGOTE)
		yz_zygote_exit_track(pid, start_boottime, generation, abi);
out:
	mutex_unlock(&yz_runtime_lock);
	return generation;
}

void yz_runtime_set_state(u32 pid, u32 generation, u8 state)
{
	int i;

	if (!generation)
		return;
	mutex_lock(&yz_runtime_lock);
	for (i = 0; i < YZ_RUNTIME_RECORD_MAX; i++) {
		struct yz_runtime_record *record =
		    &yz_runtime_records[i].record;

		if (record->pid != pid || record->generation != generation ||
		    record->module_id[0])
			continue;
		yz_runtime_set_state_locked(&yz_runtime_records[i], state);
		break;
	}
	mutex_unlock(&yz_runtime_lock);
}

void yz_runtime_read_process(struct mm_struct *mm, char *process,
			     size_t process_len)
{
	unsigned long p;
	unsigned long end;

	if (!process_len)
		return;
	process[0] = '\0';
	if (!mm)
		return;
	p = READ_ONCE(mm->arg_start);
	end = READ_ONCE(mm->arg_end);
	if (!p || end <= p)
		return;
	if (!yz_runtime_next_arg(&p, end, process, process_len))
		process[0] = '\0';
}

int yz_runtime_query(struct yz_runtime_record *entries, u32 capacity,
		     struct yz_runtime_query_cmd *query)
{
	u32 count = 0;
	int i;

	if (!query || capacity > YZ_RUNTIME_RECORD_MAX ||
	    (capacity && !entries))
		return -EINVAL;

	mutex_lock(&yz_runtime_lock);
	yz_runtime_refresh_exited_locked();
	for (i = 0; i < YZ_RUNTIME_RECORD_MAX; i++) {
		struct yz_runtime_entry *entry = &yz_runtime_records[i];

		if (!entry->record.pid)
			continue;
		if (count < capacity)
			entries[count++] = entry->record;
	}
	query->count = count;
	query->generation = yz_runtime_generation;
	mutex_unlock(&yz_runtime_lock);

	yz_safemode_fill_runtime_query(query);
	query->capabilities = YZ_RUNTIME_CAP_MODULE_IMAGE_POLICY |
			      YZ_RUNTIME_CAP_ZYGOTE_MODULE_REPORT;
	return 0;
}

int yz_runtime_report(const struct yz_runtime_report_cmd *report)
{
	struct yz_runtime_entry *base;
	struct yz_runtime_entry *module;
	char module_id[YZ_NATIVE_MODULE_ID_MAX];
	u64 start_boottime;
	u8 state;
	int base_slot;
	int module_slot;
	int ret = 0;

	if (!report || !report->pid || !report->generation ||
	    (report->kind != YZ_RUNTIME_KIND_ZYGOTE &&
	     report->kind != YZ_RUNTIME_KIND_NATIVE) ||
	    (report->module_state &&
	     report->module_state != YZ_RUNTIME_STATE_INJECTED &&
	     report->module_state != YZ_RUNTIME_STATE_FAILED &&
	     report->module_state != YZ_RUNTIME_STATE_SAFEMODE) ||
	    (!report->module_id[0] && report->module_state &&
	     report->module_state != YZ_RUNTIME_STATE_INJECTED))
		return -EINVAL;
	state = report->module_state ? report->module_state
				     : YZ_RUNTIME_STATE_INJECTED;
	yz_copy_name(module_id, sizeof(module_id), report->module_id);
	if (report->kind == YZ_RUNTIME_KIND_NATIVE && !module_id[0])
		return -EINVAL;
	if (yz_runtime_get_task_start(report->pid, &start_boottime))
		return -ESRCH;

	mutex_lock(&yz_runtime_lock);
	yz_runtime_refresh_exited_locked();
	base_slot = yz_runtime_find_base_locked(
	    report->pid, start_boottime, report->kind, report->generation);
	if (base_slot < 0) {
		ret = -ESRCH;
		goto out;
	}
	base = &yz_runtime_records[base_slot];
	if (!yz_runtime_task_alive(base->record.pid, base->start_boottime)) {
		yz_runtime_set_state_locked(base, YZ_RUNTIME_STATE_EXITED);
		ret = -ESRCH;
		goto out;
	}
	if (base->record.state != YZ_RUNTIME_STATE_REDIRECTED &&
	    base->record.state != YZ_RUNTIME_STATE_INJECTED) {
		ret = -EAGAIN;
		goto out;
	}
	if ((!module_id[0] || report->kind == YZ_RUNTIME_KIND_NATIVE) &&
	    state == YZ_RUNTIME_STATE_INJECTED)
		yz_runtime_set_state_locked(base, YZ_RUNTIME_STATE_INJECTED);
	if (!module_id[0])
		goto out;

	module_slot = yz_runtime_find_module_locked(
	    report->pid, start_boottime, report->kind, report->generation,
	    module_id);
	if (module_slot < 0)
		module_slot = yz_runtime_pick_slot_locked(base_slot);
	if (module_slot < 0) {
		ret = -ENOSPC;
		goto out;
	}
	module = &yz_runtime_records[module_slot];
	/* Keep a failed child load visible for this Zygote generation. */
	if (report->kind == YZ_RUNTIME_KIND_ZYGOTE &&
	    module->record.generation == base->record.generation &&
	    module->start_boottime == base->start_boottime &&
	    !strcmp(module->record.module_id, module_id) &&
	    (module->record.state == YZ_RUNTIME_STATE_FAILED ||
	     module->record.state == YZ_RUNTIME_STATE_SAFEMODE))
		state = module->record.state;
	if (module->record.generation != base->record.generation ||
	    module->record.state != state ||
	    strcmp(module->record.module_id, module_id) ||
	    module->start_boottime != base->start_boottime) {
		*module = *base;
		yz_copy_name(module->record.module_id,
			     sizeof(module->record.module_id), module_id);
		module->record.state = state;
		yz_runtime_next_generation_locked();
	}
out:
	mutex_unlock(&yz_runtime_lock);
	return ret;
}

bool yz_runtime_is_native(pid_t pid, u64 start_boottime)
{
	bool found = false;
	u32 i;

	mutex_lock(&yz_runtime_lock);
	for (i = 0; i < YZ_RUNTIME_RECORD_MAX; i++) {
		const struct yz_runtime_entry *slot = &yz_runtime_records[i];
		const struct yz_runtime_record *record = &slot->record;

		if (record->pid == (u32)pid &&
		    slot->start_boottime == start_boottime &&
		    record->kind == YZ_RUNTIME_KIND_NATIVE &&
		    !record->module_id[0] &&
		    (record->state == YZ_RUNTIME_STATE_REDIRECTED ||
		     record->state == YZ_RUNTIME_STATE_INJECTED)) {
			found = true;
			break;
		}
	}
	mutex_unlock(&yz_runtime_lock);
	return found;
}

u8 yz_runtime_task_abi(struct task_struct *task)
{
	struct {
		pid_t pid;
		u64 start;
	} lineage[4];
	u32 i, n = 0, level;
	u8 abi = YZ_RUNTIME_ABI_UNKNOWN;

	/* App children inherit a zygote's logical runtime ABI. In particular,
	 * Tango's ARM32 guest must not be classified by its ARM64 host task. */
	rcu_read_lock();
	while (task && n < ARRAY_SIZE(lineage)) {
		lineage[n].pid = task->tgid;
		lineage[n++].start =
		    READ_ONCE(task->group_leader->start_boottime);
		if (task->tgid == 1)
			break;
		task = rcu_dereference(task->real_parent);
	}
	rcu_read_unlock();
	mutex_lock(&yz_runtime_lock);
	for (level = 0; level < n && !abi; level++) {
		u32 newest = 0;

		for (i = 0; i < YZ_RUNTIME_RECORD_MAX; i++) {
			const struct yz_runtime_entry *entry =
			    &yz_runtime_records[i];

			if (entry->record.pid == lineage[level].pid &&
			    !entry->record.module_id[0] &&
			    entry->start_boottime == lineage[level].start &&
			    (!abi ||
			     (s32)(entry->record.generation - newest) > 0)) {
				newest = entry->record.generation;
				abi = entry->record.abi;
			}
		}
	}
	mutex_unlock(&yz_runtime_lock);
	return abi;
}

u8 yz_runtime_abi(pid_t pid)
{
	struct task_struct *task;
	u8 abi;

	rcu_read_lock();
	task = get_pid_task(find_vpid(pid), PIDTYPE_PID);
	rcu_read_unlock();
	if (!task)
		return YZ_RUNTIME_ABI_UNKNOWN;
	abi = yz_runtime_task_abi(task);
	put_task_struct(task);
	return abi;
}

u8 yz_runtime_report_abi(u32 pid, u32 generation)
{
	u32 i;
	u32 newest = 0;
	u8 abi = YZ_RUNTIME_ABI_UNKNOWN;

	mutex_lock(&yz_runtime_lock);
	for (i = 0; i < YZ_RUNTIME_RECORD_MAX; i++) {
		const struct yz_runtime_record *record =
		    &yz_runtime_records[i].record;

		if (record->pid != pid || record->module_id[0])
			continue;
		if (generation && record->generation == generation) {
			abi = record->abi;
			break;
		}
		if (!generation &&
		    (!abi || (s32)(record->generation - newest) > 0)) {
			newest = record->generation;
			abi = record->abi;
		}
	}
	mutex_unlock(&yz_runtime_lock);
	return abi;
}
