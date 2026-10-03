/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Temporary native and module load policy ownership.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#include "internal.h"
#include "klog.h"
#include "host/host.h"

#define YZ_NATIVE_POLICY_TIMEOUT (10 * HZ)
#define YZ_MODULE_POLICY_TIMEOUT (10 * HZ)
struct yz_native_policy_pending {
	struct list_head list;
	pid_t tgid;
	struct yz_file_load_policy state;
	struct delayed_work timeout;
	bool pending;
};

static DEFINE_MUTEX(yz_native_policy_lock);
static LIST_HEAD(yz_native_policy_pending);

struct yz_module_policy_holder {
	struct list_head list;
	pid_t tgid;
	struct yz_file_load_policy state;
	struct delayed_work timeout;
	bool pending;
};

static DEFINE_MUTEX(yz_module_policy_lock);
static LIST_HEAD(yz_module_policy_holders);

static int yz_restore_module_policy(pid_t tgid);

static bool
yz_native_policy_has_additions(const struct yz_file_load_policy *state)
{
	return state && (state->added_av || state->tmpfs_added_av ||
			 state->process_added_av || state->dir_added_av);
}

void yz_load_policy_restore_state(struct yz_file_load_policy *state)
{
	if (!yz_native_policy_has_additions(state))
		return;
	yz_host_file_load_policy_restore(state);
	memset(state, 0, sizeof(*state));
}

static void yz_native_policy_timeout(struct work_struct *work)
{
	struct yz_native_policy_pending *entry = container_of(
	    to_delayed_work(work), struct yz_native_policy_pending, timeout);
	bool restore = false;

	mutex_lock(&yz_native_policy_lock);
	if (entry->pending) {
		entry->pending = false;
		list_del_init(&entry->list);
		restore = true;
	}
	mutex_unlock(&yz_native_policy_lock);

	if (!restore)
		return;

	pr_info(
	    "yukizygisk: load_policy: load policy timeout pid=%d added=0x%x "
	    "tmpfs=0x%x process=0x%x\n",
	    entry->tgid, entry->state.added_av, entry->state.tmpfs_added_av,
	    entry->state.process_added_av);
	yz_load_policy_restore_state(&entry->state);
	kfree(entry);
}

void yz_load_policy_publish_native(pid_t tgid,
				   struct yz_file_load_policy *state)
{
	struct yz_native_policy_pending *entry;
	struct yz_native_policy_pending *cur;
	struct yz_native_policy_pending *tmp;
	LIST_HEAD(old_entries);

	if (!yz_native_policy_has_additions(state))
		return;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		pr_info(
		    "yukizygisk: load_policy: load policy pid=%d alloc failed, "
		    "restoring immediately\n",
		    tgid);
		yz_load_policy_restore_state(state);
		return;
	}
	entry->tgid = tgid;
	entry->state = *state;
	entry->pending = true;
	INIT_LIST_HEAD(&entry->list);
	INIT_DELAYED_WORK(&entry->timeout, yz_native_policy_timeout);
	memset(state, 0, sizeof(*state));

	mutex_lock(&yz_native_policy_lock);
	list_for_each_entry_safe (cur, tmp, &yz_native_policy_pending, list) {
		if (cur->tgid != tgid)
			continue;
		cur->pending = false;
		list_move_tail(&cur->list, &old_entries);
	}
	list_add_tail(&entry->list, &yz_native_policy_pending);
	mutex_unlock(&yz_native_policy_lock);

	schedule_delayed_work(&entry->timeout, YZ_NATIVE_POLICY_TIMEOUT);

	list_for_each_entry_safe (cur, tmp, &old_entries, list) {
		cancel_delayed_work_sync(&cur->timeout);
		list_del(&cur->list);
		yz_load_policy_restore_state(&cur->state);
		kfree(cur);
	}
	pr_info(
	    "yukizygisk: load_policy: load policy pid=%d pending added=0x%x "
	    "tmpfs=0x%x process=0x%x\n",
	    tgid, entry->state.added_av, entry->state.tmpfs_added_av,
	    entry->state.process_added_av);
}

int yz_load_policy_restore_native(pid_t tgid)
{
	struct yz_native_policy_pending *entry;
	struct yz_native_policy_pending *tmp;
	LIST_HEAD(todo);
	int n = 0;

	if (tgid <= 0)
		return -EINVAL;

	mutex_lock(&yz_native_policy_lock);
	list_for_each_entry_safe (entry, tmp, &yz_native_policy_pending, list) {
		if (entry->tgid != tgid)
			continue;
		entry->pending = false;
		list_move_tail(&entry->list, &todo);
	}
	mutex_unlock(&yz_native_policy_lock);

	list_for_each_entry_safe (entry, tmp, &todo, list) {
		cancel_delayed_work_sync(&entry->timeout);
		list_del(&entry->list);
		yz_load_policy_restore_state(&entry->state);
		kfree(entry);
		n++;
	}
	pr_info(
	    "yukizygisk: load_policy: load policy restore pid=%d entries=%d\n",
	    tgid, n);
	return yz_restore_module_policy(tgid);
}

static bool yz_module_policy_same(const struct yz_module_policy_holder *holder,
				  pid_t tgid,
				  const struct yz_file_load_policy *state)
{
	return holder->pending && holder->tgid == tgid &&
	       holder->state.src_type == state->src_type &&
	       holder->state.tgt_type == state->tgt_type &&
	       holder->state.target_class == state->target_class &&
	       holder->state.dir_class == state->dir_class;
}

static void yz_module_policy_timeout(struct work_struct *work)
{
	struct yz_module_policy_holder *holder = container_of(
	    to_delayed_work(work), struct yz_module_policy_holder, timeout);
	bool restore = false;

	mutex_lock(&yz_module_policy_lock);
	if (holder->pending) {
		holder->pending = false;
		list_del_init(&holder->list);
		restore = true;
	}
	mutex_unlock(&yz_module_policy_lock);

	if (!restore)
		return;

	pr_info("yukizygisk: load_policy: module policy timeout pid=%d src=%u "
		"tgt=%u\n",
		holder->tgid, holder->state.src_type, holder->state.tgt_type);
	yz_load_policy_restore_state(&holder->state);
	kfree(holder);
}

int yz_load_policy_allow_module(pid_t tgid, struct file *dir,
				const struct cred *cred)
{
	struct yz_module_policy_holder *holder;
	struct yz_module_policy_holder *cur;
	struct yz_file_load_policy state = {};
	int restore_ret;
	int ret;

	if (tgid <= 0 || !dir || !cred)
		return -EINVAL;

	holder = kzalloc(sizeof(*holder), GFP_KERNEL);
	if (!holder)
		return -ENOMEM;

	mutex_lock(&yz_module_policy_lock);
	ret = yz_host_file_load_policy_allow_cred(dir, cred, &state);
	if (ret)
		goto out_unlock;
	if (S_ISDIR(file_inode(dir)->i_mode)) {
		ret = yz_host_file_load_policy_allow_execmem_cred(cred, &state);
		if (ret)
			goto out_restore;
	}
	if (!yz_native_policy_has_additions(&state))
		goto out_unlock;

	list_for_each_entry (cur, &yz_module_policy_holders, list) {
		if (!yz_module_policy_same(cur, tgid, &state))
			continue;
		ret = yz_host_file_load_policy_restore(&state);
		goto out_unlock;
	}

	holder->tgid = tgid;
	holder->state = state;
	holder->pending = true;
	INIT_LIST_HEAD(&holder->list);
	INIT_DELAYED_WORK(&holder->timeout, yz_module_policy_timeout);
	list_add_tail(&holder->list, &yz_module_policy_holders);
	schedule_delayed_work(&holder->timeout, YZ_MODULE_POLICY_TIMEOUT);
	pr_info(
	    "yukizygisk: load_policy: module policy armed pid=%d src=%u tgt=%u "
	    "file=0x%x dir=0x%x process=0x%x\n",
	    tgid, state.src_type, state.tgt_type, state.added_av,
	    state.dir_added_av, state.process_added_av);
	holder = NULL;
	goto out_unlock;

out_restore:
	restore_ret = yz_host_file_load_policy_restore(&state);
	if (restore_ret)
		pr_err("yukizygisk: load_policy: module policy rollback pid=%d "
		       "ret=%d\n",
		       tgid, restore_ret);

out_unlock:
	mutex_unlock(&yz_module_policy_lock);
	kfree(holder);
	return ret;
}

static int yz_restore_module_policy(pid_t tgid)
{
	struct yz_module_policy_holder *holder;
	struct yz_module_policy_holder *tmp;
	LIST_HEAD(todo);
	int first_error = 0;
	int n = 0;

	mutex_lock(&yz_module_policy_lock);
	list_for_each_entry_safe (holder, tmp, &yz_module_policy_holders,
				  list) {
		if (!holder->pending || holder->tgid != tgid)
			continue;
		holder->pending = false;
		list_move_tail(&holder->list, &todo);
	}
	mutex_unlock(&yz_module_policy_lock);

	list_for_each_entry_safe (holder, tmp, &todo, list) {
		int ret;

		cancel_delayed_work_sync(&holder->timeout);
		list_del(&holder->list);
		ret = yz_host_file_load_policy_restore(&holder->state);
		if (ret && !first_error)
			first_error = ret;
		kfree(holder);
		n++;
	}
	if (n)
		pr_info("yukizygisk: load_policy: module policy restore pid=%d "
			"entries=%d "
			"ret=%d\n",
			tgid, n, first_error);
	return first_error;
}

void yz_load_policy_cleanup(void)
{
	struct yz_module_policy_holder *holder;
	struct yz_module_policy_holder *tmp;
	LIST_HEAD(todo);

	mutex_lock(&yz_module_policy_lock);
	list_for_each_entry_safe (holder, tmp, &yz_module_policy_holders,
				  list) {
		holder->pending = false;
		list_move_tail(&holder->list, &todo);
	}
	mutex_unlock(&yz_module_policy_lock);

	list_for_each_entry_safe (holder, tmp, &todo, list) {
		cancel_delayed_work_sync(&holder->timeout);
		list_del(&holder->list);
		yz_load_policy_restore_state(&holder->state);
		kfree(holder);
	}
}
