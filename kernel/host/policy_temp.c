/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Temporary SELinux allowances for native injection.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/string.h>

#include "host/policy.h"
#include "host/policy_base.h"
#include "host/policy_temp.h"

#define YZ_POLICY_TEMP_RULE_MAX 64
#define YZ_POLICY_PERM_BITS 32
#define YZ_POLICY_TYPE_NAME_MAX 64

struct yz_policy_temp_rule {
	bool used;
	struct yz_policy_key key;
	u16 refs[YZ_POLICY_PERM_BITS];
};

static struct yz_policy_temp_rule
	yz_policy_temp_rules[YZ_POLICY_TEMP_RULE_MAX];

void yz_policy_temp_reset(void)
{
	int ret;

	ret = yz_policy_base_lock();
	if (ret) {
		memset(yz_policy_temp_rules, 0, sizeof(yz_policy_temp_rules));
		return;
	}

	memset(yz_policy_temp_rules, 0, sizeof(yz_policy_temp_rules));
	yz_policy_base_unlock();
}

static bool yz_policy_temp_key_eq(const struct yz_policy_key *a,
				  const struct yz_policy_key *b)
{
	return a->src_type == b->src_type && a->tgt_type == b->tgt_type &&
	       a->tclass == b->tclass;
}

static struct yz_policy_temp_rule *
yz_policy_temp_find_locked(const struct yz_policy_key *key)
{
	int i;

	for (i = 0; i < YZ_POLICY_TEMP_RULE_MAX; i++) {
		if (yz_policy_temp_rules[i].used &&
		    yz_policy_temp_key_eq(&yz_policy_temp_rules[i].key, key))
			return &yz_policy_temp_rules[i];
	}

	return NULL;
}

static struct yz_policy_temp_rule *yz_policy_temp_find_free_locked(void)
{
	int i;

	for (i = 0; i < YZ_POLICY_TEMP_RULE_MAX; i++) {
		if (!yz_policy_temp_rules[i].used)
			return &yz_policy_temp_rules[i];
	}

	return NULL;
}

static u32 yz_policy_temp_mask_locked(const struct yz_policy_key *key)
{
	struct yz_policy_temp_rule *rule;
	u32 mask = 0;
	int i;

	rule = yz_policy_temp_find_locked(key);
	if (!rule)
		return 0;

	for (i = 0; i < YZ_POLICY_PERM_BITS; i++) {
		if (rule->refs[i])
			mask |= 1U << i;
	}

	return mask;
}

static int yz_policy_temp_validate_add_locked(const struct yz_policy_key *key,
					      u32 av)
{
	struct yz_policy_temp_rule *rule;
	int i;

	if (!av)
		return 0;

	rule = yz_policy_temp_find_locked(key);
	if (!rule && !yz_policy_temp_find_free_locked())
		return -ENOSPC;

	if (rule) {
		for (i = 0; i < YZ_POLICY_PERM_BITS; i++) {
			if ((av & (1U << i)) && rule->refs[i] == U16_MAX)
				return -EOVERFLOW;
		}
	}

	return 0;
}

static void yz_policy_temp_add_locked(const struct yz_policy_key *key, u32 av)
{
	struct yz_policy_temp_rule *rule;
	int i;

	if (!av)
		return;

	rule = yz_policy_temp_find_locked(key);
	if (!rule) {
		rule = yz_policy_temp_find_free_locked();
		if (!rule)
			return;
		memset(rule, 0, sizeof(*rule));
		rule->used = true;
		rule->key = *key;
	}

	for (i = 0; i < YZ_POLICY_PERM_BITS; i++) {
		if (av & (1U << i))
			rule->refs[i]++;
	}
}

static int yz_policy_temp_plan_release_locked(const struct yz_policy_key *key,
					      u32 av, u32 refs, u32 *clear_av)
{
	struct yz_policy_temp_rule *rule;
	int i;

	*clear_av = 0;
	if (!av)
		return refs ? -EINVAL : 0;
	rule = yz_policy_temp_find_locked(key);
	if (!rule || !refs)
		return -EINVAL;
	for (i = 0; i < YZ_POLICY_PERM_BITS; i++) {
		if (!(av & (1U << i)))
			continue;
		if (refs > rule->refs[i])
			return -EINVAL;
		if (refs == rule->refs[i])
			*clear_av |= 1U << i;
	}
	return 0;
}

static void yz_policy_temp_release_locked(const struct yz_policy_key *key,
					  u32 av, u32 refs)
{
	struct yz_policy_temp_rule *rule;
	bool any = false;
	int i;

	if (!av)
		return;

	rule = yz_policy_temp_find_locked(key);
	if (!rule)
		return;

	for (i = 0; i < YZ_POLICY_PERM_BITS; i++) {
		if (!(av & (1U << i)))
			continue;
		if (rule->refs[i] >= refs)
			rule->refs[i] -= refs;
	}

	for (i = 0; i < YZ_POLICY_PERM_BITS; i++) {
		if (rule->refs[i]) {
			any = true;
			break;
		}
	}
	if (!any)
		memset(rule, 0, sizeof(*rule));
}

static int yz_policy_temp_plan_allow_locked(const struct yz_policy_key *key,
					    u32 required_av, u32 *state_av,
					    u32 *commit_av)
{
	u32 direct_av;
	u32 owned_av;
	u32 request_av;
	int ret;

	if (state_av)
		*state_av = 0;
	if (commit_av)
		*commit_av = 0;
	/* An overlapping file/tmpfs key is acquired through the tmpfs role. */
	if (!required_av)
		return 0;

	direct_av = yz_policy_base_direct_allowed_av(key);
	owned_av = yz_policy_temp_mask_locked(key);
	request_av = required_av & (~direct_av | owned_av);
	if (!request_av)
		return 0;

	ret = yz_policy_temp_validate_add_locked(key, request_av);
	if (ret)
		return ret;

	if (state_av)
		*state_av = request_av;
	if (commit_av)
		*commit_av = request_av & ~owned_av;
	return 0;
}

static int yz_policy_temp_validate_batch_locked(
    const struct yz_policy_file_load_keys *keys,
    const struct yz_file_load_policy *state)
{
	const struct yz_policy_key *candidates[] = {
	    &keys->file,
	    &keys->dir,
	    &keys->tmpfs,
	};
	u32 allowances[] = {
	    state->added_av,
	    state->dir_added_av,
	    state->tmpfs_added_av,
	};
	unsigned int needed = 0, available = 0;
	unsigned int i, j;

	/* Individual validation sees the same free slot for each new key.
	 * Reserve capacity for the whole grant before changing policy. */
	for (i = 0; i < ARRAY_SIZE(candidates); i++) {
		if (!allowances[i] || yz_policy_temp_find_locked(candidates[i]))
			continue;
		for (j = 0; j < i; j++)
			if (allowances[j] &&
			    yz_policy_temp_key_eq(candidates[i], candidates[j]))
				break;
		if (j == i)
			needed++;
	}
	for (i = 0; i < YZ_POLICY_TEMP_RULE_MAX; i++)
		if (!yz_policy_temp_rules[i].used)
			available++;
	return needed <= available ? 0 : -ENOSPC;
}

static int yz_host_policy_allow_file(struct file *file, const struct cred *cred,
				     bool include_dir,
				     enum yz_policy_tmpfs_access tmpfs_access,
				     struct yz_file_load_policy *state)
{
	struct yz_policy_file_load_keys keys = {};
	u32 file_commit_av = 0;
	u32 dir_commit_av = 0;
	u32 tmpfs_commit_av = 0;
	char src_name[YZ_POLICY_TYPE_NAME_MAX];
	char tgt_name[YZ_POLICY_TYPE_NAME_MAX];
	int ret;

	if (!file || !cred || !state)
		return -EINVAL;
	memset(state, 0, sizeof(*state));

	ret = yz_policy_base_lock();
	if (ret)
		return ret;

	ret = yz_policy_base_get_file_load_keys(
		file, cred, include_dir, tmpfs_access, &keys, src_name,
		sizeof(src_name), tgt_name, sizeof(tgt_name));
	if (ret)
		goto out_unlock;

	ret = yz_policy_temp_plan_allow_locked(&keys.file,
					       keys.file_required_av,
					       &state->added_av,
					       &file_commit_av);
	if (ret)
		goto out_unlock;

	if (keys.dir_required_av) {
		ret = yz_policy_temp_plan_allow_locked(
			&keys.dir, keys.dir_required_av, &state->dir_added_av,
			&dir_commit_av);
		if (ret)
			goto out_clear_state;
	}

	if (keys.tmpfs_required_av) {
		ret = yz_policy_temp_plan_allow_locked(
			&keys.tmpfs, keys.tmpfs_required_av,
			&state->tmpfs_added_av, &tmpfs_commit_av);
		if (ret)
			goto out_clear_state;
	}

	state->src_type = keys.file.src_type;
	state->tgt_type = keys.file.tgt_type;
	state->tmpfs_type = keys.tmpfs.tgt_type;
	state->target_class = keys.file.tclass;
	state->dir_class = keys.dir.tclass;
	ret = yz_policy_temp_validate_batch_locked(&keys, state);
	if (ret)
		goto out_clear_state;

	ret = yz_policy_base_commit_allow_locked(
		&keys.file, file_commit_av, &keys.dir, dir_commit_av,
		&keys.tmpfs, tmpfs_commit_av, NULL, 0);
	if (ret)
		goto out_clear_state;

	state->file_lease_refs = state->added_av ? 1 : 0;
	state->dir_lease_refs = state->dir_added_av ? 1 : 0;
	state->tmpfs_lease_refs = state->tmpfs_added_av ? 1 : 0;
	yz_policy_temp_add_locked(&keys.file, state->added_av);
	yz_policy_temp_add_locked(&keys.dir, state->dir_added_av);
	yz_policy_temp_add_locked(&keys.tmpfs, state->tmpfs_added_av);

	if (state->added_av || state->dir_added_av ||
	    state->tmpfs_added_av)
		pr_info("yukizygisk: policy allow src=%s tgt=%s file=0x%x dir=0x%x tmpfs=0x%x\n",
			src_name, tgt_name, state->added_av,
			state->dir_added_av,
			state->tmpfs_added_av);
	goto out_unlock;

out_clear_state:
	memset(state, 0, sizeof(*state));

out_unlock:
	yz_policy_base_unlock();
	return ret;
}

int yz_host_policy_allow_file_current(struct file *file,
				      struct yz_file_load_policy *state)
{
	return yz_host_policy_allow_file(file, current_cred(), false,
					 YZ_POLICY_TMPFS_LOAD, state);
}

int yz_host_policy_allow_file_cred(struct file *file, const struct cred *cred,
				   struct yz_file_load_policy *state)
{
	if (file && !S_ISDIR(file_inode(file)->i_mode))
		return yz_host_policy_allow_file(file, cred, false,
						 YZ_POLICY_FILE_RECEIVE, state);
	return yz_host_policy_allow_file(file, cred, true,
					 YZ_POLICY_TMPFS_RECEIVE, state);
}

static int
yz_host_policy_allow_execmem(const struct cred *cred,
			     struct yz_file_load_policy *state)
{
	struct yz_policy_key key = {};
	u32 required_av = 0;
	u32 commit_av = 0;
	char src_name[YZ_POLICY_TYPE_NAME_MAX];
	int ret;

	if (!cred || !state)
		return -EINVAL;

	ret = yz_policy_base_lock();
	if (ret)
		return ret;

	ret = yz_policy_base_get_execmem_key(cred, &key, &required_av,
					     src_name, sizeof(src_name));
	if (ret)
		goto out_unlock;
	if ((state->src_type && state->src_type != key.src_type) ||
	    (state->process_added_av &&
	     (state->process_type != key.src_type ||
	      state->process_class != key.tclass))) {
		ret = -EINVAL;
		goto out_unlock;
	}
	if (state->process_added_av)
		goto out_unlock;

	ret = yz_policy_temp_plan_allow_locked(&key, required_av,
					       &state->process_added_av,
					       &commit_av);
	if (ret)
		goto out_unlock;

	state->process_type = key.src_type;
	state->process_class = key.tclass;

	ret = yz_policy_base_commit_allow_locked(NULL, 0, NULL, 0, NULL, 0,
						 &key, commit_av);
	if (ret) {
		state->process_type = 0;
		state->process_class = 0;
		state->process_added_av = 0;
		goto out_unlock;
	}

	state->process_lease_refs = state->process_added_av ? 1 : 0;
	yz_policy_temp_add_locked(&key, state->process_added_av);

	if (state->process_added_av)
		pr_info("yukizygisk: policy allow src=%s process=0x%x\n",
			src_name, state->process_added_av);

out_unlock:
	yz_policy_base_unlock();
	return ret;
}

int yz_host_policy_allow_execmem_current(struct yz_file_load_policy *state)
{
	return yz_host_policy_allow_execmem(current_cred(), state);
}

int yz_host_policy_allow_execmem_cred(const struct cred *cred,
				      struct yz_file_load_policy *state)
{
	return yz_host_policy_allow_execmem(cred, state);
}

int yz_host_policy_restore(const struct yz_file_load_policy *state)
{
	struct yz_policy_key file_key = {};
	struct yz_policy_key dir_key = {};
	struct yz_policy_key tmpfs_key = {};
	struct yz_policy_key process_key = {};
	u32 file_clear_av = 0;
	u32 dir_clear_av = 0;
	u32 tmpfs_clear_av = 0;
	u32 process_clear_av = 0;
	int ret;

	if (!state)
		return 0;
	if (!!state->added_av != !!state->file_lease_refs ||
	    !!state->dir_added_av != !!state->dir_lease_refs ||
	    !!state->tmpfs_added_av != !!state->tmpfs_lease_refs ||
	    !!state->process_added_av != !!state->process_lease_refs)
		return -EINVAL;
	if (!state->added_av && !state->tmpfs_added_av &&
	    !state->process_added_av && !state->dir_added_av)
		return 0;

	file_key.src_type = state->src_type;
	file_key.tgt_type = state->tgt_type;
	file_key.tclass = state->target_class;
	dir_key.src_type = state->src_type;
	dir_key.tgt_type = state->tgt_type;
	dir_key.tclass = state->dir_class;
	tmpfs_key.src_type = state->src_type;
	tmpfs_key.tgt_type = state->tmpfs_type;
	tmpfs_key.tclass = state->target_class;
	process_key.src_type = state->process_type;
	process_key.tgt_type = state->process_type;
	process_key.tclass = state->process_class;

	ret = yz_policy_base_lock();
	if (ret)
		return ret;

	ret = yz_policy_temp_plan_release_locked(
	    &file_key, state->added_av, state->file_lease_refs, &file_clear_av);
	if (ret)
		goto out_unlock;
	ret = yz_policy_temp_plan_release_locked(&dir_key, state->dir_added_av,
						 state->dir_lease_refs,
						 &dir_clear_av);
	if (ret)
		goto out_unlock;
	ret = yz_policy_temp_plan_release_locked(
	    &tmpfs_key, state->tmpfs_added_av, state->tmpfs_lease_refs,
	    &tmpfs_clear_av);
	if (ret)
		goto out_unlock;
	ret = yz_policy_temp_plan_release_locked(
	    &process_key, state->process_added_av, state->process_lease_refs,
	    &process_clear_av);
	if (ret)
		goto out_unlock;

	ret = yz_policy_base_commit_restore_locked(
		&file_key, file_clear_av, &dir_key, dir_clear_av, &tmpfs_key,
		tmpfs_clear_av, &process_key, process_clear_av);
	if (!ret) {
		yz_policy_temp_release_locked(&file_key, state->added_av,
					      state->file_lease_refs);
		yz_policy_temp_release_locked(&dir_key, state->dir_added_av,
					      state->dir_lease_refs);
		yz_policy_temp_release_locked(&tmpfs_key, state->tmpfs_added_av,
					      state->tmpfs_lease_refs);
		yz_policy_temp_release_locked(&process_key,
					      state->process_added_av,
					      state->process_lease_refs);
		pr_info("yukizygisk: policy restore file=0x%x dir=0x%x tmpfs=0x%x process=0x%x\n",
			file_clear_av, dir_clear_av, tmpfs_clear_av,
			process_clear_av);
	}

out_unlock:
	yz_policy_base_unlock();
	return ret;
}
