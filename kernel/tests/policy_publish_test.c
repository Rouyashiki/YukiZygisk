/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

typedef uint16_t u16;
typedef uint32_t u32;
#define U16_MAX UINT16_MAX
#define YZ_LEGACY_INDIRECT_CALL __attribute__((noinline))
#define pr_debug(...) ((void)0)
#define pr_warn_ratelimited(...) (++warnings)
#define WRITE_ONCE(v, n) ((v) = (n))
#define smp_store_release(p, n) (*(p) = (n))

struct test_mutex {
	pthread_mutex_t native;
	/* A failed ownership check may read another thread's token. */
	_Atomic(char *) owner;
};
#define TEST_MUTEX_INITIALIZER { .native = PTHREAD_MUTEX_INITIALIZER }
static _Thread_local char thread_token;

static void mutex_lock(struct test_mutex *lock)
{
	assert(!pthread_mutex_lock(&lock->native));
	atomic_store(&lock->owner, &thread_token);
}

static void lockdep_assert_held(const struct test_mutex *lock)
{
	assert(atomic_load(&lock->owner) == &thread_token);
}

static void mutex_unlock(struct test_mutex *lock)
{
	lockdep_assert_held(lock);
	atomic_store(&lock->owner, NULL);
	assert(!pthread_mutex_unlock(&lock->native));
}

struct yz_policy_key {
	u32 src_type, tgt_type;
	u16 tclass;
};
struct policydb {
	struct {
		u32 nel;
	} te_avtab;
	struct {
		u32 nprim;
	} p_types;
	u32 allowed;
};
struct selinux_policy {
	struct policydb policydb;
	u32 latest_granting;
};
enum yz_policy_edit_scope { YZ_POLICY_AVTAB };
struct yz_policy_edit {
	struct selinux_policy *old_policy, *policy;
	enum yz_policy_edit_scope scope;
};
static struct selinux_policy policies[2], *candidate, *yz_sized_policy;
static struct {
	struct selinux_policy *policy;
	struct test_mutex policy_mutex;
} state = {.policy = &policies[0], .policy_mutex = TEST_MUTEX_INITIALIZER};
#define yz_selinux_state (&state)
static struct test_mutex yz_policy_lock = TEST_MUTEX_INITIALIZER;
static struct test_mutex yz_fixed_lock = TEST_MUTEX_INITIALIZER;
static bool yz_fixed_latched, yz_unregister_policy_notifier = true;
static struct {
	int enabled;
} yz_fixed_config;
static struct {
	int error, requested, initialized;
} yz_fixed_status;
static u32 yz_sized_seqno, yz_sized_nel, yz_sized_types;
static int selections, advances, publications, warnings, phase, clone_error;
static bool metadata_matches = true;
static const struct yz_policy_key key = {1, 2, 3}, bad_key = {0};

static int yz_fixed_read_config(void)
{
	return 0;
}
static void yz_host_policy_select_temporary(void)
{
	++selections;
}
static bool yz_policy_base_ready(void)
{
	return true;
}

static int yz_policy_begin_edit_locked(struct yz_policy_edit *edit, enum yz_policy_edit_scope scope)
{
	if (clone_error)
		return clone_error;
	candidate = state.policy == &policies[0] ? &policies[1] : &policies[0];
	*candidate = *state.policy;
	*edit = (struct yz_policy_edit){state.policy, candidate, scope};
	return 0;
}

static void yz_policy_cancel_edit_locked(struct yz_policy_edit *edit)
{
	assert(phase == 0 && state.policy == edit->old_policy);
	candidate = NULL;
}

static int yz_policy_apply_av(struct policydb *db, const struct yz_policy_key *k, u32 av, bool add)
{
	if (k == &bad_key)
		return -EINVAL;
	db->allowed = add ? db->allowed | av : db->allowed & ~av;
	return 0;
}

static u32 yz_policy_base_direct_allowed_av(const struct yz_policy_key *k)
{
	return state.policy->policydb.allowed;
}

static bool host_advance(struct policydb *new_db, struct policydb *old_db, u32 old_gen, u32 new_gen)
{
	lockdep_assert_held(&state.policy_mutex);
	assert(phase == 0 && old_db == &state.policy->policydb && new_db == &candidate->policydb);
	assert(old_gen == state.policy->latest_granting && new_gen == old_gen + 1 &&
	       new_gen == candidate->latest_granting);
	++advances;
	phase = 1;
	return metadata_matches;
}

static typeof(&host_advance) advance_types;
static void publish(struct selinux_policy **slot, struct selinux_policy *new)
{
	lockdep_assert_held(&state.policy_mutex);
	assert(phase == !!advance_types && *slot != new && new == candidate);
	*slot = new;
	++publications;
	phase = 2;
}
#define rcu_assign_pointer(slot, new) publish(&(slot), new)
static void synchronize_rcu(void)
{
	assert(phase == 2);
	phase = 3;
}
static void yz_policy_destroy(struct selinux_policy *old, enum yz_policy_edit_scope scope)
{
	assert(phase == 3 && old != state.policy && scope == YZ_POLICY_AVTAB);
	phase = 4;
}
static void yz_policy_reset_avc(u32 gen)
{
	assert(phase == 4 && gen == state.policy->latest_granting);
	phase = 0;
}

#include "production.inc"

static void grant(void)
{
	u32 lease, commit;
	assert(!yz_policy_base_lock());
	assert(!yz_policy_temp_plan_allow_locked(&key, 3, &lease, &commit) && lease == 2);
	assert(!yz_policy_base_commit_allow_locked(&key, commit, NULL, 0, NULL, 0, NULL, 0));
	yz_policy_temp_add_locked(&key, lease);
	yz_policy_base_unlock();
}

static void release(void)
{
	u32 clear;
	assert(!yz_policy_base_lock());
	assert(!yz_policy_temp_plan_release_locked(&key, 2, 1, &clear));
	assert(!yz_policy_base_commit_restore_locked(&key, clear, NULL, 0, NULL, 0, NULL, 0));
	yz_policy_temp_release_locked(&key, 2, 1);
	yz_policy_base_unlock();
}

/* A second policy writer only takes SELinux's mutex. */
static void *host_writer(void *unused)
{
	for (int i = 0; i < 100; i++) {
		struct selinux_policy *old, *new;
		mutex_lock(&state.policy_mutex);
		old = state.policy;
		new = old == &policies[0] ? &policies[1] : &policies[0];
		*new = *old;
		new->latest_granting++;
		state.policy = new;
		mutex_unlock(&state.policy_mutex);
	}
	return NULL;
}

int main(void)
{
	pthread_t writer;
	yz_fixed_config.enabled = 1;
	assert(!yz_fixed_policy_latch() && !selections);
	yz_fixed_latched = false;
	yz_fixed_config.enabled = 0;
	assert(!yz_fixed_policy_latch() && !yz_fixed_policy_latch() && selections == 1);

	assert(!yz_policy_base_lock());
	state.policy->policydb.allowed = 1;
	advance_types = host_advance;
	clone_error = -ENOMEM;
	assert(yz_policy_base_commit_allow_locked(&key, 2, NULL, 0, NULL, 0, NULL, 0) == -ENOMEM);
	clone_error = 0;
	assert(yz_policy_base_commit_allow_locked(&key, 2, &bad_key, 4, NULL, 0, NULL, 0) ==
	       -EINVAL);
	assert(!advances && !publications && state.policy->policydb.allowed == 1);
	yz_policy_base_unlock();

	grant();
	grant();
	release();
	assert(advances == 1 && publications == 1 && state.policy->policydb.allowed == 3);
	metadata_matches = false;
	release();
	assert(advances == 2 && publications == 2 && warnings == 1 &&
	       state.policy->policydb.allowed == 1);
	advance_types = NULL;
	grant();
	release();
	assert(advances == 2 && publications == 4 && warnings == 1);

	advance_types = host_advance;
	metadata_matches = true;
	assert(!pthread_create(&writer, NULL, host_writer, NULL));
	for (int i = 0; i < 100; i++) {
		grant();
		release();
	}
	assert(!pthread_join(writer, NULL));
	assert(advances == 202 && publications == 204 && warnings == 1);
	assert(state.policy->latest_granting == 304 && state.policy->policydb.allowed == 1);
	return 0;
}
