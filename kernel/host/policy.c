/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * YukiZygisk - SELinux policy control base.
 *
 * Derived from KernelSU/YukiSU SELinux policy helpers.
 *
 * License: GPL-2.0-only
 *
 * Author: KernelSU contributors and Rouyashiki Developers
 */

#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/lsm_hooks.h>
#include <linux/memfd.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/overflow.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#include "objsec.h"
#include "security.h"
#include "ss/avtab.h"
#include "ss/policydb.h"
#include "ss/services.h"
#include "policydb_cleanup.h"
#include "ss/sidtab.h"
#include "ss/symtab.h"
#include "xfrm.h"

#include "feature/fixed_policy.h"
#include <linux/magic.h>
#include "flask.h"
#include "host/host.h"
#include "host/inode.h"
#include "host/policy_base.h"
#include "host/policy.h"
#include "host/policy_ksu.h"
#include "host/policy_temp.h"
#include "host/runtime.h"

#define YZ_POLICY_PERM_BITS 32
/* avtab_write_item(): four 16-bit key fields and a 32-bit access vector. */
#define YZ_POLICY_AVTAB_ALLOWED_SIZE (4 * sizeof(u16) + sizeof(u32))
/* Audited ACK layouts from android12-5.10 through android17-6.18. */
#define YZ_POLICY_AVTAB_KMI (VIOLA_KMI_ID >= 1 && VIOLA_KMI_ID <= 8)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
extern int avc_ss_reset(u32 seqno);
#else
extern int avc_ss_reset(struct selinux_avc *avc, u32 seqno);
#endif

enum yz_policy_edit_scope {
	YZ_POLICY_FULL,
	YZ_POLICY_AVTAB,
};

struct yz_policy_edit {
	struct selinux_policy *old_policy;
	struct selinux_policy *policy;
	enum yz_policy_edit_scope scope;
};

static int yz_policy_begin_edit_locked(struct yz_policy_edit *edit,
				       enum yz_policy_edit_scope scope);
static void
yz_policy_cancel_edit_locked(struct yz_policy_edit *edit);
static void
yz_policy_commit_edit_locked(struct yz_policy_edit *edit);

static DEFINE_MUTEX(yz_policy_lock);
static struct selinux_state *yz_selinux_state;
/* Only our last AV-only publication has a known serialized length. */
static struct selinux_policy *yz_sized_policy;
static u32 yz_sized_seqno;
static u32 yz_sized_nel;
static u32 yz_sized_types;
static typeof(&unregister_blocking_lsm_notifier) yz_unregister_policy_notifier;
static typeof(&security_compute_av_user) yz_fp_compute_fn;
static typeof(&security_context_to_sid) yz_fp_context_fn;
static typeof(&memfd_fcntl) yz_memfd_fcntl;
static struct lsm_blob_sizes *yz_selinux_blob_sizes;
static typeof(&policydb_write) yz_policydb_write;
static typeof(&policydb_read) yz_policydb_read;
static typeof(&policydb_destroy) yz_policydb_destroy;
static typeof(&symtab_search) yz_symtab_search;
static typeof(&avtab_search_node) yz_avtab_search_node;
static typeof(&avtab_insert_nonunique) yz_avtab_insert_nonunique;
static typeof(&avtab_alloc) yz_avtab_alloc;
static typeof(&avtab_destroy) yz_avtab_destroy;
static typeof(&sidtab_search_entry) yz_sidtab_search_entry;
static typeof(&avc_ss_reset) yz_avc_ss_reset;
static typeof(&selnl_notify_policyload) yz_selnl_notify_policyload;
static typeof(&selinux_status_update_policyload)
	yz_selinux_status_update_policyload;

/* These private SELinux functions need not have named old-CFI jump-table
 * entries. Keep each resolved call in its own boundary, including after LTO. */
static YZ_LEGACY_INDIRECT_CALL int
yz_call_policydb_write(struct policydb *db, void *fp)
{
	return yz_policydb_write(db, fp);
}

static YZ_LEGACY_INDIRECT_CALL int
yz_call_policydb_read(struct policydb *db, void *fp)
{
	return yz_policydb_read(db, fp);
}

static YZ_LEGACY_INDIRECT_CALL void
yz_call_policydb_destroy(struct policydb *db)
{
	yz_policydb_destroy(db);
}

static YZ_LEGACY_INDIRECT_CALL void *
yz_call_symtab_search(struct symtab *table, const char *name)
{
	return yz_symtab_search(table, name);
}

static YZ_LEGACY_INDIRECT_CALL struct avtab_node *
yz_call_avtab_search_node(struct avtab *table, struct avtab_key *key)
{
	return yz_avtab_search_node(table, key);
}

static YZ_LEGACY_INDIRECT_CALL struct avtab_node *
yz_call_avtab_insert_nonunique(struct avtab *table, struct avtab_key *key,
			      struct avtab_datum *datum)
{
	return yz_avtab_insert_nonunique(table, key, datum);
}

static YZ_LEGACY_INDIRECT_CALL int
yz_call_avtab_alloc(struct avtab *table, u32 entries)
{
	return yz_avtab_alloc(table, entries);
}

static YZ_LEGACY_INDIRECT_CALL void yz_call_avtab_destroy(struct avtab *table)
{
	yz_avtab_destroy(table);
}

static const char *const yz_file_load_perms[] = {
	"read", "open", "getattr", "map", "execute",
};

static const char *const yz_dir_load_perms[] = {
	"read", "open", "getattr", "search",
};

static const char *const yz_tmpfs_load_perms[] = {
	"read", "open", "getattr", "map", "execute",
};

static const char *const yz_tmpfs_receive_perms[] = {
	"read",
	"open",
	"getattr",
	"map",
};

static const char *const yz_process_execmem_perms[] = {
	"execmem",
};

static const char *const yz_runtime_socket_perms[] = {
	"read", "write", "connectto", "getopt", "getattr",
};

static const char *const yz_runtime_fd_perms[] = {
	"use",
};

static const char *const yz_runtime_fifo_perms[] = {
	"read", "write", "open", "getattr",
};

static const char *const yz_runtime_memfd_perms[] = {
	"execute", "getattr", "map", "read", "write",
};

static const char *const yz_runtime_process_perms[] = {
	"sigchld",
};

struct yz_runtime_policy_class {
	const char *name;
	const char *const *perms;
	size_t perm_count;
	bool optional;
};

static const struct yz_runtime_policy_class yz_runtime_policy_classes[] = {
	{
		.name = "unix_stream_socket",
		.perms = yz_runtime_socket_perms,
		.perm_count = ARRAY_SIZE(yz_runtime_socket_perms),
	},
	{
		.name = "fd",
		.perms = yz_runtime_fd_perms,
		.perm_count = ARRAY_SIZE(yz_runtime_fd_perms),
	},
	{
		.name = "fifo_file",
		.perms = yz_runtime_fifo_perms,
		.perm_count = ARRAY_SIZE(yz_runtime_fifo_perms),
	},
	{
		.name = "memfd_file",
		.perms = yz_runtime_memfd_perms,
		.perm_count = ARRAY_SIZE(yz_runtime_memfd_perms),
		.optional = true,
	},
	{
		.name = "process",
		.perms = yz_runtime_process_perms,
		.perm_count = ARRAY_SIZE(yz_runtime_process_perms),
	},
};

bool yz_policy_base_ready(void)
{
	return yz_selinux_state && yz_selinux_blob_sizes && yz_policydb_write &&
	       yz_policydb_read && yz_policydb_destroy && yz_symtab_search &&
	       yz_avtab_search_node && yz_avtab_insert_nonunique &&
	       yz_avtab_alloc && yz_avtab_destroy && yz_sidtab_search_entry &&
	       yz_avc_ss_reset && yz_selnl_notify_policyload &&
	       yz_selinux_status_update_policyload;
}

static u32 yz_policy_cred_sid(const struct cred *cred)
{
	/* Follow the credential security type in the target SELinux headers. */
	typeof(selinux_cred(cred)) csec;

	if (!cred || !cred->security || !yz_selinux_blob_sizes)
		return 0;
	csec = cred->security + yz_selinux_blob_sizes->lbs_cred;
	return csec->sid;
}

static YZ_LEGACY_INDIRECT_CALL struct context *
yz_policy_sidtab_search(struct sidtab *sidtab, u32 sid)
{
	struct sidtab_entry *entry;

	if (!sidtab || !sid || !yz_sidtab_search_entry)
		return NULL;

	entry = yz_sidtab_search_entry(sidtab, sid);
	return entry ? &entry->context : NULL;
}

static const char *yz_policy_type_name_by_value(struct policydb *db, u32 type)
{
	if (!db || type == 0 || type > db->p_types.nprim)
		return NULL;
	if (!db->sym_val_to_name[SYM_TYPES])
		return NULL;
	return db->sym_val_to_name[SYM_TYPES][type - 1];
}

static const char *yz_policy_class_name_by_value(struct policydb *db,
						 u16 tclass)
{
	if (!db || tclass == 0 || tclass > db->p_classes.nprim)
		return NULL;
	if (!db->sym_val_to_name[SYM_CLASSES])
		return NULL;
	return db->sym_val_to_name[SYM_CLASSES][tclass - 1];
}

static u32
yz_policy_type_value_by_name(struct policydb *db, const char *name)
{
	struct type_datum *type;

	if (!db || !name)
		return 0;
	type = yz_call_symtab_search(&db->p_types, name);
	return type ? type->value : 0;
}

static void yz_policy_copy_type_name(char *dst, size_t dst_size,
				     struct policydb *db, u32 type)
{
	const char *name = yz_policy_type_name_by_value(db, type);

	if (!dst || !dst_size)
		return;
	if (name)
		strscpy(dst, name, dst_size);
	else
		strscpy(dst, "-", dst_size);
}

static u32
yz_policy_perm_mask(struct class_datum *cls, const char *perm_name)
{
	struct perm_datum *perm;

	if (!cls || !perm_name)
		return 0;

	perm = yz_call_symtab_search(&cls->permissions, perm_name);
	if (!perm && cls->comdatum)
		perm = yz_call_symtab_search(&cls->comdatum->permissions, perm_name);
	if (!perm || perm->value == 0 || perm->value > YZ_POLICY_PERM_BITS)
		return 0;

	return 1U << (perm->value - 1);
}

static u32 yz_policy_required_av(struct class_datum *cls,
				 const char *const *perms, size_t count)
{
	u32 av = 0;
	size_t i;

	for (i = 0; i < count; i++)
		av |= yz_policy_perm_mask(cls, perms[i]);

	return av;
}

static u32
yz_policy_direct_allowed_av_locked(struct policydb *db,
				   const struct yz_policy_key *key)
{
	struct avtab_key avkey = {};
	struct avtab_node *node;

	avkey.source_type = key->src_type;
	avkey.target_type = key->tgt_type;
	avkey.target_class = key->tclass;
	avkey.specified = AVTAB_ALLOWED;

	node = yz_call_avtab_search_node(&db->te_avtab, &avkey);
	return node ? node->datum.u.data : 0;
}

u32 yz_policy_base_direct_allowed_av(const struct yz_policy_key *key)
{
	struct selinux_policy *policy;

	if (!key || !yz_policy_base_ready())
		return 0;

	policy = rcu_dereference_protected(
		yz_selinux_state->policy,
		lockdep_is_held(&yz_selinux_state->policy_mutex));
	if (!policy)
		return 0;

	return yz_policy_direct_allowed_av_locked(&policy->policydb, key);
}

static struct avtab_node *
yz_policy_get_avtab_node(struct policydb *db,
			 const struct yz_policy_key *key)
{
	struct avtab_key avkey = {};
	struct avtab_datum datum = {};
	struct avtab_node *node;

	avkey.source_type = key->src_type;
	avkey.target_type = key->tgt_type;
	avkey.target_class = key->tclass;
	avkey.specified = AVTAB_ALLOWED;

	node = yz_call_avtab_search_node(&db->te_avtab, &avkey);
	if (node)
		return node;

	node = yz_call_avtab_insert_nonunique(&db->te_avtab, &avkey, &datum);
	if (node)
		db->len += YZ_POLICY_AVTAB_ALLOWED_SIZE;

	return node;
}

static int yz_policy_remove_avtab_node(struct policydb *db,
				       struct avtab_node *node)
{
	struct avtab removed = {};
	struct avtab_node *cur;
	struct avtab_node *prev;
	int ret;
	size_t i;

	ret = yz_call_avtab_alloc(&removed, 1);
	/* An empty allow node grants nothing and retains its serialized size. */
	if (ret == -ENOMEM)
		return 0;
	if (ret < 0)
		return ret;

	for (i = 0; i < db->te_avtab.nslot; i++) {
		prev = NULL;
		for (cur = db->te_avtab.htable[i]; cur;
		     prev = cur, cur = cur->next) {
			if (cur != node)
				continue;
			if (prev)
				prev->next = cur->next;
			else
				db->te_avtab.htable[i] = cur->next;
			if (db->te_avtab.nel)
				db->te_avtab.nel--;
			cur->next = NULL;
			removed.htable[0] = cur;
			removed.nel = 1;
			yz_call_avtab_destroy(&removed);
			db->len -= YZ_POLICY_AVTAB_ALLOWED_SIZE;
			return 0;
		}
	}

	yz_call_avtab_destroy(&removed);
	return -ENOENT;
}

static int
yz_policy_apply_av(struct policydb *db, const struct yz_policy_key *key,
		   u32 av, bool allow)
{
	struct avtab_node *node;

	if (!av)
		return 0;
	if (!yz_policy_type_name_by_value(db, key->src_type) ||
	    !yz_policy_type_name_by_value(db, key->tgt_type) ||
	    !yz_policy_class_name_by_value(db, key->tclass))
		return -ENOENT;

	if (allow) {
		node = yz_policy_get_avtab_node(db, key);
		if (!node)
			return -ENOMEM;
		node->datum.u.data |= av;
		return 0;
	}

	node = yz_call_avtab_search_node(
		&db->te_avtab,
		&(struct avtab_key){
			.source_type = key->src_type,
			.target_type = key->tgt_type,
			.target_class = key->tclass,
			.specified = AVTAB_ALLOWED,
		});
	if (!node)
		return 0;

	node->datum.u.data &= ~av;
	if (node->datum.u.data == 0)
		return yz_policy_remove_avtab_node(db, node);

	return 0;
}

static int yz_policy_allow_all_sources(
	struct policydb *db, u32 target_type,
	const struct yz_runtime_policy_class *spec)
{
	struct class_datum *cls;
	struct yz_policy_key key = {
		.tgt_type = target_type,
	};
	u32 av;
	u32 self_av;
	u32 src_type;

	cls = yz_call_symtab_search(&db->p_classes, spec->name);
	if (!cls || cls->value > U16_MAX)
		return spec->optional ? 0 : -ENOENT;

	av = yz_policy_required_av(cls, spec->perms, spec->perm_count);
	if (!av)
		return spec->optional ? 0 : -ENOENT;
	/* Do not pollute concrete daemon->daemon socket reply perms during
	 * temporary runtime setup; domain self-socket rules compile concrete. */
	self_av = !strcmp(spec->name, "unix_stream_socket")
		      ? yz_policy_perm_mask(cls, "connectto")
		      : av;
	key.tclass = (u16)cls->value;

	for (src_type = 1; src_type <= db->p_types.nprim; src_type++) {
		const char *name = yz_policy_type_name_by_value(db, src_type);
		struct type_datum *type;
		u32 grant = src_type == target_type ? self_av : av;
		int ret;

		if (!name || !grant)
			continue;
		type = yz_call_symtab_search(&db->p_types, name);
		if (!type || type->attribute)
			continue;

		key.src_type = src_type;
		ret = yz_policy_apply_av(db, &key, grant, true);
		if (ret)
			return ret;
	}

	return 0;
}

static int yz_policy_allow_named(
	struct policydb *db, const char *source, const char *target,
	const char *class_name, const char *const *perms, size_t perm_count)
{
	struct type_datum *source_type;
	struct type_datum *target_type;
	struct class_datum *cls;
	struct yz_policy_key key;
	u32 av;

	source_type = yz_call_symtab_search(&db->p_types, source);
	target_type = yz_call_symtab_search(&db->p_types, target);
	cls = yz_call_symtab_search(&db->p_classes, class_name);
	if (!source_type || source_type->attribute || !target_type ||
	    target_type->attribute || !cls || source_type->value > U16_MAX ||
	    target_type->value > U16_MAX || cls->value > U16_MAX)
		return -ENOENT;

	av = yz_policy_required_av(cls, perms, perm_count);
	if (!av)
		return -ENOENT;

	key = (struct yz_policy_key){
		.src_type = (u16)source_type->value,
		.tgt_type = (u16)target_type->value,
		.tclass = (u16)cls->value,
	};
	return yz_policy_apply_av(db, &key, av, true);
}

/* Written by the authenticated runtime before its policy is prepared. */
static u32 yz_mount_daemon_sid;
static bool yz_mount_identity_changed;

int yz_host_policy_prepare_runtime_current(void)
{
	struct selinux_policy *policy;
	struct context *target_context;
	struct yz_policy_edit edit;
	char target_name[64];
	u32 target_type;
	u32 sid;
	size_t i;
	int ret;

	if (yz_fixed_policy_active())
		return yz_fixed_policy_live_error(current_cred(), NULL);
	if (!yz_fixed_policy_ready())
		return -EACCES;
	ret = yz_policy_base_lock();
	if (ret)
		return ret;

	sid = yz_policy_cred_sid(current_cred());
	if (!sid) {
		pr_err("yukizygisk: runtime SELinux policy: current credential "
		       "has no SID\n");
		ret = -EINVAL;
		goto out_unlock;
	}

	policy = rcu_dereference_protected(
		yz_selinux_state->policy,
		lockdep_is_held(&yz_selinux_state->policy_mutex));
	if (!policy) {
		ret = -ENOENT;
		goto out_unlock;
	}
	target_context = yz_policy_sidtab_search(policy->sidtab, sid);
	if (!target_context) {
		ret = -ENOENT;
		goto out_unlock;
	}
	target_type = target_context->type;
	if (!yz_mount_daemon_sid)
		WRITE_ONCE(yz_mount_daemon_sid, sid);
	else if (yz_mount_daemon_sid != sid)
		WRITE_ONCE(yz_mount_identity_changed, true);
	yz_policy_copy_type_name(target_name, sizeof(target_name),
				 &policy->policydb, target_type);

	ret = yz_policy_begin_edit_locked(&edit, YZ_POLICY_AVTAB);
	if (ret)
		goto out_unlock;

	for (i = 0; i < ARRAY_SIZE(yz_runtime_policy_classes); i++) {
		ret = yz_policy_allow_all_sources(
			&edit.policy->policydb, target_type,
			&yz_runtime_policy_classes[i]);
		if (ret)
			goto out_cancel;
	}

	ret = yz_policy_allow_named(
		&edit.policy->policydb, "system_server",
		"system_server", "process", yz_process_execmem_perms,
		ARRAY_SIZE(yz_process_execmem_perms));
	if (ret)
		goto out_cancel;

	yz_policy_commit_edit_locked(&edit);
	pr_info("yukizygisk: runtime SELinux communication allowed to daemon type=%s; system_server execmem allowed\n",
		target_name);
	ret = 0;
	goto out_unlock;

out_cancel:
	yz_policy_cancel_edit_locked(&edit);
out_unlock:
	yz_policy_base_unlock();
	return ret;
}

static void yz_policy_destroy(struct selinux_policy *policy,
			      enum yz_policy_edit_scope scope)
{
	if (!policy)
		return;
	if (scope == YZ_POLICY_AVTAB)
		yz_call_avtab_destroy(&policy->policydb.te_avtab);
	else
		yz_call_policydb_destroy(&policy->policydb);
	kfree(policy);
}

static struct selinux_policy *yz_policy_dup(struct selinux_policy *old_policy)
{
	struct selinux_policy *policy;
	struct policy_file fp;
	void *data;
	size_t len;
	int ret;

	if (!policydb_snapshot_capacity(&old_policy->policydb, &len)) {
		pr_err("yukizygisk: SELinux policy buffer length overflow\n");
		return ERR_PTR(-EOVERFLOW);
	}
	data = vmalloc(len);
	if (!data)
		return ERR_PTR(-ENOMEM);

	fp.data = data;
	fp.len = len;
	ret = yz_call_policydb_write(&old_policy->policydb, &fp);
	if (ret) {
		pr_err("yukizygisk: policydb_write failed: %d (capacity=%zu "
		       "remaining=%zu)\n",
		       ret, len, fp.len);
		goto out_free_data;
	}
	len -= fp.len;

#ifdef POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE
	if (len >= 24) {
		__le32 *config_ptr = (__le32 *)((u8 *)data + 20);
		u32 config = le32_to_cpu(*config_ptr);

		if (old_policy->policydb.android_netlink_route)
			config |= POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE;
#ifdef POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH
		if (old_policy->policydb.android_netlink_getneigh)
			config |= POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH;
#endif
		*config_ptr = cpu_to_le32(config);
	}
#endif

	policy = kmemdup(old_policy, sizeof(*old_policy), GFP_KERNEL);
	if (!policy) {
		ret = -ENOMEM;
		goto out_free_data;
	}
	memset(&policy->policydb, 0, sizeof(policy->policydb));

	fp.data = data;
	fp.len = len;
	ret = yz_call_policydb_read(&policy->policydb, &fp);
	if (ret) {
		pr_err("yukizygisk: policydb_read failed: %d (length=%zu "
		       "remaining=%zu)\n",
		       ret, len, fp.len);
		goto out_free_policy;
	}
	policy->policydb.len = len;
	vfree(data);
	return policy;

out_free_policy:
	if (policydb_read_needs_destroy(&policy->policydb))
		yz_call_policydb_destroy(&policy->policydb);
	kfree(policy);
out_free_data:
	vfree(data);
	return ERR_PTR(ret);
}

static int yz_policy_serialized_len(struct selinux_policy *old, size_t *len)
{
	struct policy_file fp;
	size_t capacity;
	void *data;
	int ret;

	if (old == READ_ONCE(yz_sized_policy) &&
	    old->latest_granting == yz_sized_seqno &&
	    old->policydb.te_avtab.nel == yz_sized_nel &&
	    old->policydb.p_types.nprim == yz_sized_types) {
		*len = old->policydb.len;
		return 0;
	}
	if (!policydb_snapshot_capacity(&old->policydb, &capacity))
		return -EOVERFLOW;
	data = vmalloc(capacity);
	if (!data)
		return -ENOMEM;
	fp.data = data;
	fp.len = capacity;
	ret = yz_call_policydb_write(&old->policydb, &fp);
	if (!ret)
		*len = capacity - fp.len;
	vfree(data);
	return ret;
}

static struct selinux_policy *yz_policy_dup_avtab(struct selinux_policy *old)
{
	struct avtab *src = &old->policydb.te_avtab;
	struct selinux_policy *policy;
	struct avtab *dst;
	size_t len;
	u32 i;
	int ret;

	ret = yz_policy_serialized_len(old, &len);
	if (ret)
		return ERR_PTR(ret);
	policy = kmemdup(old, sizeof(*old), GFP_KERNEL);
	if (!policy)
		return ERR_PTR(-ENOMEM);
	policy->policydb.len = len;
	dst = &policy->policydb.te_avtab;
	memset(dst, 0, sizeof(*dst));
	ret = yz_call_avtab_alloc(dst, max(src->nel, 1U));
	if (ret)
		goto free_policy;

	for (i = 0; i < src->nslot; i++) {
		struct avtab_node *prev = NULL, *node;

		if (!(i & 63))
			cond_resched();
		for (node = src->htable[i]; node; node = node->next) {
			struct avtab tail = {.nslot = 1};
			struct avtab *table = dst;

			if ((node->key.specified & AVTAB_XPERMS) &&
			    !node->datum.u.xperms) {
				ret = -EINVAL;
				goto free_table;
			}
			/* Rehash distinct triples when the bucket count
			 * changes. Append siblings in source order, including
			 * equal xperms. */
			if (src->nslot == dst->nslot ||
			    (prev &&
			     prev->key.source_type == node->key.source_type &&
			     prev->key.target_type == node->key.target_type &&
			     prev->key.target_class ==
				 node->key.target_class)) {
				tail.htable =
				    prev ? &prev->next : &dst->htable[i];
				table = &tail;
			}
			prev = yz_call_avtab_insert_nonunique(table, &node->key,
							      &node->datum);
			if (!prev) {
				ret = -ENOMEM;
				goto free_table;
			}
			dst->nel += tail.nel;
		}
	}
	return policy;

free_table:
	yz_call_avtab_destroy(dst);
free_policy:
	kfree(policy);
	return ERR_PTR(ret);
}

static YZ_LEGACY_INDIRECT_CALL void yz_policy_reset_avc(u32 seqno)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	yz_avc_ss_reset(seqno);
	yz_selnl_notify_policyload(seqno);
	yz_selinux_status_update_policyload(seqno);
#else
	yz_avc_ss_reset(yz_selinux_state->avc, seqno);
	yz_selnl_notify_policyload(seqno);
	yz_selinux_status_update_policyload(yz_selinux_state, seqno);
#endif
	selinux_xfrm_notify_policyload();
}

static int yz_policy_begin_edit_locked(struct yz_policy_edit *edit,
				       enum yz_policy_edit_scope scope)
{
	struct selinux_policy *old_policy;

	memset(edit, 0, sizeof(*edit));
	if (!yz_policy_base_ready())
		return -EOPNOTSUPP;
	if (!smp_load_acquire(&yz_selinux_state->initialized))
		return -EAGAIN;

	old_policy = rcu_dereference_protected(
		yz_selinux_state->policy,
		lockdep_is_held(&yz_selinux_state->policy_mutex));
	if (!old_policy)
		return -ENOENT;

	edit->scope = YZ_POLICY_AVTAB_KMI ? scope : YZ_POLICY_FULL;
	pr_debug("yukizygisk: SELinux %s copy at generation %u\n",
		 edit->scope == YZ_POLICY_AVTAB ? "AVTAB" : "full",
		 old_policy->latest_granting);
	edit->policy = edit->scope == YZ_POLICY_AVTAB
			   ? yz_policy_dup_avtab(old_policy)
			   : yz_policy_dup(old_policy);
	if (IS_ERR(edit->policy)) {
		int ret = PTR_ERR(edit->policy);

		memset(edit, 0, sizeof(*edit));
		return ret;
	}
	edit->old_policy = old_policy;
	return 0;
}

static void
yz_policy_cancel_edit_locked(struct yz_policy_edit *edit)
{
	yz_policy_destroy(edit->policy, edit->scope);
	memset(edit, 0, sizeof(*edit));
}

static void
yz_policy_commit_edit_locked(struct yz_policy_edit *edit)
{
	lockdep_assert_held(&yz_selinux_state->policy_mutex);
	edit->policy->latest_granting = edit->old_policy->latest_granting + 1;
	/* KernelSU invalidates stale metadata on false. The edit still commits. */
	if (!yz_ksu_policy_advance(&edit->policy->policydb, &edit->old_policy->policydb,
				   edit->old_policy->latest_granting,
				   edit->policy->latest_granting))
		pr_warn_ratelimited("yukizygisk: KernelSU using backup type lookups at SELinux generation %u\n",
				    edit->policy->latest_granting);
	rcu_assign_pointer(yz_selinux_state->policy, edit->policy);
	synchronize_rcu();
	yz_policy_destroy(edit->old_policy, edit->scope);
	yz_policy_reset_avc(edit->policy->latest_granting);
	/* Our synchronous reset invalidated the old entry. The policy mutex
	 * still excludes a host replacement while we record the new one. */
	if (yz_unregister_policy_notifier && edit->scope == YZ_POLICY_AVTAB) {
		yz_sized_seqno = edit->policy->latest_granting;
		yz_sized_nel = edit->policy->policydb.te_avtab.nel;
		yz_sized_types = edit->policy->policydb.p_types.nprim;
		WRITE_ONCE(yz_sized_policy, edit->policy);
	}
	memset(edit, 0, sizeof(*edit));
}

int yz_policy_base_commit_allow_locked(const struct yz_policy_key *file_key,
				       u32 file_av,
				       const struct yz_policy_key *dir_key,
				       u32 dir_av,
				       const struct yz_policy_key *tmpfs_key,
				       u32 tmpfs_av,
				       const struct yz_policy_key *process_key,
				       u32 process_av)
{
	struct yz_policy_edit edit;
	int ret;

	if (!file_av && !dir_av && !tmpfs_av && !process_av) {
		pr_debug(
		    "yukizygisk: SELinux grant skipped (no new permissions)\n");
		return 0;
	}

	ret = yz_policy_begin_edit_locked(&edit, YZ_POLICY_AVTAB);
	if (ret)
		return ret;

	if (file_av) {
		ret = yz_policy_apply_av(&edit.policy->policydb,
					 file_key, file_av, true);
		if (ret)
			goto out_cancel;
	}
	if (dir_av) {
		ret = yz_policy_apply_av(&edit.policy->policydb,
					 dir_key, dir_av, true);
		if (ret)
			goto out_cancel;
	}
	if (tmpfs_av) {
		ret = yz_policy_apply_av(&edit.policy->policydb,
					 tmpfs_key, tmpfs_av, true);
		if (ret)
			goto out_cancel;
	}
	if (process_av) {
		ret = yz_policy_apply_av(&edit.policy->policydb,
					 process_key, process_av, true);
		if (ret)
			goto out_cancel;
	}

	yz_policy_commit_edit_locked(&edit);
	return 0;

out_cancel:
	yz_policy_cancel_edit_locked(&edit);
	return ret;
}

int yz_policy_base_commit_restore_locked(
	const struct yz_policy_key *file_key, u32 file_av,
	const struct yz_policy_key *dir_key, u32 dir_av,
	const struct yz_policy_key *tmpfs_key, u32 tmpfs_av,
	const struct yz_policy_key *process_key, u32 process_av)
{
	struct yz_policy_edit edit;
	int ret;

	if (!file_av && !dir_av && !tmpfs_av && !process_av) {
		pr_debug("yukizygisk: SELinux restore skipped (no permissions "
			 "to remove)\n");
		return 0;
	}

	ret = yz_policy_begin_edit_locked(&edit, YZ_POLICY_AVTAB);
	if (ret)
		return ret;

	if (file_av) {
		ret = yz_policy_apply_av(&edit.policy->policydb,
					 file_key, file_av, false);
		if (ret)
			goto out_cancel;
	}
	if (dir_av) {
		ret = yz_policy_apply_av(&edit.policy->policydb,
					 dir_key, dir_av, false);
		if (ret)
			goto out_cancel;
	}
	if (tmpfs_av) {
		ret = yz_policy_apply_av(&edit.policy->policydb,
					 tmpfs_key, tmpfs_av, false);
		if (ret)
			goto out_cancel;
	}
	if (process_av) {
		ret = yz_policy_apply_av(&edit.policy->policydb,
					 process_key, process_av, false);
		if (ret)
			goto out_cancel;
	}

	yz_policy_commit_edit_locked(&edit);
	return 0;

out_cancel:
	yz_policy_cancel_edit_locked(&edit);
	return ret;
}

int yz_policy_base_lock(void)
{
	if (!yz_policy_base_ready())
		return -EOPNOTSUPP;

	mutex_lock(&yz_policy_lock);
	if (!yz_policy_base_ready()) {
		mutex_unlock(&yz_policy_lock);
		return -EOPNOTSUPP;
	}
	mutex_lock(&yz_selinux_state->policy_mutex);
	return 0;
}

void yz_policy_base_unlock(void)
{
	mutex_unlock(&yz_selinux_state->policy_mutex);
	mutex_unlock(&yz_policy_lock);
}

int
yz_policy_base_get_file_load_keys(
	struct file *file, const struct cred *cred, bool include_dir,
	enum yz_policy_tmpfs_access tmpfs_access,
	struct yz_policy_file_load_keys *keys,
	char *src_name, size_t src_name_size, char *tgt_name,
	size_t tgt_name_size)
{
	const char *const *tmpfs_perms = NULL;
	struct inode_security_struct *isec;
	struct selinux_policy *policy;
	struct policydb *db;
	struct context *scontext;
	struct context *tcontext;
	struct class_datum *cls;
	u32 ssid;
	u32 tsid;
	u32 tmpfs_type;
	size_t tmpfs_perm_count = 0;

	if (!file || !cred || !keys)
		return -EINVAL;

	switch (tmpfs_access) {
	case YZ_POLICY_TMPFS_NONE:
	case YZ_POLICY_FILE_RECEIVE:
		break;
	case YZ_POLICY_TMPFS_LOAD:
		tmpfs_perms = yz_tmpfs_load_perms;
		tmpfs_perm_count = ARRAY_SIZE(yz_tmpfs_load_perms);
		break;
	case YZ_POLICY_TMPFS_RECEIVE:
		tmpfs_perms = yz_tmpfs_receive_perms;
		tmpfs_perm_count = ARRAY_SIZE(yz_tmpfs_receive_perms);
		break;
	default:
		return -EINVAL;
	}

	*keys = (struct yz_policy_file_load_keys){};

	isec = yz_selinux_inode(file_inode(file));
	if (IS_ERR(isec))
		return PTR_ERR(isec);
	if (!isec)
		return -EINVAL;

	ssid = yz_policy_cred_sid(cred);
	tsid = isec->sid;
	if (!ssid || !tsid)
		return -EINVAL;

	policy = rcu_dereference_protected(
		yz_selinux_state->policy,
		lockdep_is_held(&yz_selinux_state->policy_mutex));
	if (!policy)
		return -ENOENT;

	db = &policy->policydb;
	scontext = yz_policy_sidtab_search(policy->sidtab, ssid);
	tcontext = yz_policy_sidtab_search(policy->sidtab, tsid);
	if (!scontext || !tcontext)
		return -ENOENT;

	cls = yz_call_symtab_search(&db->p_classes, "file");
	if (!cls || cls->value > U16_MAX)
		return -ENOENT;

	keys->file.src_type = scontext->type;
	keys->file.tgt_type = tcontext->type;
	keys->file.tclass = (u16)cls->value;
	keys->file_required_av =
	    tmpfs_access == YZ_POLICY_FILE_RECEIVE
		? yz_policy_required_av(cls, yz_tmpfs_receive_perms,
					ARRAY_SIZE(yz_tmpfs_receive_perms))
		: yz_policy_required_av(cls, yz_file_load_perms,
					ARRAY_SIZE(yz_file_load_perms));

	if (include_dir) {
		cls = yz_call_symtab_search(&db->p_classes, "dir");
		if (!cls || cls->value > U16_MAX)
			return -ENOENT;
		keys->dir.src_type = scontext->type;
		keys->dir.tgt_type = tcontext->type;
		keys->dir.tclass = (u16)cls->value;
		keys->dir_required_av = yz_policy_required_av(
			cls, yz_dir_load_perms, ARRAY_SIZE(yz_dir_load_perms));
	}

	tmpfs_type = tmpfs_perms ?
			     yz_policy_type_value_by_name(db, "tmpfs") :
			     0;
	if (tmpfs_type) {
		cls = yz_call_symtab_search(&db->p_classes, "file");
		if (!cls || cls->value > U16_MAX)
			return -ENOENT;
		if (tmpfs_type == tcontext->type) {
			/* The tmpfs role is a superset; acquire the key only once. */
			keys->file_required_av = 0;
		}
		keys->tmpfs.src_type = scontext->type;
		keys->tmpfs.tgt_type = tmpfs_type;
		keys->tmpfs.tclass = (u16)cls->value;
		keys->tmpfs_required_av = yz_policy_required_av(
			cls, tmpfs_perms, tmpfs_perm_count);
	}

	yz_policy_copy_type_name(src_name, src_name_size, db,
				 scontext->type);
	yz_policy_copy_type_name(tgt_name, tgt_name_size, db,
				 tcontext->type);
	return 0;
}

int
yz_policy_base_get_execmem_key(const struct cred *cred,
			       struct yz_policy_key *key, u32 *required_av,
			       char *src_name, size_t src_name_size)
{
	struct selinux_policy *policy;
	struct policydb *db;
	struct context *scontext;
	struct class_datum *cls;
	u32 ssid;

	if (!key || !required_av)
		return -EINVAL;

	*key = (struct yz_policy_key){};
	*required_av = 0;

	ssid = yz_policy_cred_sid(cred);
	if (!ssid)
		return -EINVAL;

	policy = rcu_dereference_protected(
		yz_selinux_state->policy,
		lockdep_is_held(&yz_selinux_state->policy_mutex));
	if (!policy)
		return -ENOENT;

	db = &policy->policydb;
	scontext = yz_policy_sidtab_search(policy->sidtab, ssid);
	if (!scontext)
		return -ENOENT;

	cls = yz_call_symtab_search(&db->p_classes, "process");
	if (!cls || cls->value > U16_MAX)
		return -ENOENT;

	key->src_type = scontext->type;
	key->tgt_type = scontext->type;
	key->tclass = (u16)cls->value;
	*required_av = yz_policy_required_av(
		cls, yz_process_execmem_perms,
		ARRAY_SIZE(yz_process_execmem_perms));
	yz_policy_copy_type_name(src_name, src_name_size, db,
				 scontext->type);
	return 0;
}

static void yz_fixed_cache_invalidate(void);

static int yz_policy_changed(struct notifier_block *nb, unsigned long event,
			     void *data)
{
	if (event == LSM_POLICY_CHANGE) {
		WRITE_ONCE(yz_sized_policy, NULL);
		yz_fixed_cache_invalidate();
	}
	return NOTIFY_DONE;
}

static struct notifier_block yz_policy_notifier = {
	.notifier_call = yz_policy_changed,
};

static YZ_LEGACY_INDIRECT_CALL void yz_policy_cache_init(void)
{
	typeof(&register_blocking_lsm_notifier) subscribe =
	    (void *)yz_lookup_callable_quiet("register_blocking_lsm_notifier");
	typeof(&unregister_blocking_lsm_notifier) unsubscribe =
	    (void *)yz_lookup_callable_quiet("unregister_blocking_lsm_notifier");

	if (subscribe && unsubscribe && !subscribe(&yz_policy_notifier))
		yz_unregister_policy_notifier = unsubscribe;
}

static YZ_LEGACY_INDIRECT_CALL void yz_policy_cache_exit(void)
{
	if (yz_unregister_policy_notifier) {
		yz_unregister_policy_notifier(&yz_policy_notifier);
		yz_unregister_policy_notifier = NULL;
	}
	WRITE_ONCE(yz_sized_policy, NULL);
	yz_fixed_cache_invalidate();
}

int yz_host_policy_init(void)
{
	int ret;

	yz_fp_compute_fn =
	    (void *)yz_lookup_callable_quiet("security_compute_av_user");
	yz_fp_context_fn =
	    (void *)yz_lookup_callable_quiet("security_context_to_sid");
	yz_memfd_fcntl = (void *)yz_lookup_callable_quiet("memfd_fcntl");

	yz_selinux_state =
		(void *)yz_lookup_name_quiet("selinux_state");
	yz_selinux_blob_sizes =
		(void *)yz_lookup_name_quiet("selinux_blob_sizes");
	yz_policydb_write =
		(void *)yz_lookup_callable_quiet("policydb_write");
	yz_policydb_read =
		(void *)yz_lookup_callable_quiet("policydb_read");
	yz_policydb_destroy =
		(void *)yz_lookup_callable_quiet("policydb_destroy");
	yz_symtab_search =
		(void *)yz_lookup_callable_quiet("symtab_search");
	yz_avtab_search_node =
		(void *)yz_lookup_callable_quiet("avtab_search_node");
	yz_avtab_insert_nonunique =
		(void *)yz_lookup_callable_quiet("avtab_insert_nonunique");
	yz_avtab_alloc =
		(void *)yz_lookup_callable_quiet("avtab_alloc");
	yz_avtab_destroy =
		(void *)yz_lookup_callable_quiet("avtab_destroy");
	yz_sidtab_search_entry =
		(void *)yz_lookup_callable_quiet("sidtab_search_entry");
	yz_avc_ss_reset =
		(void *)yz_lookup_callable_quiet("avc_ss_reset");
	yz_selnl_notify_policyload =
		(void *)yz_lookup_callable_quiet("selnl_notify_policyload");
	yz_selinux_status_update_policyload =
		(void *)yz_lookup_callable_quiet(
			"selinux_status_update_policyload");
	if (!yz_policy_base_ready()) {
		pr_warn("yukizygisk: KernelSU-style SELinux policy backend unavailable\n");
		return 0;
	}

	ret = yz_selinux_inode_init(yz_selinux_blob_sizes);
	if (ret)
		return ret;

	yz_policy_cache_init();
	pr_info("yukizygisk: KernelSU-style SELinux policy backend available\n");
	return 0;
}

void yz_host_policy_select_temporary(void)
{
	mutex_lock(&yz_policy_lock);
	if (yz_policy_base_ready())
		yz_ksu_policy_bind();
	mutex_unlock(&yz_policy_lock);
}

void yz_host_policy_exit(void)
{
	yz_policy_cache_exit();
	yz_policy_temp_reset();

	mutex_lock(&yz_policy_lock);
	yz_ksu_policy_unbind();
	yz_fp_compute_fn = NULL;
	yz_fp_context_fn = NULL;
	yz_memfd_fcntl = NULL;
	yz_selinux_state = NULL;
	yz_selinux_blob_sizes = NULL;
	yz_policydb_write = NULL;
	yz_policydb_read = NULL;
	yz_policydb_destroy = NULL;
	yz_symtab_search = NULL;
	yz_avtab_search_node = NULL;
	yz_avtab_insert_nonunique = NULL;
	yz_avtab_alloc = NULL;
	yz_sized_seqno = 0;
	yz_sized_nel = 0;
	yz_sized_types = 0;
	yz_mount_daemon_sid = 0;
	yz_mount_identity_changed = false;
	yz_avtab_destroy = NULL;
	yz_sidtab_search_entry = NULL;
	yz_avc_ss_reset = NULL;
	yz_selnl_notify_policyload = NULL;
	yz_selinux_status_update_policyload = NULL;
	mutex_unlock(&yz_policy_lock);
}

static bool yz_policy_sid_has_type(struct selinux_policy *policy, u32 sid,
				   const char *type_name)
{
	struct context *ctx = yz_policy_sidtab_search(policy->sidtab, sid);
	const char *name;

	if (!ctx)
		return false;
	name = yz_policy_type_name_by_value(&policy->policydb, ctx->type);
	return name && !strcmp(name, type_name);
}

bool yz_host_policy_cred_has_type(const struct cred *cred,
				  const char *type_name)
{
	struct selinux_policy *policy;
	u32 sid;
	bool match;

	if (!type_name || !yz_policy_base_ready())
		return false;

	sid = yz_policy_cred_sid(cred);
	if (!sid)
		return false;

	rcu_read_lock();
	policy = rcu_dereference(yz_selinux_state->policy);
	match = policy && yz_policy_sid_has_type(policy, sid, type_name);
	rcu_read_unlock();
	return match;
}

static YZ_LEGACY_INDIRECT_CALL void
yz_fp_compute(u32 source, u32 target, u16 cls, struct av_decision *decision)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	yz_fp_compute_fn(source, target, cls, decision);
#else
	yz_fp_compute_fn(yz_selinux_state, source, target, cls, decision);
#endif
}
static YZ_LEGACY_INDIRECT_CALL int
yz_fp_context_sid(const char *context, u32 len, u32 *sid, gfp_t flags)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	return yz_fp_context_fn(context, len, sid, flags);
#else
	return yz_fp_context_fn(yz_selinux_state, context, len, sid, flags);
#endif
}
#define yz_fp_search yz_call_symtab_search
#define yz_fp_state yz_selinux_state
#define yz_fp_cred_sid yz_policy_cred_sid
#define yz_fp_sidtab_search yz_policy_sidtab_search
#define yz_fp_inode yz_selinux_inode
static int yz_fp_has_rule(struct policydb *db, const char *source,
			  const char *target, const char *class_name,
			  const char *permission)
{
	struct type_datum *src = yz_fp_search(&db->p_types, source);
	struct type_datum *tgt = yz_fp_search(&db->p_types, target);
	struct class_datum *cls = yz_fp_search(&db->p_classes, class_name);
	u32 required;

	if (!src || !tgt || !cls)
		return -ENOENT;
	required = yz_policy_perm_mask(cls, permission);
	return required &&
		       (yz_policy_direct_allowed_av_locked(
			    db, &(struct yz_policy_key){.src_type = src->value,
							.tgt_type = tgt->value,
							.tclass = cls->value}) &
			required) == required
		   ? 0
		   : -EACCES;
}

#include "feature/policy/database.h"
#include "feature/policy/mount_route.h"

static bool yz_fixed_socket_route(struct selinux_policy *policy, u32 daemon_sid)
{
	struct context *ctx;

	if (!daemon_sid || READ_ONCE(yz_mount_identity_changed) ||
	    READ_ONCE(yz_mount_daemon_sid) != daemon_sid)
		return false;
	ctx = yz_policy_sidtab_search(policy->sidtab, daemon_sid);
	return ctx && yz_mount_host_allows_app_connect(&policy->policydb,
						       ctx->type);
}

static bool yz_fixed_mount_route_locked(struct selinux_policy *policy,
					u32 daemon_sid, bool bind)
{
	bool socket_route = yz_fixed_socket_route(policy, daemon_sid);

	return yz_host_check_app_mounts(bind, socket_route) || socket_route;
}

static const struct yz_fixed_policy_config *yz_bound_config;
static char yz_bound_daemon[YZ_FIXED_NAME_MAX];
static u32 yz_bound_sid;
static DEFINE_SPINLOCK(yz_fixed_cache_lock);
static u64 yz_fixed_cache_epoch;
static struct {
	struct selinux_policy *policy;
	u32 generation;
	bool socket_route;
	struct yz_fixed_policy_status rules;
} yz_fixed_cache;

static void yz_fixed_cache_invalidate(void)
{
	unsigned long flags;

	spin_lock_irqsave(&yz_fixed_cache_lock, flags);
	yz_fixed_cache.policy = NULL;
	yz_fixed_cache_epoch++;
	spin_unlock_irqrestore(&yz_fixed_cache_lock, flags);
}

static int yz_fixed_live_error(struct selinux_policy *policy,
			       const struct cred *cred,
			       struct yz_fixed_policy_status *detail)
{
	struct yz_fixed_policy_status checked = {};
	unsigned long flags;
	bool socket_route;
	u64 epoch;
	u32 generation;
	int ret;

	if (!policy)
		return -EAGAIN;
	if (cred && !yz_policy_sid_has_type(policy, yz_policy_cred_sid(cred),
					    yz_bound_daemon))
		return -EACCES;
	generation = READ_ONCE(policy->latest_granting);
	spin_lock_irqsave(&yz_fixed_cache_lock, flags);
	if (yz_fixed_cache.policy == policy &&
	    yz_fixed_cache.generation == generation) {
		ret = yz_fixed_cache.rules.error;
		socket_route = yz_fixed_cache.socket_route;
		if (detail && ret)
			*detail = yz_fixed_cache.rules;
		spin_unlock_irqrestore(&yz_fixed_cache_lock, flags);
		goto route;
	}
	epoch = yz_fixed_cache_epoch;
	spin_unlock_irqrestore(&yz_fixed_cache_lock, flags);

	ret = -EACCES;
	if (yz_policy_sid_has_type(policy, yz_bound_sid, yz_bound_daemon))
		ret = yz_fixed_verify_rules(&policy->policydb, yz_bound_config,
					    yz_bound_daemon, &checked);
	socket_route =
	    !ret &&
	    (yz_unregister_policy_notifier || !yz_host_handles_app_mounts()) &&
	    yz_fixed_socket_route(policy, yz_bound_sid);
	checked.error = ret;
	if (detail && ret)
		*detail = checked;

	/* Older hosts replace policies without advancing latest_granting.
	 * An AVC reset also invalidates checks begun before the notification. */
	spin_lock_irqsave(&yz_fixed_cache_lock, flags);
	if (yz_unregister_policy_notifier && epoch == yz_fixed_cache_epoch &&
	    rcu_access_pointer(yz_selinux_state->policy) == policy) {
		yz_fixed_cache.policy = policy;
		yz_fixed_cache.generation = generation;
		yz_fixed_cache.socket_route = socket_route;
		yz_fixed_cache.rules = checked;
	}
	spin_unlock_irqrestore(&yz_fixed_cache_lock, flags);
route:
	if (!ret && !yz_host_handles_app_mounts() &&
	    (!socket_route || READ_ONCE(yz_mount_identity_changed)))
		ret = -ENETUNREACH;
	return ret;
}

int yz_fixed_policy_live_error(const struct cred *cred,
			       struct yz_fixed_policy_status *detail)
{
	int ret;

	rcu_read_lock();
	ret = yz_fixed_live_error(rcu_dereference(yz_selinux_state->policy),
				  cred, detail);
	rcu_read_unlock();
	return ret;
}

static int yz_fixed_capabilities(void)
{
	if (!yz_fp_compute_fn || !yz_fp_context_fn || !yz_memfd_fcntl)
		return -EOPNOTSUPP;
	return yz_fixed_inode_layout();
}

int yz_fixed_policy_validate(const struct yz_fixed_policy_config *config)
{
	struct selinux_policy *policy;
	int ret;

	if (config->version != YZ_FIXED_POLICY_VERSION ||
	    config->enabled != 1 || config->reserved ||
	    config->count > YZ_FIXED_DOMAIN_MAX)
		return -EINVAL;
	ret = yz_fixed_capabilities();
	if (ret)
		return ret;
	ret = yz_policy_base_lock();
	if (ret)
		return ret;
	policy = rcu_dereference_protected(
	    yz_selinux_state->policy,
	    lockdep_is_held(&yz_selinux_state->policy_mutex));
	if (!policy || !smp_load_acquire(&yz_selinux_state->initialized))
		ret = -EAGAIN;
	else if (!yz_fixed_mount_route_locked(policy, yz_mount_daemon_sid,
					      false))
		ret = -ENETUNREACH;
	else
		ret = yz_fixed_verify_rules(&policy->policydb, config, NULL,
					    NULL);
	yz_policy_base_unlock();
	return ret;
}

int yz_fixed_policy_verify(const struct yz_fixed_policy_config *config,
			   const struct cred *cred,
			   struct yz_fixed_policy_status *detail)
{
	char bound_name[YZ_FIXED_NAME_MAX];
	struct selinux_policy *policy;
	const char *daemon_name;
	struct context *context;
	u32 sid;
	int ret;

	ret = yz_fixed_capabilities();
	if (ret)
		return ret;
	ret = yz_policy_base_lock();
	if (ret)
		return ret;
	if (!smp_load_acquire(&yz_selinux_state->initialized)) {
		ret = -EAGAIN;
		goto unlock;
	}
	policy = rcu_dereference_protected(yz_selinux_state->policy,
		lockdep_is_held(&yz_selinux_state->policy_mutex));
	if (!policy) {
		ret = -EAGAIN;
		goto unlock;
	}
	sid = yz_policy_cred_sid(cred);
	context = yz_policy_sidtab_search(policy->sidtab, sid);
	if (!context) {
		ret = -EINVAL;
		goto unlock;
	}
	daemon_name =
	    yz_policy_type_name_by_value(&policy->policydb, context->type);
	if (!daemon_name) {
		ret = -ENOENT;
		goto unlock;
	}
	if (strscpy(bound_name, daemon_name, sizeof(bound_name)) < 0) {
		ret = -ENAMETOOLONG;
		goto unlock;
	}
	ret = yz_fixed_verify_rules(&policy->policydb, config, bound_name,
				    detail);
	if (ret)
		goto unlock;
	if (!yz_mount_daemon_sid)
		WRITE_ONCE(yz_mount_daemon_sid, sid);
	else if (yz_mount_daemon_sid != sid)
		WRITE_ONCE(yz_mount_identity_changed, true);
	if (!yz_fixed_mount_route_locked(policy, sid, true)) {
		ret = -ENETUNREACH;
		goto unlock;
	}
	strscpy(yz_bound_daemon, bound_name, sizeof(yz_bound_daemon));
	yz_bound_config = config;
	yz_bound_sid = sid;
unlock:
	yz_policy_base_unlock();
	return ret;
}

#include "feature/policy/access.h"
