/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * YukiZygisk - SELinux policy control base.
 *
 * Derived from KernelSU/YukiSU SELinux policy helpers.
 *
 * License: GPL-2.0-only
 *
 * Author: KernelSU contributors and Anatdx
 */

#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/lsm_hooks.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#include "objsec.h"
#include "security.h"
#include "ss/avtab.h"
#include "ss/policydb.h"
#include "ss/services.h"
#include "ss/sidtab.h"
#include "ss/symtab.h"
#include "xfrm.h"

#include "host/policy_base.h"
#include "host/policy.h"
#include "host/policy_temp.h"
#include "host/runtime.h"

#define YZ_POLICY_PERM_BITS 32

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
extern int avc_ss_reset(u32 seqno);
#else
extern int avc_ss_reset(struct selinux_avc *avc, u32 seqno);
#endif

struct yz_policy_edit {
	struct selinux_policy *old_policy;
	struct selinux_policy *policy;
};

static int
yz_policy_begin_edit_locked(struct yz_policy_edit *edit);
static void
yz_policy_cancel_edit_locked(struct yz_policy_edit *edit);
static void
yz_policy_commit_edit_locked(struct yz_policy_edit *edit);

static DEFINE_MUTEX(yz_policy_lock);
static struct selinux_state *yz_selinux_state;
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

static struct task_security_struct *yz_policy_cred_security(
	const struct cred *cred)
{
	if (!cred || !cred->security || !yz_selinux_blob_sizes)
		return NULL;
	return cred->security + yz_selinux_blob_sizes->lbs_cred;
}

static struct inode_security_struct *
yz_policy_inode_security(const struct inode *inode)
{
	if (!inode || !inode->i_security || !yz_selinux_blob_sizes)
		return NULL;
	return inode->i_security + yz_selinux_blob_sizes->lbs_inode;
}

static struct context *
yz_policy_sidtab_search(struct sidtab *sidtab, u32 sid)
{
	struct sidtab_entry *entry;

	if (!sidtab || !sid || !yz_sidtab_search_entry)
		return NULL;

	entry = yz_sidtab_search_entry(sidtab, sid);
	return entry ? &entry->context : NULL;
}

static u32 yz_policy_cred_sid(const struct cred *cred)
{
	struct task_security_struct *tsec =
		yz_policy_cred_security(cred);

	return tsec ? tsec->sid : 0;
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
	type = yz_symtab_search(&db->p_types, name);
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

	perm = yz_symtab_search(&cls->permissions, perm_name);
	if (!perm && cls->comdatum)
		perm = yz_symtab_search(&cls->comdatum->permissions, perm_name);
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

	node = yz_avtab_search_node(&db->te_avtab, &avkey);
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

	node = yz_avtab_search_node(&db->te_avtab, &avkey);
	if (node)
		return node;

	node = yz_avtab_insert_nonunique(&db->te_avtab, &avkey, &datum);
	if (node)
		db->len += sizeof(struct avtab_key) +
			   sizeof(struct avtab_datum);

	return node;
}

static bool
yz_policy_remove_avtab_node(struct policydb *db, struct avtab_node *node)
{
	struct avtab removed = {};
	struct avtab_node *cur;
	struct avtab_node *prev;
	int ret;
	size_t i;

	ret = yz_avtab_alloc(&removed, 1);
	if (ret < 0)
		return false;

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
			yz_avtab_destroy(&removed);
			db->len -= sizeof(struct avtab_key) +
				   sizeof(struct avtab_datum);
			return true;
		}
	}

	yz_avtab_destroy(&removed);
	return false;
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

	node = yz_avtab_search_node(
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
		yz_policy_remove_avtab_node(db, node);

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
	u32 src_type;

	cls = yz_symtab_search(&db->p_classes, spec->name);
	if (!cls || cls->value > U16_MAX)
		return spec->optional ? 0 : -ENOENT;

	av = yz_policy_required_av(cls, spec->perms, spec->perm_count);
	if (!av)
		return spec->optional ? 0 : -ENOENT;
	key.tclass = (u16)cls->value;

	for (src_type = 1; src_type <= db->p_types.nprim; src_type++) {
		const char *name = yz_policy_type_name_by_value(db, src_type);
		struct type_datum *type;
		int ret;

		if (!name)
			continue;
		type = yz_symtab_search(&db->p_types, name);
		if (!type || type->attribute)
			continue;

		key.src_type = src_type;
		ret = yz_policy_apply_av(db, &key, av, true);
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

	source_type = yz_symtab_search(&db->p_types, source);
	target_type = yz_symtab_search(&db->p_types, target);
	cls = yz_symtab_search(&db->p_classes, class_name);
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

int yz_host_policy_prepare_runtime_current(void)
{
	struct task_security_struct *tsec;
	struct selinux_policy *policy;
	struct context *target_context;
	struct yz_policy_edit edit;
	char target_name[64];
	u32 target_type;
	size_t i;
	int ret;

	ret = yz_policy_base_lock();
	if (ret)
		return ret;

	tsec = yz_policy_cred_security(current_cred());
	if (!tsec || !tsec->sid) {
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
	target_context = yz_policy_sidtab_search(policy->sidtab, tsec->sid);
	if (!target_context) {
		ret = -ENOENT;
		goto out_unlock;
	}
	target_type = target_context->type;
	yz_policy_copy_type_name(target_name, sizeof(target_name),
				 &policy->policydb, target_type);

	ret = yz_policy_begin_edit_locked(&edit);
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

static void yz_policy_destroy(struct selinux_policy *policy)
{
	if (!policy)
		return;
	yz_policydb_destroy(&policy->policydb);
	kfree(policy);
}

static struct selinux_policy *
yz_policy_dup(struct selinux_policy *old_policy)
{
	struct selinux_policy *policy;
	struct policy_file fp;
	void *data;
	size_t len;
	int ret;

	len = old_policy->policydb.len;
	data = vmalloc(len);
	if (!data)
		return ERR_PTR(-ENOMEM);

	fp.data = data;
	fp.len = len;
	ret = yz_policydb_write(&old_policy->policydb, &fp);
	if (ret)
		goto out_free_data;

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
	ret = yz_policydb_read(&policy->policydb, &fp);
	if (ret)
		goto out_free_policy;
	policy->policydb.len = old_policy->policydb.len;
	vfree(data);
	return policy;

out_free_policy:
	kfree(policy);
out_free_data:
	vfree(data);
	return ERR_PTR(ret);
}

static void yz_policy_reset_avc(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	yz_avc_ss_reset(0);
	yz_selnl_notify_policyload(0);
	yz_selinux_status_update_policyload(0);
#else
	yz_avc_ss_reset(yz_selinux_state->avc, 0);
	yz_selnl_notify_policyload(0);
	yz_selinux_status_update_policyload(yz_selinux_state, 0);
#endif
	selinux_xfrm_notify_policyload();
}

static int
yz_policy_begin_edit_locked(struct yz_policy_edit *edit)
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

	edit->policy = yz_policy_dup(old_policy);
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
	yz_policy_destroy(edit->policy);
	memset(edit, 0, sizeof(*edit));
}

static void
yz_policy_commit_edit_locked(struct yz_policy_edit *edit)
{
	rcu_assign_pointer(yz_selinux_state->policy, edit->policy);
	synchronize_rcu();
	yz_policy_destroy(edit->old_policy);
	yz_policy_reset_avc();
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

	if (!file_av && !dir_av && !tmpfs_av && !process_av)
		return 0;

	ret = yz_policy_begin_edit_locked(&edit);
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

	if (!file_av && !dir_av && !tmpfs_av && !process_av)
		return 0;

	ret = yz_policy_begin_edit_locked(&edit);
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
	struct task_security_struct *tsec;
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

	isec = yz_policy_inode_security(file_inode(file));
	if (!isec)
		return -EINVAL;

	tsec = yz_policy_cred_security(cred);
	ssid = tsec ? tsec->sid : 0;
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

	cls = yz_symtab_search(&db->p_classes, "file");
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
		cls = yz_symtab_search(&db->p_classes, "dir");
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
		cls = yz_symtab_search(&db->p_classes, "file");
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

	cls = yz_symtab_search(&db->p_classes, "process");
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

int yz_host_policy_init(void)
{
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

	pr_info("yukizygisk: KernelSU-style SELinux policy backend available\n");
	return 0;
}

void yz_host_policy_exit(void)
{
	yz_policy_temp_reset();

	yz_selinux_state = NULL;
	yz_selinux_blob_sizes = NULL;
	yz_policydb_write = NULL;
	yz_policydb_read = NULL;
	yz_policydb_destroy = NULL;
	yz_symtab_search = NULL;
	yz_avtab_search_node = NULL;
	yz_avtab_insert_nonunique = NULL;
	yz_avtab_alloc = NULL;
	yz_avtab_destroy = NULL;
	yz_sidtab_search_entry = NULL;
	yz_avc_ss_reset = NULL;
	yz_selnl_notify_policyload = NULL;
	yz_selinux_status_update_policyload = NULL;
}

bool yz_host_policy_cred_has_type(const struct cred *cred,
				  const char *type_name)
{
	struct task_security_struct *tsec;
	struct selinux_policy *policy;
	struct context *ctx;
	struct policydb *db;
	const char *name;
	bool match = false;

	if (!type_name || !yz_policy_base_ready())
		return false;

	tsec = yz_policy_cred_security(cred);
	if (!tsec || !tsec->sid)
		return false;

	rcu_read_lock();
	policy = rcu_dereference(yz_selinux_state->policy);
	if (!policy)
		goto out_unlock;

	ctx = yz_policy_sidtab_search(policy->sidtab, tsec->sid);
	if (!ctx)
		goto out_unlock;

	db = &policy->policydb;
	name = yz_policy_type_name_by_value(db, ctx->type);
	match = name && !strcmp(name, type_name);

out_unlock:
	rcu_read_unlock();
	return match;
}
