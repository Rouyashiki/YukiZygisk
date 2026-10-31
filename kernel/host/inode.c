#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/ratelimit.h>
#include <linux/string.h>

#include "host/inode.h"
#include "host/runtime.h"
#include "objsec.h"

#ifdef CONFIG_DEBUG_INFO_BTF
struct yz_btf_field {
	u32 offset;
	u32 struct_size;
};

static YZ_LEGACY_INDIRECT_CALL int yz_btf_field(const char *structure,
						const char *member, u32 kind,
						u32 size,
						struct yz_btf_field *field)
{
	const struct btf *btf;
	const struct btf_type *type;
	const struct btf_member *m;
	s32 id;
	u32 i;
	typeof(&bpf_get_btf_vmlinux) call_bpf_get_btf_vmlinux =
	    (void *)yz_lookup_callable_quiet("bpf_get_btf_vmlinux");
	typeof(&btf_find_by_name_kind) call_btf_find_by_name_kind =
	    (void *)yz_lookup_callable_quiet("btf_find_by_name_kind");
	typeof(&btf_type_by_id) call_btf_type_by_id =
	    (void *)yz_lookup_callable_quiet("btf_type_by_id");
	typeof(&btf_name_by_offset) call_btf_name_by_offset =
	    (void *)yz_lookup_callable_quiet("btf_name_by_offset");
	typeof(&btf_type_skip_modifiers) call_btf_type_skip_modifiers =
	    (void *)yz_lookup_callable_quiet("btf_type_skip_modifiers");

	if (!call_bpf_get_btf_vmlinux || !call_btf_find_by_name_kind ||
	    !call_btf_type_by_id || !call_btf_name_by_offset ||
	    !call_btf_type_skip_modifiers)
		return -ENOENT;

	pr_info("BTF: acquiring vmlinux metadata for %s.%s\n", structure,
		member);
	btf = call_bpf_get_btf_vmlinux();
	if (IS_ERR_OR_NULL(btf)) {
		pr_err("BTF: vmlinux metadata unavailable (%ld)\n",
		       btf ? PTR_ERR(btf) : -ENOENT);
		return btf ? PTR_ERR(btf) : -ENOENT;
	}

	pr_info("BTF: looking up struct %s\n", structure);
	id = call_btf_find_by_name_kind(btf, structure, BTF_KIND_STRUCT);
	if (id < 0)
		return id;
	type = call_btf_type_by_id(btf, id);
	if (!type)
		return -EINVAL;

	for_each_member(i, type, m)
	{
		const struct btf_type *member_type;
		const char *name = call_btf_name_by_offset(btf, m->name_off);
		u32 bits, bytes, bitfield_size;

		if (!name)
			return -EINVAL;
		if (strcmp(name, member))
			continue;
		bits = m->offset;
		bitfield_size = 0;
		if (BTF_INFO_KFLAG(type->info)) {
			bitfield_size = BTF_MEMBER_BITFIELD_SIZE(bits);
			bits = BTF_MEMBER_BIT_OFFSET(bits);
		}
		bytes = bits / 8;
		if (bitfield_size || !size || (bits & 7) || bytes % size ||
		    bytes > type->size || size > type->size - bytes)
			return -EINVAL;
		member_type = call_btf_type_skip_modifiers(btf, m->type, NULL);
		if (!member_type || BTF_INFO_KIND(member_type->info) != kind)
			return -EINVAL;
		if (kind == BTF_KIND_INT) {
			u32 info = *(const u32 *)(member_type + 1);

			if (member_type->size != size || BTF_INT_OFFSET(info) ||
			    BTF_INT_BITS(info) != size * 8 ||
			    (BTF_INT_ENCODING(info) &
			     (BTF_INT_CHAR | BTF_INT_BOOL)))
				return -EINVAL;
		} else if (kind != BTF_KIND_PTR || size != sizeof(void *)) {
			return -EINVAL;
		}
		field->offset = bytes;
		field->struct_size = type->size;
		pr_info("BTF: resolved %s.%s at %u, struct size %u\n",
			structure, member, bytes, type->size);
		return 0;
	}
	return -ENOENT;
}
#endif

static u32 inode_blob_offset __ro_after_init;

int yz_selinux_inode_init(const struct lsm_blob_sizes *blob_sizes)
{
#ifdef CONFIG_DEBUG_INFO_BTF
	struct yz_btf_field blob_field, inode_field, sid_field;
#endif
	s32 blob_offset;
	int ret;
	u32 field_offset;

	if (!blob_sizes)
		return -EINVAL;
#ifdef CONFIG_DEBUG_INFO_BTF
	ret = yz_btf_field("lsm_blob_sizes", "lbs_inode", BTF_KIND_INT,
			   sizeof(int), &blob_field);
	if (ret)
		goto fail;
	ret = yz_btf_field("inode_security_struct", "inode", BTF_KIND_PTR,
			   sizeof(void *), &inode_field);
	if (ret)
		goto fail;
	ret = yz_btf_field("inode_security_struct", "sid", BTF_KIND_INT,
			   sizeof(u32), &sid_field);
	if (ret)
		goto fail;
	if (inode_field.offset !=
		offsetof(struct inode_security_struct, inode) ||
	    sid_field.offset != offsetof(struct inode_security_struct, sid)) {
		ret = -EINVAL;
		goto fail;
	}
	field_offset = blob_field.offset;
#else
	field_offset = offsetof(struct lsm_blob_sizes, lbs_inode);
#endif
	ret = yz_kernel_read_nofault(&blob_offset,
				     (unsigned long)blob_sizes + field_offset,
				     sizeof(blob_offset))
		  ? 0
		  : -EFAULT;
	if (ret) {
		pr_err("selinux_blob_sizes.lbs_inode unreadable (%d)\n", ret);
		goto fail;
	}
	if (blob_offset < 0 ||
	    blob_offset % __alignof__(struct inode_security_struct)) {
		ret = -EINVAL;
		goto fail;
	}
	inode_blob_offset = blob_offset;
	pr_info("yukizygisk: SELinux lbs_inode@%u, blob=%u\n", field_offset,
		inode_blob_offset);
	return 0;
fail:
	pr_err("yukizygisk: SELinux inode layout unavailable (%d)\n", ret);
	return ret;
}

struct inode_security_struct *yz_selinux_inode(const struct inode *inode)
{
	struct inode_security_struct *security;
	struct inode *owner;
	int ret;

	if (!inode || !inode->i_security)
		return NULL;
	security = (void *)((char *)inode->i_security + inode_blob_offset);
	// Validate the back pointer before callers read or overwrite the SID.
	ret = yz_kernel_read_nofault(&owner, (unsigned long)&security->inode,
				     sizeof(owner))
		  ? 0
		  : -EFAULT;
	if (ret || owner != inode) {
		pr_err_ratelimited(
		    "SELinux inode security layout mismatch (%d)\n", ret);
		return ERR_PTR(ret ? ret : -EINVAL);
	}
	return security;
}
