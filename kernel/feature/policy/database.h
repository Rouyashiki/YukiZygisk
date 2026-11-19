static inline bool yz_fixed_has_bit(const struct ebitmap *map, u32 bit)
{
	struct ebitmap_node *node;

	if (bit >= ebitmap_length(map))
		return false;
	for (node = map->node; node && node->startbit <= bit;
	     node = node->next) {
		if (bit - node->startbit < EBITMAP_SIZE)
			return ebitmap_node_get_bit(node, bit);
	}
	return false;
}

struct yz_fixed_rule {
	const char *source;
	const char *target;
	const char *class_name;
	const char *permission;
};

static const struct yz_fixed_rule yz_fixed_rules[] = {
#include "policy/rules.h"
};

static int yz_fixed_verify_file_type(struct policydb *db)
{
	struct type_datum *type =
	    yz_fp_search(&db->p_types, YZ_FIXED_FILE_TYPE);
	struct type_datum *file_attr = yz_fp_search(&db->p_types, "file_type");
	struct type_datum *trusted =
	    yz_fp_search(&db->p_types, "mlstrustedobject");
	struct type_datum *domain = yz_fp_search(&db->p_types, "domain");
	struct ebitmap_node *node;
	struct ebitmap *map;
	u32 bit, members = 0;

	if (!file_attr || !file_attr->attribute || !trusted ||
	    !trusted->attribute || !domain || !domain->attribute ||
	    !domain->value || domain->value > db->p_types.nprim ||
	    !db->sym_val_to_name[SYM_TYPES][domain->value - 1] ||
	    strcmp(db->sym_val_to_name[SYM_TYPES][domain->value - 1], "domain"))
		return -EINVAL;
	if (!type)
		return -ENOENT;
	if (type->attribute || !type->primary || !type->value ||
	    type->value > db->p_types.nprim ||
	    !db->sym_val_to_name[SYM_TYPES][type->value - 1] ||
	    strcmp(db->sym_val_to_name[SYM_TYPES][type->value - 1],
		   YZ_FIXED_FILE_TYPE))
		return -EEXIST;

	/* An additional attribute can grant access through unrelated rules. */
	map = &db->type_attr_map_array[type->value - 1];
	ebitmap_for_each_positive_bit(map, node, bit)
	{
		if (bit != type->value - 1 && bit != file_attr->value - 1 &&
		    bit != trusted->value - 1)
			return -EEXIST;
		members++;
	}
	return members == 3 ? 0 : -EEXIST;
}

static const char *yz_fixed_resolve(const char *name, const char *daemon)
{
	if (!strcmp(name, "$daemon"))
		return daemon;
	return name;
}

static int yz_fixed_verify_rules(struct policydb *db,
				 const struct yz_fixed_policy_config *config,
				 const char *daemon,
				 struct yz_fixed_policy_status *detail)
{
	struct type_datum *daemon_type;
	size_t j;
	int ret;

	(void)config;
	ret = yz_fixed_verify_file_type(db);
	if (ret && (daemon || ret != -ENOENT))
		return ret;
	/* Preparation checks symbol ownership before the host adds any AVs. */
	if (!daemon)
		return 0;
	daemon_type = yz_fp_search(&db->p_types, daemon);
	if (!daemon_type || !daemon_type->primary || daemon_type->attribute ||
	    !daemon_type->value || daemon_type->value > db->p_types.nprim ||
	    !db->sym_val_to_name[SYM_TYPES][daemon_type->value - 1] ||
	    strcmp(db->sym_val_to_name[SYM_TYPES][daemon_type->value - 1],
		   daemon))
		return -EINVAL;
	for (j = 0; j < ARRAY_SIZE(yz_fixed_rules); j++) {
		const struct yz_fixed_rule *rule = &yz_fixed_rules[j];
		const char *source = yz_fixed_resolve(rule->source, daemon);
		const char *dest = yz_fixed_resolve(rule->target, daemon);

		/* Only the class absent from older policies is optional. */
		if (!strcmp(rule->class_name, "memfd_file") &&
		    !yz_fp_search(&db->p_classes, rule->class_name))
			continue;
		ret = yz_fp_has_rule(db, source, dest, rule->class_name,
				     rule->permission);
		if (!ret)
			continue;
		if (detail) {
			struct class_datum *cls =
			    yz_fp_search(&db->p_classes, rule->class_name);
			u32 av = yz_policy_perm_mask(cls, rule->permission);

			yz_fixed_set_missing(detail, source, dest,
					     rule->class_name, av);
		}
		return ret;
	}
	return 0;
}
