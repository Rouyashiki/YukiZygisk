/* SPDX-License-Identifier: GPL-2.0-only */

/* Only facts shared by every possible client context can prove a route. */
static bool yz_socket_constraint(const struct constraint_expr *expr, u32 source,
				 u32 target, bool same_low)
{
	/* AND takes the lesser value, OR the greater, and NOT negates it. */
	enum { YZ_NEVER = -1, YZ_UNKNOWN, YZ_ALWAYS };
	int stack[CEXPR_MAXDEPTH];
	unsigned int depth = 0;

	for (; expr; expr = expr->next) {
		switch (expr->expr_type) {
		case CEXPR_ATTR:
		case CEXPR_NAMES:
			if (depth == ARRAY_SIZE(stack))
				return false;
			stack[depth++] = YZ_UNKNOWN;
			if (expr->expr_type == CEXPR_NAMES &&
			    (expr->attr == CEXPR_TYPE ||
			     expr->attr == (CEXPR_TARGET | CEXPR_TYPE)) &&
			    (expr->op == CEXPR_EQ || expr->op == CEXPR_NEQ)) {
				u32 type =
				    expr->attr == CEXPR_TYPE ? source : target;
				bool member =
				    yz_fixed_has_bit(&expr->names, type - 1);

				stack[depth - 1] = member == (expr->op == CEXPR_EQ)
						       ? YZ_ALWAYS : YZ_NEVER;
			} else if (same_low && expr->expr_type == CEXPR_ATTR &&
				   expr->attr == CEXPR_L1L2) {
				if (expr->op == CEXPR_EQ ||
				    expr->op == CEXPR_DOM ||
				    expr->op == CEXPR_DOMBY)
					stack[depth - 1] = YZ_ALWAYS;
				else if (expr->op == CEXPR_NEQ ||
					 expr->op == CEXPR_INCOMP)
					stack[depth - 1] = YZ_NEVER;
			}
			break;
		case CEXPR_NOT:
			if (!depth)
				return false;
			stack[depth - 1] = -stack[depth - 1];
			break;
		case CEXPR_AND:
		case CEXPR_OR:
			if (depth < 2)
				return false;
			depth--;
			if (expr->expr_type == CEXPR_AND)
				stack[depth - 1] = min(stack[depth - 1], stack[depth]);
			else
				stack[depth - 1] = max(stack[depth - 1], stack[depth]);
			break;
		default:
			return false;
		}
	}
	return depth == 1 && stack[0] == YZ_ALWAYS;
}

static bool yz_socket_uses_owner_type(struct policydb *db, u32 owner, u16 cls)
{
	struct avtab_key key = {
	    .source_type = owner,
	    .target_type = owner,
	    .target_class = cls,
	    .specified = AVTAB_TRANSITION,
	};
	struct avtab_node *node =
	    yz_call_avtab_search_node(&db->te_avtab, &key);

	if (node)
		return node->datum.u.data == owner;
	return !yz_call_avtab_search_node(&db->te_cond_avtab, &key);
}

struct yz_socket_range_scan {
	bool default_low;
	bool overflow;
	unsigned int count;
	u32 owners[16];
};

static void yz_socket_range_scan_init(struct yz_socket_range_scan *scan,
				      struct policydb *db,
				      struct class_datum *cls)
{
	const void *htable = db->range_tr.htable;
	struct hashtab_node *node;
	u32 i;

	memset(scan, 0, sizeof(*scan));
	if (cls->default_range && cls->default_range != DEFAULT_SOURCE_LOW &&
	    cls->default_range != DEFAULT_SOURCE_LOW_HIGH &&
	    cls->default_range != DEFAULT_TARGET_LOW &&
	    cls->default_range != DEFAULT_TARGET_LOW_HIGH)
		return;
	scan->default_low = true;
	if (!htable)
		return;
	for (i = 0; i < db->range_tr.size; i++) {
		for (node = db->range_tr.htable[i]; node; node = node->next) {
			const struct range_trans *range = node->key;

			if (range->source_type != range->target_type ||
			    range->target_class != cls->value)
				continue;
			if (scan->count < ARRAY_SIZE(scan->owners)) {
				scan->owners[scan->count++] =
				    range->source_type;
			} else {
				scan->overflow = true;
				return;
			}
		}
	}
}

static bool yz_socket_inherits_low(const struct yz_socket_range_scan *scan,
				   struct policydb *db, struct class_datum *cls,
				   u32 owner)
{
	struct hashtab_node *node;
	unsigned int j;
	u32 i;

	if (!scan->default_low)
		return false;
	if (!scan->overflow) {
		for (j = 0; j < scan->count; j++) {
			if (scan->owners[j] == owner)
				return false;
		}
		return true;
	}
	for (i = 0; i < db->range_tr.size; i++) {
		for (node = db->range_tr.htable[i]; node; node = node->next) {
			const struct range_trans *range = node->key;

			if (range->source_type == owner &&
			    range->target_type == owner &&
			    range->target_class == cls->value)
				return false;
		}
	}
	return true;
}

static bool yz_host_socket_allows(struct policydb *db, struct class_datum *cls,
				  u32 source, u32 target, u32 required,
				  u32 temporary, bool same_low)
{
	struct type_datum *const *types = db->type_val_to_struct;
	struct constraint_node *c;
	struct ebitmap_node *sn, *tn;
	u32 s, d;

	if (!types || !types[source - 1] || types[source - 1]->bounds)
		return false;
	for (c = cls->constraints; c; c = c->next)
		if ((c->permissions & required) &&
		    !yz_socket_constraint(c->expr, source, target, same_low))
			return false;

	ebitmap_for_each_positive_bit(&db->type_attr_map_array[source - 1], sn,
				      s)
	{
		ebitmap_for_each_positive_bit(
		    &db->type_attr_map_array[target - 1], tn, d)
		{
			struct yz_policy_key key = {
			    .src_type = s + 1,
			    .tgt_type = d + 1,
			    .tclass = cls->value,
			};
			u32 av = yz_policy_direct_allowed_av_locked(db, &key);

			/* Concrete grants to the daemon can survive an LKM
			 * reload. */
			if (s + 1 == source && d + 1 == target)
				av &= ~temporary;
			required &= ~av;
			if (!required)
				return true;
		}
	}
	return false;
}

static bool yz_optional_socket_client(struct policydb *db, const char *name,
				      u32 *id)
{
	struct type_datum *type = yz_call_symtab_search(&db->p_types, name);

	*id = type ? type->value : 0;
	return !type || (!type->attribute && *id && *id <= db->p_types.nprim &&
			 db->type_val_to_struct[*id - 1] &&
			 !db->type_val_to_struct[*id - 1]->attribute);
}

static bool yz_mount_host_allows_app_connect(struct policydb *db, u32 daemon)
{
	static const char *const client_ops[] = {
	    "create", "connect", "getopt", "setopt", "read", "write",
	};
	static const char *const listener_ops[] = {"create", "bind", "listen",
						   "accept"};
	static const char *const reply_ops[] = {"getopt", "read", "write"};
	struct type_datum *apps =
	    yz_call_symtab_search(&db->p_types, "appdomain");
	struct type_datum *isolated =
	    yz_call_symtab_search(&db->p_types, "isolated_app");
	struct class_datum *cls =
	    yz_call_symtab_search(&db->p_classes, "unix_stream_socket");
	struct type_datum *const *types = db->type_val_to_struct;
	struct yz_socket_range_scan range_scan;
	u32 t, client, listener, reply, connect, temporary;
	u32 app_zygote, webview_zygote;
	bool saw_isolated = false, saw_app = false;

	if (!apps || !apps->attribute || !isolated || isolated->attribute ||
	    !cls || !daemon || daemon > db->p_types.nprim ||
	    !types || !types[daemon - 1] || types[daemon - 1]->attribute ||
	    db->p_types.nprim > U16_MAX || cls->value > U16_MAX ||
	    !yz_optional_socket_client(db, "app_zygote", &app_zygote) ||
	    !yz_optional_socket_client(db, "webview_zygote", &webview_zygote))
		return false;
	connect = yz_policy_perm_mask(cls, "connectto");
	client = yz_policy_required_av(cls, client_ops, ARRAY_SIZE(client_ops));
	listener =
	    yz_policy_required_av(cls, listener_ops, ARRAY_SIZE(listener_ops));
	reply = yz_policy_required_av(cls, reply_ops, ARRAY_SIZE(reply_ops));
	if (!connect || hweight32(client) != ARRAY_SIZE(client_ops) ||
	    hweight32(listener) != ARRAY_SIZE(listener_ops) ||
	    hweight32(reply) != ARRAY_SIZE(reply_ops))
		return false;
	temporary = yz_policy_required_av(cls, yz_runtime_socket_perms,
					  ARRAY_SIZE(yz_runtime_socket_perms));
	yz_socket_range_scan_init(&range_scan, db, cls);
	/* Domain self-socket rules compile into concrete (daemon, daemon)
	 * entries; temporary runtime setup does not grant reply perms there.
	 * The accepted socket can carry the connecting application's MLS. */
	if (!yz_socket_uses_owner_type(db, daemon, cls->value) ||
	    !yz_host_socket_allows(
		db, cls, daemon, daemon, listener, 0,
		yz_socket_inherits_low(&range_scan, db, cls, daemon)) ||
	    !yz_host_socket_allows(db, cls, daemon, daemon, reply, 0, false))
		return false;
	for (t = 0; t < db->p_types.nprim; t++) {
		struct ebitmap *sources = &db->type_attr_map_array[t];
		struct type_datum *type = db->type_val_to_struct[t];
		bool app;

		if (!type || type->attribute)
			continue;
		app = yz_fixed_has_bit(sources, apps->value - 1);
		/* Child zygotes can specialize without belonging to appdomain. */
		if (!app && t + 1 != isolated->value && t + 1 != app_zygote &&
		    t + 1 != webview_zygote)
			continue;
		saw_isolated |= t + 1 == isolated->value;
		saw_app |= app && t + 1 != isolated->value;
		if (!yz_socket_uses_owner_type(db, t + 1, cls->value) ||
		    !yz_host_socket_allows(
			db, cls, t + 1, t + 1, client, 0,
			yz_socket_inherits_low(&range_scan, db, cls, t + 1)) ||
		    !yz_host_socket_allows(db, cls, t + 1, daemon, connect,
					   temporary, false))
			return false;
	}
	return saw_app && saw_isolated;
}
