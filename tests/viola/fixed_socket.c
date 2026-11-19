/* SPDX-License-Identifier: GPL-2.0-only */
/* Exercise the production verifier against a small host policy. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

typedef uint16_t u16;
typedef uint32_t u32;
#define U16_MAX UINT16_MAX
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define hweight32 __builtin_popcount
#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))
#define CEXPR_MAXDEPTH 5
enum { CEXPR_ATTR, CEXPR_NAMES, CEXPR_NOT, CEXPR_AND, CEXPR_OR };
enum { CEXPR_TYPE = 1, CEXPR_TARGET = 2, CEXPR_L1L2 = 4 };
enum { CEXPR_EQ, CEXPR_NEQ, CEXPR_DOM, CEXPR_DOMBY, CEXPR_INCOMP };
enum {
    DEFAULT_SOURCE_LOW = 1,
    DEFAULT_SOURCE_LOW_HIGH = 3,
    DEFAULT_TARGET_LOW = 4,
    DEFAULT_TARGET_LOW_HIGH = 6
};
enum { APP = 1, ISOLATED, APP_ZYGOTE, WEBVIEW_ZYGOTE, DAEMON, APPS, SERVERS, TYPES };
struct ebitmap {
    unsigned bits;
};
struct ebitmap_node {
    int unused;
};
#define yz_fixed_has_bit(map, n) (((map)->bits >> (n)) & 1U)
#define ebitmap_for_each_positive_bit(map, node, bit)                                          \
    for ((void)sizeof(node), (bit) = 0; (bit) < TYPES - 1; ++(bit))                            \
        if (yz_fixed_has_bit(map, bit))
struct constraint_expr {
    int expr_type, attr, op;
    struct ebitmap names;
    struct constraint_expr *next;
};
struct constraint_node {
    u32 permissions;
    struct constraint_expr *expr;
    struct constraint_node *next;
};
struct type_datum {
    unsigned value, attribute, bounds;
};
struct class_datum {
    unsigned value, default_range;
    struct constraint_node *constraints;
};
struct avtab_key {
    u16 source_type, target_type, target_class, specified;
};
enum { AVTAB_TRANSITION = 16 };
struct avtab_node {
    struct {
        union {
            u32 data;
        } u;
    } datum;
};
struct avtab {
    struct avtab_node *nodes[TYPES];
};
struct range_trans {
    u32 source_type, target_type, target_class;
};
struct hashtab_node {
    struct range_trans *key;
    struct hashtab_node *next;
};
struct yz_policy_key {
    u16 src_type, tgt_type, tclass;
};
struct policydb {
    struct {
        unsigned nprim;
    } p_types, p_classes;
    struct {
        unsigned size;
        struct hashtab_node *htable[1];
    } range_tr;
    struct ebitmap type_attr_map_array[TYPES - 1];
    struct type_datum *type_val_to_struct[TYPES - 1];
    struct avtab te_avtab, te_cond_avtab;
    u32 allowed[TYPES][TYPES];
};
static struct type_datum types[TYPES];
static struct class_datum socket_class = {.value = 1};
static const char *const perms[] = {"create", "connect", "getopt",    "setopt",
                                    "read",   "write",   "connectto", "bind",
                                    "listen", "accept",  "getattr"};
static const char *const yz_runtime_socket_perms[] = {"read", "write", "connectto", "getopt",
                                                      "getattr"};
static const char *absent_perm;
static const char *absent_type;
static u32 yz_policy_perm_mask(struct class_datum *cls, const char *name) {
    assert(cls == &socket_class);
    for (unsigned i = 0; i < ARRAY_SIZE(perms); ++i)
        if (!strcmp(perms[i], name) && (!absent_perm || strcmp(absent_perm, name)))
            return 1U << i;
    return 0;
}
static u32 yz_policy_required_av(struct class_datum *cls, const char *const *names,
                                 size_t count) {
    u32 av = 0;
    for (size_t i = 0; i < count; ++i)
        av |= yz_policy_perm_mask(cls, names[i]);
    return av;
}
static void *yz_call_symtab_search(void *table, const char *name) {
    if (absent_type && !strcmp(name, absent_type))
        return NULL;
    if (!strcmp(name, "appdomain"))
        return &types[APPS];
    if (!strcmp(name, "isolated_app"))
        return &types[ISOLATED];
    if (!strcmp(name, "app_zygote"))
        return &types[APP_ZYGOTE];
    if (!strcmp(name, "webview_zygote"))
        return &types[WEBVIEW_ZYGOTE];
    return !strcmp(name, "unix_stream_socket") ? &socket_class : NULL;
}
static struct avtab_node *yz_call_avtab_search_node(struct avtab *table,
                                                    struct avtab_key *key) {
    assert(key->source_type == key->target_type && key->specified == AVTAB_TRANSITION);
    return table->nodes[key->source_type];
}
static u32 yz_policy_direct_allowed_av_locked(struct policydb *db,
                                              const struct yz_policy_key *key) {
    return db->allowed[key->src_type][key->tgt_type];
}
#include "kernel/feature/policy/mount_route.h"

int main(void) {
    struct policydb db = {.p_types.nprim = TYPES - 1};
    const u32 all = (1U << ARRAY_SIZE(perms)) - 1;
    for (unsigned i = APP; i < TYPES; ++i) {
        types[i] = (struct type_datum){.value = i, .attribute = i >= APPS};
        db.type_val_to_struct[i - 1] = &types[i];
        db.type_attr_map_array[i - 1].bits = 1U << (i - 1);
    }
    db.type_attr_map_array[APP - 1].bits |= 1U << (APPS - 1);
    db.type_attr_map_array[DAEMON - 1].bits |= 1U << (SERVERS - 1);
    db.allowed[APP][APP] = db.allowed[ISOLATED][ISOLATED] = all;
    db.allowed[APP][SERVERS] = db.allowed[ISOLATED][SERVERS] = all;
    db.allowed[APP_ZYGOTE][APP_ZYGOTE] = db.allowed[WEBVIEW_ZYGOTE][WEBVIEW_ZYGOTE] = all;
    db.allowed[APP_ZYGOTE][SERVERS] = db.allowed[WEBVIEW_ZYGOTE][SERVERS] = all;
    db.allowed[DAEMON][DAEMON] = all;
    assert(yz_mount_host_allows_app_connect(&db, DAEMON));
    const struct {
        unsigned source, target;
        const char *permission;
    } required[] = {
        {APP, APP, "create"},        {ISOLATED, ISOLATED, "connect"},
        {APP, APP, "getopt"},        {ISOLATED, ISOLATED, "setopt"},
        {APP, APP, "read"},          {ISOLATED, ISOLATED, "write"},
        {APP, SERVERS, "connectto"}, {ISOLATED, SERVERS, "connectto"},
        {APP_ZYGOTE, APP_ZYGOTE, "create"}, {WEBVIEW_ZYGOTE, WEBVIEW_ZYGOTE, "write"},
        {APP_ZYGOTE, SERVERS, "connectto"}, {WEBVIEW_ZYGOTE, SERVERS, "connectto"},
        {DAEMON, DAEMON, "create"},  {DAEMON, DAEMON, "bind"},
        {DAEMON, DAEMON, "listen"},  {DAEMON, DAEMON, "accept"},
        {DAEMON, DAEMON, "getopt"},  {DAEMON, DAEMON, "read"},
        {DAEMON, DAEMON, "write"},
    };
    for (unsigned i = 0; i < ARRAY_SIZE(required); ++i) {
        u32 *grant = &db.allowed[required[i].source][required[i].target];
        u32 bit = yz_policy_perm_mask(&socket_class, required[i].permission);
        *grant &= ~bit;
        assert(!yz_mount_host_allows_app_connect(&db, DAEMON));
        *grant |= bit;
    }
    db.allowed[WEBVIEW_ZYGOTE][SERVERS] = 0;
    absent_type = "webview_zygote";
    assert(yz_mount_host_allows_app_connect(&db, DAEMON));
    absent_type = NULL;
    db.allowed[WEBVIEW_ZYGOTE][SERVERS] = all;
    types[APP_ZYGOTE].attribute = true;
    assert(!yz_mount_host_allows_app_connect(&db, DAEMON));
    types[APP_ZYGOTE].attribute = false;
    db.type_val_to_struct[DAEMON - 1] = NULL;
    assert(!yz_mount_host_allows_app_connect(&db, DAEMON));
    db.type_val_to_struct[DAEMON - 1] = &types[DAEMON];
    absent_perm = "getopt";
    assert(!yz_mount_host_allows_app_connect(&db, DAEMON));
    absent_perm = NULL;
    /* Concrete (app, daemon) connectto can be left by temporary runtime setup. */
    db.allowed[APP][DAEMON] = all;
    db.allowed[APP][SERVERS] &= ~yz_policy_perm_mask(&socket_class, "connectto");
    assert(!yz_mount_host_allows_app_connect(&db, DAEMON));
    db.allowed[APP][SERVERS] = all;
    db.allowed[APP][DAEMON] = 0;
    struct avtab_node trans = {.datum.u.data = DAEMON};
    db.te_cond_avtab.nodes[APP] = &trans;
    assert(!yz_mount_host_allows_app_connect(&db, DAEMON));
    db.te_cond_avtab.nodes[APP] = NULL;
    struct constraint_expr levels = {
        .expr_type = CEXPR_ATTR, .attr = CEXPR_L1L2, .op = CEXPR_EQ};
    struct constraint_node c = {.permissions = yz_policy_perm_mask(&socket_class, "create"),
                                .expr = &levels};
    socket_class.constraints = &c;
    assert(yz_mount_host_allows_app_connect(&db, DAEMON));
    struct range_trans range = {APP, APP, 2};
    struct hashtab_node node = {.key = &range};
    db.range_tr.size = 1;
    db.range_tr.htable[0] = &node;
    assert(yz_mount_host_allows_app_connect(&db, DAEMON));
    range.target_class = socket_class.value;
    assert(!yz_mount_host_allows_app_connect(&db, DAEMON));
    db.range_tr.size = 0;
    c.permissions = yz_policy_perm_mask(&socket_class, "read");
    assert(!yz_mount_host_allows_app_connect(&db, DAEMON));
    return 0;
}
