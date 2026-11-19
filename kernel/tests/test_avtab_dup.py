# SPDX-License-Identifier: GPL-2.0-only
"""Exercise AVTAB-only policy duplication and node removal."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


def function(source, signature):
    start = source.index(signature)
    return source[start:source.index('\n}', start) + 2] + '\n'


class AvtabDupTest(unittest.TestCase):
    def test_dup_avtab_rehash_order_and_remove_fallback(self):
        root = Path(__file__).resolve().parents[2]
        policy = (root / 'kernel/host/policy.c').read_text()
        fixture = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

#define AVTAB_ALLOWED        0x0001
#define AVTAB_AUDITALLOW     0x0002
#define AVTAB_XPERMS_ALLOWED 0x0100
#define AVTAB_XPERMS         0x0700
#define AVTAB_ENABLED        0x8000
#define AVTAB_ENABLED_OLD    0x80000000
#define YZ_POLICY_AVTAB_ALLOWED_SIZE (4 * sizeof(u16) + sizeof(u32))

#define READ_ONCE(x) (x)
#define GFP_KERNEL 0
#define max(a, b) ((a) > (b) ? (a) : (b))
#define ERR_PTR(err) ((void *)(intptr_t)(err))
#define PTR_ERR(ptr) ((intptr_t)(ptr))
#define IS_ERR(ptr) ((uintptr_t)(ptr) >= (uintptr_t)-4095)
#define cond_resched() (++resched_calls)
#define vmalloc(n) malloc(n)
#define vfree(p) free(p)
#define kfree(p) free(p)

static void *kmemdup(const void *src, size_t len, int flags)
{
    void *dst = malloc(len);

    (void)flags;
    if (dst)
        memcpy(dst, src, len);
    return dst;
}

struct avtab_key {
    u16 source_type;
    u16 target_type;
    u16 target_class;
    u16 specified;
};

struct avtab_extended_perms {
    u8 specified;
    u8 driver;
    u32 perms[8];
};

struct avtab_datum {
    union {
        u32 data;
        struct avtab_extended_perms *xperms;
    } u;
};

struct avtab_node {
    struct avtab_key key;
    struct avtab_datum datum;
    struct avtab_node *next;
};

struct avtab {
    struct avtab_node **htable;
    u32 nel;
    u32 nslot;
    u32 mask;
};

struct symtab {
    u32 nprim;
};

struct policydb {
    size_t len;
    struct symtab p_types;
    struct avtab te_avtab;
};

struct selinux_policy {
    u32 latest_granting;
    struct policydb policydb;
};

struct policy_file {
    void *data;
    size_t len;
};

static struct selinux_policy *yz_sized_policy;
static u32 yz_sized_seqno;
static u32 yz_sized_nel;
static u32 yz_sized_types;
static size_t serialized_bytes = 256;
static unsigned write_calls;
static unsigned resched_calls;
static u32 forced_nslot;
static int fail_alloc_at;
static int alloc_calls;
static int fail_insert_at;
static int insert_calls;

static bool policydb_snapshot_capacity(const struct policydb *p, size_t *cap)
{
    (void)p;
    *cap = serialized_bytes + 16;
    return true;
}

static int yz_call_policydb_write(struct policydb *db, struct policy_file *fp)
{
    (void)db;
    ++write_calls;
    fp->len -= serialized_bytes;
    return 0;
}

static inline int avtab_hash(const struct avtab_key *keyp, u32 mask)
{
    return (keyp->target_class + (keyp->target_type << 2) +
            (keyp->source_type << 9)) & mask;
}

static int yz_call_avtab_alloc(struct avtab *h, u32 nrules)
{
    u32 nslot = forced_nslot ? forced_nslot : 1;

    ++alloc_calls;
    if (fail_alloc_at && alloc_calls == fail_alloc_at)
        return -ENOMEM;
    if (!forced_nslot) {
        while (nslot < nrules && nslot < 1024)
            nslot <<= 1;
    }
    h->htable = calloc(nslot, sizeof(*h->htable));
    if (!h->htable)
        return -ENOMEM;
    h->nel = 0;
    h->nslot = nslot;
    h->mask = nslot - 1;
    return 0;
}

static void yz_call_avtab_destroy(struct avtab *h)
{
    for (u32 i = 0; i < h->nslot; ++i) {
        struct avtab_node *cur = h->htable[i];

        while (cur) {
            struct avtab_node *next = cur->next;

            if (cur->key.specified & AVTAB_XPERMS)
                free(cur->datum.u.xperms);
            free(cur);
            cur = next;
        }
    }
    free(h->htable);
    h->htable = NULL;
    h->nslot = 0;
    h->mask = 0;
    h->nel = 0;
}

static struct avtab_node *avtab_insert_node(struct avtab *h, int hvalue,
                                            struct avtab_node *prev,
                                            const struct avtab_key *key,
                                            const struct avtab_datum *datum)
{
    struct avtab_node *newnode;

    ++insert_calls;
    if (fail_insert_at && insert_calls == fail_insert_at)
        return NULL;
    newnode = calloc(1, sizeof(*newnode));
    if (!newnode)
        return NULL;
    newnode->key = *key;
    if (key->specified & AVTAB_XPERMS) {
        newnode->datum.u.xperms = calloc(1, sizeof(*newnode->datum.u.xperms));
        if (!newnode->datum.u.xperms) {
            free(newnode);
            return NULL;
        }
        *newnode->datum.u.xperms = *datum->u.xperms;
    } else {
        newnode->datum = *datum;
    }
    if (prev) {
        newnode->next = prev->next;
        prev->next = newnode;
    } else {
        newnode->next = h->htable[hvalue];
        h->htable[hvalue] = newnode;
    }
    h->nel++;
    return newnode;
}

static struct avtab_node *
yz_call_avtab_insert_nonunique(struct avtab *h, struct avtab_key *key,
                               struct avtab_datum *datum)
{
    int hvalue;
    struct avtab_node *prev, *cur;
    u16 specified = key->specified & ~(AVTAB_ENABLED | AVTAB_ENABLED_OLD);

    if (!h || !h->nslot || h->nel == UINT32_MAX)
        return NULL;
    hvalue = avtab_hash(key, h->mask);
    for (prev = NULL, cur = h->htable[hvalue]; cur;
         prev = cur, cur = cur->next) {
        if (key->source_type == cur->key.source_type &&
            key->target_type == cur->key.target_type &&
            key->target_class == cur->key.target_class &&
            (specified & cur->key.specified))
            break;
        if (key->source_type < cur->key.source_type)
            break;
        if (key->source_type == cur->key.source_type &&
            key->target_type < cur->key.target_type)
            break;
        if (key->source_type == cur->key.source_type &&
            key->target_type == cur->key.target_type &&
            key->target_class < cur->key.target_class)
            break;
    }
    return avtab_insert_node(h, hvalue, prev, key, datum);
}
'''
        fixture += function(policy, 'static int yz_policy_remove_avtab_node(')
        fixture += function(policy, 'static int yz_policy_serialized_len(')
        fixture += function(policy, 'static struct selinux_policy *yz_policy_dup_avtab(')
        fixture += r'''
static void add_data(struct avtab *tab, u16 s, u16 t, u16 c, u16 spec, u32 data)
{
    struct avtab_key key = {s, t, c, spec};
    struct avtab_datum datum = {.u.data = data};

    assert(yz_call_avtab_insert_nonunique(tab, &key, &datum) != NULL);
}

static void add_xperm(struct avtab *tab, u16 s, u16 t, u16 c, u8 driver, u32 word)
{
    struct avtab_key key = {s, t, c, AVTAB_XPERMS_ALLOWED};
    struct avtab_extended_perms xp = {.specified = 1, .driver = driver, .perms = {word}};
    struct avtab_datum datum = {.u.xperms = &xp};

    assert(yz_call_avtab_insert_nonunique(tab, &key, &datum) != NULL);
}

static void verify_bucket_order_and_siblings(const struct avtab *tab, u16 s, u16 t, u16 c,
                                             const u8 *expected_drivers, size_t count)
{
    int bucket = avtab_hash(&(struct avtab_key){s, t, c, AVTAB_ALLOWED}, tab->mask);
    struct avtab_node *cur = tab->htable[bucket];
    struct avtab_node *prev = NULL;
    size_t seen = 0;

    for (; cur; prev = cur, cur = cur->next) {
        if (prev) {
            assert(prev->key.source_type < cur->key.source_type ||
                   (prev->key.source_type == cur->key.source_type &&
                    (prev->key.target_type < cur->key.target_type ||
                     (prev->key.target_type == cur->key.target_type &&
                      prev->key.target_class <= cur->key.target_class))));
        }
        if (cur->key.source_type == s && cur->key.target_type == t &&
            cur->key.target_class == c && (cur->key.specified & AVTAB_XPERMS)) {
            assert(seen < count);
            assert(cur->datum.u.xperms->driver == expected_drivers[seen]);
            seen++;
        }
    }
    assert(seen == count);
}

int main(void)
{
    struct selinux_policy src = {.latest_granting = 7, .policydb = {.len = 100, .p_types = {12}}};
    const u8 drivers[] = {0x53, 0x52, 0x51};

    forced_nslot = 8;
    assert(yz_call_avtab_alloc(&src.policydb.te_avtab, 8) == 0);
    /* Populate colliding triples across buckets plus equal-key xperm siblings. */
    add_data(&src.policydb.te_avtab, 1, 2, 1, AVTAB_ALLOWED, 0x11);
    add_data(&src.policydb.te_avtab, 5, 2, 1, AVTAB_ALLOWED, 0x55);
    add_data(&src.policydb.te_avtab, 3, 2, 1, AVTAB_ALLOWED, 0x33);
    add_data(&src.policydb.te_avtab, 3, 2, 1, AVTAB_AUDITALLOW, 0x44);
    /* insert_nonunique prepends before matching specified, so order in src is 0x53, 0x52, 0x51. */
    add_xperm(&src.policydb.te_avtab, 3, 2, 1, 0x51, 1);
    add_xperm(&src.policydb.te_avtab, 3, 2, 1, 0x52, 2);
    add_xperm(&src.policydb.te_avtab, 3, 2, 1, 0x53, 3);
    add_data(&src.policydb.te_avtab, 9, 4, 2, AVTAB_ALLOWED, 0x99);
    assert(src.policydb.te_avtab.nel == 8);

    /* 1. Same nslot copy preserves exact order, length, and deep-copies xperms. */
    forced_nslot = 8;
    resched_calls = 0;
    struct selinux_policy *same = yz_policy_dup_avtab(&src);
    assert(!IS_ERR(same) && resched_calls > 0);
    assert(same->policydb.te_avtab.nel == src.policydb.te_avtab.nel);
    assert(same->policydb.len == serialized_bytes && write_calls == 1);
    verify_bucket_order_and_siblings(&same->policydb.te_avtab, 3, 2, 1, drivers, 3);
    /* Mutating source xperms must not affect destination copy. */
    int b = avtab_hash(&(struct avtab_key){3, 2, 1, AVTAB_XPERMS_ALLOWED}, src.policydb.te_avtab.mask);
    for (struct avtab_node *n = src.policydb.te_avtab.htable[b]; n; n = n->next) {
        if (n->key.specified & AVTAB_XPERMS)
            n->datum.u.xperms->driver ^= 0xff;
    }
    verify_bucket_order_and_siblings(&same->policydb.te_avtab, 3, 2, 1, drivers, 3);
    for (struct avtab_node *n = src.policydb.te_avtab.htable[b]; n; n = n->next) {
        if (n->key.specified & AVTAB_XPERMS)
            n->datum.u.xperms->driver ^= 0xff;
    }

    /* 2. Cache hit skips policydb_write; nel/types drift invalidates cache. */
    yz_sized_policy = same;
    yz_sized_seqno = same->latest_granting;
    yz_sized_nel = same->policydb.te_avtab.nel;
    yz_sized_types = same->policydb.p_types.nprim;
    size_t cached_len = 0;
    assert(yz_policy_serialized_len(same, &cached_len) == 0 && cached_len == serialized_bytes);
    assert(write_calls == 1);
    same->policydb.te_avtab.nel++;
    serialized_bytes = 300;
    assert(yz_policy_serialized_len(same, &cached_len) == 0 && cached_len == 300 && write_calls == 2);
    same->policydb.te_avtab.nel--;
    same->policydb.p_types.nprim++;
    serialized_bytes = 340;
    assert(yz_policy_serialized_len(same, &cached_len) == 0 && cached_len == 340 && write_calls == 3);
    same->policydb.p_types.nprim--;
    yz_sized_policy = NULL;

    /* 3. Shrinking nslot (8 -> 2) and growing nslot (8 -> 32) preserve order & siblings. */
    for (u32 slots = 2; slots <= 32; slots *= 16) {
        forced_nslot = slots;
        struct selinux_policy *rehashed = yz_policy_dup_avtab(&src);
        assert(!IS_ERR(rehashed));
        assert(rehashed->policydb.te_avtab.nel == src.policydb.te_avtab.nel);
        verify_bucket_order_and_siblings(&rehashed->policydb.te_avtab, 3, 2, 1, drivers, 3);
        yz_call_avtab_destroy(&rehashed->policydb.te_avtab);
        free(rehashed);
    }

    /* 4. OOM during insert frees partial table cleanly (checked by ASan). */
    forced_nslot = 4;
    insert_calls = 0;
    fail_insert_at = 5;
    struct selinux_policy *oom = yz_policy_dup_avtab(&src);
    assert(IS_ERR(oom) && PTR_ERR(oom) == -ENOMEM);
    fail_insert_at = 0;

    /* 5. NULL xperms returns -EINVAL and cleans up partial table. */
    struct avtab_node *xnode = NULL;
    for (struct avtab_node *n = src.policydb.te_avtab.htable[b]; n; n = n->next) {
        if (n->key.specified & AVTAB_XPERMS) {
            xnode = n;
            break;
        }
    }
    assert(xnode != NULL);
    struct avtab_extended_perms *saved_xp = xnode->datum.u.xperms;
    xnode->datum.u.xperms = NULL;
    struct selinux_policy *bad = yz_policy_dup_avtab(&src);
    assert(IS_ERR(bad) && PTR_ERR(bad) == -EINVAL);
    xnode->datum.u.xperms = saved_xp;

    /* 6. yz_policy_remove_avtab_node: -ENOMEM keeps empty node & len; normal removes & shrinks len. */
    forced_nslot = 1;
    struct avtab_node *victim = same->policydb.te_avtab.htable[0];
    for (u32 i = 0; !victim && i < same->policydb.te_avtab.nslot; ++i)
        victim = same->policydb.te_avtab.htable[i];
    assert(victim != NULL);
    u32 nel_before = same->policydb.te_avtab.nel;
    size_t len_before = same->policydb.len;
    alloc_calls = 0;
    fail_alloc_at = 1;
    assert(yz_policy_remove_avtab_node(&same->policydb, victim) == 0);
    assert(same->policydb.te_avtab.nel == nel_before && same->policydb.len == len_before);
    fail_alloc_at = 0;
    assert(yz_policy_remove_avtab_node(&same->policydb, victim) == 0);
    assert(same->policydb.te_avtab.nel == nel_before - 1);
    assert(same->policydb.len == len_before - YZ_POLICY_AVTAB_ALLOWED_SIZE);

    yz_call_avtab_destroy(&same->policydb.te_avtab);
    free(same);
    yz_call_avtab_destroy(&src.policydb.te_avtab);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as work:
            binary = Path(work) / 'avtab-dup'
            subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-g', '-O1',
                            '-Wall', '-Werror', '-fsanitize=address,undefined',
                            '-x', 'c', '-', '-o', str(binary)],
                           input=fixture, text=True, check=True)
            subprocess.run([str(binary)], check=True)


if __name__ == '__main__':
    unittest.main()
