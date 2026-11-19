# SPDX-License-Identifier: Apache-2.0
"""Exercise the kernel's fixed-policy binding across SELinux policy reloads."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class FixedPolicyTests(unittest.TestCase):
    def test_public_header(self):
        include = Path(__file__).resolve().parents[2] / 'uapi'
        for compiler, language in ((os.environ.get('CC', 'cc'), 'c'),
                                   (os.environ.get('CXX', 'c++'), 'c++')):
            with self.subTest(language=language):
                subprocess.run([compiler, '-x', language, '-I', include, '-fsyntax-only', '-'],
                               input='#include <fixed_policy.h>\nstruct yz_fixed_policy_config config;\n',
                               text=True, check=True)

    def test_mprotect_skips_policy_checks_for_unrelated_mappings(self):
        root = Path(__file__).resolve().parents[2]
        source = (root / 'kernel/feature/tango.c').read_text()
        callback = source.index('static int yz_tango_mprotect_impl(')
        start = source.index('if (ret ||', callback)
        end = source.index('return ret;', start) + len('return ret;')
        fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/mman.h>
#define VM_WRITE 2
#define VM_SHARED 8
#define U32_MAX UINT32_MAX
struct mapping { unsigned vm_flags; uint64_t vm_start; int vm_file; };
static struct task { int mm, pid, tgid; } task = {1, 1, 1}, *current = &task;
static unsigned checks;
static bool target, allowed;
static bool yz_tango_leaf(int file, const char *name) { return file != 0; }
static bool yz_tango_is_process(void) { return target; }
static bool yz_tango_active(void) { ++checks; return allowed; }
static int check(int ret, const struct mapping *vma, int prot) {
''' + source[start:end] + r'''
    return 1;
}
int main(void) {
    struct mapping vma = {.vm_flags = VM_WRITE};
    assert(check(-13, &vma, PROT_READ) == -13);
    assert(!check(0, &vma, PROT_READ));
    vma.vm_file = 1;
    assert(!check(0, &vma, PROT_READ));
    target = true;
    assert(!check(0, &vma, PROT_WRITE) && checks == 0);
    assert(!check(0, &vma, PROT_READ) && checks == 1);
    allowed = true;
    assert(check(0, &vma, PROT_READ) == 1 && checks == 2);
}
'''
        with tempfile.TemporaryDirectory() as work:
            binary = Path(work) / 'mprotect-filter'
            subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Werror',
                            '-x', 'c', '-', '-o', str(binary)], input=fixture, text=True, check=True)
            subprocess.run([str(binary)], check=True)

    def test_mount_socket_permissions(self):
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as work:
            directory = Path(work)
            binary = directory / 'mount-socket'
            subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Werror',
                            '-I', str(root), str(root / 'tests/viola/fixed_socket.c'), '-o', str(binary)],
                           check=True)
            subprocess.run([str(binary)], check=True)

    def test_revalidate_bound_policy_on_reload(self):
        root = Path(__file__).resolve().parents[2]
        host = (root / 'kernel/host/policy.c').read_text()
        state = (root / 'kernel/feature/fixed_policy.c').read_text()
        rules = (root / 'kernel/feature/policy/database.h').read_text()
        access = (root / 'kernel/feature/policy/access.h').read_text()

        def function(source, signature):
            start = source.index(signature)
            return source[start:source.index('\n}', start) + 2] + '\n'

        fixture = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "kernel/uapi/fixed_policy.h"
typedef uint32_t u32;
typedef uint64_t u64;
struct notifier_block { int unused; };
#define LSM_POLICY_CHANGE 1
#define NOTIFY_DONE 0
static int yz_policy_changed(struct notifier_block *, unsigned long, void *);
#define READ_ONCE(v) (v)
#define WRITE_ONCE(v, x) ((v) = (x))
#define smp_load_acquire(p) (*(p))
#define smp_store_release(p, v) (*(p) = (v))
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)
#define rcu_dereference(v) (v)
#define rcu_access_pointer(v) (v)
#define DEFINE_SPINLOCK(name) int name __attribute__((unused))
#define noinline __attribute__((noinline))
#define rcu_dereference_protected(v, lock) (v)
#define mutex_lock(p) assert((*(p))++ == 0)
#define mutex_unlock(p) assert((*(p))-- == 1)
#define spin_lock_irqsave(p, flags) ((flags) = 0)
#define spin_unlock_irqrestore(p, flags) ((void)(flags))
#define pr_info_ratelimited(...) ((void)0)
struct cred { u32 sid; };
struct context { u32 type; };
struct symtab { u32 nprim; };
struct ebitmap_node { u32 bits; };
struct ebitmap { struct ebitmap_node node; };
#define ebitmap_for_each_positive_bit(map, nodep, bit) \
    for ((nodep) = &(map)->node, (bit) = 0; (bit) < 8; ++(bit)) if ((nodep)->bits & (1U << (bit)))
#define FILE_ATTRS ((1U << 5) | (1U << 3) | (1U << 4))
struct policydb {
    int rule_error; const char *daemon; bool socket_route;
    size_t len, encoded_size;
    struct { u32 nel; } te_avtab;
    struct symtab p_types, p_classes;
    const char *sym_val_to_name[1][6];
    struct ebitmap type_attr_map_array[6];
};
struct selinux_policy { u32 latest_granting; struct context *sidtab; struct policydb policydb; };
static struct { bool initialized; struct selinux_policy *policy; int policy_mutex; } selinux;
static struct selinux_policy *yz_sized_policy;
static u32 yz_sized_seqno, yz_sized_nel, yz_sized_types;
struct policy_file { void *data; size_t len; };
#define vmalloc(size) malloc(size)
#define vfree(data) free(data)
static bool policydb_snapshot_capacity(struct policydb *db, size_t *capacity) {
    *capacity = db->encoded_size + 8;
    return true;
}
static int yz_call_policydb_write(struct policydb *db, struct policy_file *fp) {
    fp->len -= db->encoded_size;
    return 0;
}
static int yz_fixed_lock;
static struct yz_fixed_policy_config yz_fixed_config;
static struct yz_fixed_policy_status yz_fixed_status;
static int yz_fixed_primary_error;
static unsigned checks;
static bool yz_fixed_latched, yz_mount_identity_changed, native_mounts;
static bool yz_unregister_policy_notifier, reset_during_route;
static u32 yz_mount_daemon_sid;
#define yz_selinux_state (&selinux)
#define yz_policy_base_lock() 0
#define yz_policy_base_unlock() ((void)0)
#define yz_fixed_capabilities() 0
#define yz_policy_cred_sid(cred) ((cred)->sid)
#define yz_policy_sidtab_search(table, sid) ((sid) == 17 ? (table) : NULL)
#define yz_policy_type_name_by_value(db, type) ((db)->daemon)
#define yz_host_handles_app_mounts() (native_mounts)
#define yz_host_check_app_mounts(bind, socket_route) (native_mounts)
static bool yz_mount_host_allows_app_connect(struct policydb *db, u32 type) {
    bool allowed = db->socket_route;
    if (reset_during_route) {
        reset_during_route = false;
        db->socket_route = false;
        yz_policy_changed(NULL, LSM_POLICY_CHANGE, NULL);
    }
    return allowed;
}
static int strscpy(char *out, const char *value, size_t size) {
    if (strlen(value) >= size) return -E2BIG;
    strcpy(out, value);
    return strlen(value);
}
struct type_datum { u32 value; bool primary, attribute; };
struct class_datum { u32 value; };
static void *yz_fp_search(struct symtab *table, const char *name) {
    static struct type_datum types[] = {{1, true}, {2, true}, {3, false, true},
        {4, false, true}, {5, false, true}, {6, true}};
    static struct class_datum cls = {1};
    if (!strcmp(name, "fd")) return &cls;
    if (!strcmp(name, "daemon")) return &types[0];
    if (!strcmp(name, "zygote")) return &types[1];
    if (!strcmp(name, "domain")) return &types[2];
    if (!strcmp(name, "file_type")) return &types[3];
    if (!strcmp(name, "mlstrustedobject")) return &types[4];
    if (!strcmp(name, YZ_FIXED_FILE_TYPE)) { ++checks; return &types[5]; }
    return NULL;
}
#define SYM_TYPES 0
#define ARRAY_SIZE(items) (sizeof(items)/sizeof(*(items)))
#define yz_fixed_has_bit(map, bit) (true)
#define yz_fp_has_rule(db, source, dest, cls, perm) ((db)->rule_error)
#define yz_policy_perm_mask(cls, name) ((cls) && !strcmp(name, "use") ? 4U : 0U)
struct yz_fixed_rule { const char *source, *target, *class_name, *permission; };
static const struct yz_fixed_rule yz_fixed_rules[] = {{"domain", "$daemon", "fd", "use"}};
'''
        fixture += function(state, 'void yz_fixed_set_missing(')
        fixture += function(rules, 'static int yz_fixed_verify_file_type(')
        fixture += function(rules, 'static const char *yz_fixed_resolve(')
        fixture += function(rules, 'static int yz_fixed_verify_rules(')
        cache = host.index('static const struct yz_fixed_policy_config *yz_bound_config;')
        fixture += function(host, 'static bool yz_policy_sid_has_type(')
        fixture += function(host, 'static bool yz_fixed_socket_route(')
        fixture += function(host, 'static bool yz_fixed_mount_route_locked(')
        fixture += host[cache:host.index('static int yz_fixed_capabilities(', cache)]
        fixture += function(host, 'int yz_fixed_policy_verify(')
        fixture += function(host, 'static int yz_policy_changed(')
        fixture += function(host, 'static int yz_policy_serialized_len(')
        for signature in ('int yz_fixed_policy_bind_daemon(', 'bool yz_fixed_policy_active(',
                          'bool yz_fixed_policy_ready(', 'void yz_fixed_policy_status('):
            fixture += function(state, signature)
        fixture += r'''
struct inode_security_struct { u32 sid, sclass, initialized; int lock; };
struct super_block { int s_magic; };
struct inode { int i_mode; struct super_block *i_sb; struct inode_security_struct security; };
struct file { struct inode *inode; const struct cred *f_cred; };
#define file_inode(file) ((file)->inode)
#define yz_fp_inode(inode) (&(inode)->security)
#define yz_fp_state (&selinux)
#define yz_fp_cred_sid(cred) ((cred)->sid)
#define ERR_PTR(err) ((void *)(intptr_t)(err))
#define PTR_ERR(ptr) ((intptr_t)(ptr))
#define IS_ERR(ptr) ((uintptr_t)(ptr) >= (uintptr_t)-4095)
#define IS_ERR_OR_NULL(ptr) (!(ptr) || IS_ERR(ptr))
#define SECCLASS_FILE 1
#define LABEL_INITIALIZED 1
#define TMPFS_MAGIC 42
#define yz_fixed_private_module_image(file, isec) (true)
#define spin_lock(lock) assert(selinux.policy_mutex && !(*(lock))++)
#define spin_unlock(lock) assert(selinux.policy_mutex && (*(lock))-- == 1)
static int file_checks, fd_error;
static int yz_fp_context_sid(const char *ctx, size_t len, u32 *sid, int flags) {
    assert(selinux.policy_mutex);
    *sid = selinux.policy->latest_granting;
    return 0;
}
#define GFP_KERNEL 0
static int yz_fixed_check_access_locked(struct selinux_policy *policy, u32 src, u32 dst,
                                        const char *cls, const char *const *perms, size_t count) {
    assert(selinux.policy_mutex && policy == selinux.policy);
    ++file_checks;
    if (!strcmp(cls, "fd")) return fd_error;
    bool has_exec = false;
    for (size_t i = 0; i < count; ++i)
        has_exec |= !strcmp(perms[i], "execute");
    assert(has_exec);
    assert(dst == policy->latest_granting);
    return 0;
}
'''
        for signature in ('static struct selinux_policy *yz_fixed_lock_policy(',
                          'static const char *yz_fixed_type_name(',
                          'static int yz_fixed_check_file_locked(', 'int yz_fixed_policy_label('):
            fixture += function(access, signature)
        fixture += r'''
static void check_denial(const struct yz_fixed_policy_status *status) {
    assert(!strcmp(status->source, "domain") && !strcmp(status->target, "daemon"));
    assert(!strcmp(status->class_name, "fd") && status->missing_av == 4);
}
static void expect(int error, unsigned rechecks) {
    struct yz_fixed_policy_status status;
    unsigned before = checks;
    assert(yz_fixed_policy_active());
    assert(yz_fixed_policy_ready() == !error);
    yz_fixed_policy_status(&status);
    assert(status.initialized && status.requested);
    assert(status.active == !error && status.error == error && checks == before + rechecks);
    if (error == -EACCES && selinux.policy && selinux.policy->policydb.rule_error)
        check_denial(&status);
    else
        assert(!status.source[0] && !status.missing_av);
}
int main(void) {
    struct cred daemon = {17}, other = {18};
    struct context context = {2};
    struct selinux_policy policy = {10, &context, {.daemon = "daemon",
        .p_types = {6}, .sym_val_to_name = {{"daemon", "zygote", "domain", [5] = YZ_FIXED_FILE_TYPE}},
        .type_attr_map_array = {[5].node.bits = FILE_ATTRS}}};
    struct super_block sb = {TMPFS_MAGIC};
    struct inode inode = {S_IFREG, &sb};
    struct file file = {&inode, &daemon};
    struct yz_fixed_policy_status status;
    selinux.initialized = true;
    selinux.policy = &policy;
    yz_fixed_latched = native_mounts = yz_unregister_policy_notifier = true;
    yz_fixed_status.requested = 1;
    policy.policydb.rule_error = -EACCES;
    assert(yz_fixed_policy_bind_daemon(&daemon, true) == -EACCES);
    yz_fixed_policy_status(&status);
    assert(!status.initialized && status.error == -EACCES);
    check_denial(&status);
    policy.policydb.rule_error = 0;
    assert(yz_fixed_policy_bind_daemon(&daemon, false) == 0);
    yz_fixed_policy_status(&status);
    assert(status.initialized && !status.active && status.error == -EACCES);
    assert(yz_fixed_policy_bind_daemon(&daemon, true) == 0);
    expect(0, 0);
    assert(yz_fixed_policy_label(&file, NULL) == 0 && inode.security.sid == 10 && !file_checks);
    ++policy.latest_granting;
    policy.policydb.rule_error = -EACCES;
    assert(yz_fixed_policy_label(&file, NULL) == -EACCES && inode.security.sid == 10);
    expect(-EACCES, 0);
    assert(yz_fixed_policy_bind_daemon(&daemon, true) == -EACCES);
    expect(-EACCES, 0);
    ++policy.latest_granting;
    policy.policydb.rule_error = 0;
    yz_fixed_policy_status(&status);
    assert(!status.active && status.error == -EACCES && !status.missing_av);
    assert(yz_fixed_policy_bind_daemon(&daemon, true) == 0);
    expect(0, 0);
    fd_error = -EACCES;
    assert(yz_fixed_policy_label(&file, &other) == fd_error && inode.security.sid == 10);
    assert(!selinux.policy_mutex && file_checks == 2);
    fd_error = 0;
    assert(yz_fixed_policy_label(&file, &other) == 0 && inode.security.sid == 12);
    assert(!selinux.policy_mutex && file_checks == 4);
    /* A delayed RCU reader can describe its denied generation without evicting the current one. */
    struct selinux_policy retired = policy;
    --retired.latest_granting;
    retired.policydb.rule_error = -EACCES;
    assert(yz_fixed_live_error(&retired, NULL, &status) == -EACCES);
    check_denial(&status);
    expect(0, 0);
    native_mounts = false;
    expect(-ENETUNREACH, 0);
    policy.policydb.socket_route = true;
    yz_sized_policy = &policy;
    yz_sized_seqno = policy.latest_granting;
    yz_sized_nel = policy.policydb.te_avtab.nel;
    yz_sized_types = policy.policydb.p_types.nprim;
    size_t bytes;
    policy.policydb.len = policy.policydb.encoded_size = 16;
    assert(!yz_policy_serialized_len(&policy, &bytes) && bytes == 16);
    /* Out-of-bounds or NULL type names must never crash the denial path. */
    struct context bad_zero = {0}, bad_high = {99}, bad_null = {4};
    assert(!strcmp(yz_fixed_type_name(&policy.policydb, NULL), "?"));
    assert(!strcmp(yz_fixed_type_name(&policy.policydb, &bad_zero), "?"));
    assert(!strcmp(yz_fixed_type_name(&policy.policydb, &bad_high), "?"));
    assert(!strcmp(yz_fixed_type_name(&policy.policydb, &bad_null), "?"));
    assert(!strcmp(yz_fixed_type_name(&policy.policydb, &context), "zygote"));
    /* A host replacement can reuse both the address and generation. */
    yz_policy_changed(NULL, LSM_POLICY_CHANGE, NULL);
    policy.policydb.encoded_size = 32;
    assert(!yz_policy_serialized_len(&policy, &bytes) && bytes == 32);
    expect(0, 1);
    assert(yz_fixed_policy_bind_daemon(&other, false) == -EACCES);
    expect(0, 0);
    assert(yz_fixed_policy_bind_daemon(&other, true) == -EACCES);
    assert(yz_fixed_policy_bind_daemon(&daemon, false) == 0);
    yz_fixed_policy_status(&status);
    assert(!status.active && status.error == -EACCES && !status.missing_av);
    assert(yz_fixed_policy_active() && yz_fixed_policy_ready());
    assert(yz_fixed_policy_bind_daemon(&daemon, true) == 0);
    expect(0, 0);
    ++policy.latest_granting;
    policy.policydb.daemon = "remapped";
    expect(-EACCES, 0);
    policy.policydb.daemon = "daemon";
    ++policy.latest_granting;
    policy.policydb.type_attr_map_array[5].node.bits |= 1U << 6;
    expect(-EEXIST, 1);
    ++policy.latest_granting;
    policy.policydb.type_attr_map_array[5].node.bits = FILE_ATTRS & ~(1U << 4);
    expect(-EEXIST, 1);
    ++policy.latest_granting;
    policy.policydb.type_attr_map_array[5].node.bits = FILE_ATTRS;
    expect(0, 1);
    ++policy.latest_granting;
    policy.policydb.sym_val_to_name[SYM_TYPES][2] = "replacement_attr";
    expect(-EINVAL, 1);
    ++policy.latest_granting;
    policy.policydb.sym_val_to_name[SYM_TYPES][2] = "domain";
    expect(0, 1);
    /* A host can publish a new policy before notifying, with the old sequence. */
    struct selinux_policy replacement = policy;
    selinux.policy = &replacement;
    replacement.policydb.rule_error = -EACCES;
    expect(-EACCES, 1);
    selinux.policy = &policy;
    policy.policydb.socket_route = false;
    expect(-ENETUNREACH, 1);
    policy.policydb.socket_route = reset_during_route = true;
    yz_policy_changed(NULL, LSM_POLICY_CHANGE, NULL);
    assert(!yz_fixed_live_error(&policy, NULL, NULL));
    expect(-ENETUNREACH, 1);
    yz_policy_changed(NULL, LSM_POLICY_CHANGE, NULL);
    policy.policydb.socket_route = true;
    expect(0, 1);
    yz_unregister_policy_notifier = false;
    yz_fixed_cache_invalidate();
    expect(0, 2);
    policy.policydb.rule_error = -EACCES;
    expect(-EACCES, 2);
    selinux.policy = NULL;
    expect(-EAGAIN, 0);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as work:
            binary = Path(work) / 'fixed-policy'
            subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Werror',
                            '-I', str(root), '-x', 'c', '-', '-o', str(binary)],
                           input=fixture, text=True, check=True)
            subprocess.run([str(binary)], check=True)

    def test_generated_rules_cover_all_domains(self):
        root = Path(__file__).resolve().parents[2]
        policy = root / 'kernel/feature/policy'
        with tempfile.TemporaryDirectory() as work:
            generated = Path(work) / 'rules.h'
            native = Path(work) / 'module_rules.inc'
            subprocess.run(['python3', str(policy / 'generate.py'),
                            str(policy / 'sepolicy.rule'), str(generated)],
                           check=True)
            subprocess.run(['python3', str(policy / 'generate.py'),
                            str(policy / 'sepolicy.rule'), str(native), '--native'],
                           check=True)
            rules = generated.read_text()
            self.assertNotIn('$target', rules)
            self.assertNotIn('"self"', rules)
            self.assertIn('{ "domain", "domain", "process", "execmem" },', rules)
            self.assertIn('{ "domain", "yukizygisk_file", "file", "execute" },', rules)
            self.assertIn('{ "domain", "$daemon", "unix_stream_socket", "setopt" },', rules)
            self.assertIn('"allow domain domain process execmem",', native.read_text())
