/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * YukiZygisk - Host runtime symbol resolver.
 *
 * Derived from KernelSU infra/symbol_resolver.c and Linux kernel/task_work.c.
 *
 * License: GPL-2.0-only
 *
 * Author: KernelSU contributors, Linux kernel contributors and Anatdx
 */

#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/path.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/task_work.h>
#include <linux/string.h>
#include <linux/version.h>

#include "host/root_impl.h"
#include "host/runtime.h"

/* Android common KMI 5.10 still exports __close_fd(files, fd) */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0)
#define YZ_USE_LEGACY_CLOSE_FD 1
#else
#define YZ_USE_LEGACY_CLOSE_FD 0
#endif

unsigned long (*yz_kallsyms_lookup_name)(const char *name);
struct file *(*yz_filp_open)(const char *filename, int flags, umode_t mode);
int (*yz_filp_close)(struct file *file, fl_owner_t id);

static struct cred *(*yz_prepare_creds_fn)(void);
static void (*yz_abort_creds_fn)(struct cred *cred);
static const struct cred *(*yz_override_creds_fn)(const struct cred *cred);
static void (*yz_revert_creds_fn)(const struct cred *cred);
static ssize_t (*yz_kernel_read_fn)(struct file *file, void *buf,
				    size_t count, loff_t *pos);
static ssize_t (*yz_kernel_write_fn)(struct file *file, const void *buf,
				     size_t count, loff_t *pos);
static int (*yz_kern_path_fn)(const char *name, unsigned int flags,
			      struct path *path);
static typeof(&path_put) yz_path_put_fn;
#ifdef YZ_USE_LEGACY_CLOSE_FD
static int (*yz_close_fd_fn)(struct files_struct *files, unsigned int fd);
#else
static int (*yz_close_fd_fn)(unsigned int fd);
#endif
static int (*yz_task_work_add_fn)(struct task_struct *task,
				  struct callback_head *twork,
				  enum task_work_notify_mode mode);
static typeof(&copy_from_kernel_nofault) yz_copy_from_kernel_nofault_fn;
static typeof(&get_task_exe_file) yz_get_task_exe_file_fn;
static typeof(&kallsyms_lookup_size_offset)
	yz_kallsyms_lookup_size_offset_fn;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define YZ_USE_KCFI 1
#else
#define YZ_USE_KCFI 0
#endif

#if YZ_USE_KCFI
static typeof(&task_work_cancel_match) yz_task_work_cancel_match_fn;
#endif

#if !YZ_USE_KCFI
static const char yz_cfi_suffix[] = ".cfi_jt";
static const size_t yz_cfi_suffix_len = sizeof(yz_cfi_suffix) - 1;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
typedef int (*yz_kallsyms_on_each_symbol_fn)(int (*fn)(void *, const char *,
						       unsigned long),
					     void *data);
#else
typedef int (*yz_kallsyms_on_each_symbol_fn)(int (*fn)(void *, const char *,
						       struct module *,
						       unsigned long),
					     void *data);
#endif

typedef int (*yz_kallsyms_on_each_match_symbol_fn)(int (*fn)(void *,
							     unsigned long),
						 const char *name, void *data);

static yz_kallsyms_on_each_symbol_fn yz_kallsyms_on_each_symbol;
static yz_kallsyms_on_each_match_symbol_fn yz_kallsyms_on_each_match_symbol;

struct yz_lookup_symbol_ctx {
	const char *symbol_name;
	size_t symbol_len;
	void *match;
};

bool yz_valid_kernel_addr(unsigned long addr)
{
	if (!addr)
		return false;
	if (IS_ERR_VALUE(addr))
		return false;
#if defined(CONFIG_64BIT)
	return (addr & (1UL << 63)) != 0;
#else
	return addr >= PAGE_OFFSET;
#endif
}

static int yz_find_kernel_symbol_exact_cb(void *data, unsigned long addr)
{
	*(unsigned long *)data = addr;
	return 0;
}

static unsigned long yz_lookup_via_kprobe(const char *name)
{
	struct kprobe kp = { .symbol_name = name };
	unsigned long addr;

	if (register_kprobe(&kp))
		return 0;
	addr = (unsigned long)kp.addr;
	unregister_kprobe(&kp);
	return yz_valid_kernel_addr(addr) ? addr : 0;
}

static YZ_INDIRECT_CALL unsigned long
yz_find_kernel_symbol_exact(const char *name)
{
	unsigned long addr = 0;

	if (!name || !name[0])
		return 0;
	if (yz_kallsyms_on_each_match_symbol) {
		yz_kallsyms_on_each_match_symbol(yz_find_kernel_symbol_exact_cb,
						  name, &addr);
		if (addr)
			return addr;
	}
	if (yz_kallsyms_lookup_name)
		return yz_kallsyms_lookup_name(name);
	return yz_lookup_via_kprobe(name);
}

static bool yz_symbol_has_suffix(const char *name, size_t name_len,
				 const char *suffix, size_t suffix_len)
{
	return name_len >= suffix_len &&
	       !strcmp(name + name_len - suffix_len, suffix);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
static int yz_lookup_symbol_variant_cb(void *data, const char *name,
				       unsigned long addr)
#else
static int yz_lookup_symbol_variant_cb(void *data, const char *name,
				       struct module *mod, unsigned long addr)
#endif
{
	struct yz_lookup_symbol_ctx *ctx = data;
	size_t name_len;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
	(void)mod;
#endif
	if (!name || !addr)
		return 0;

	name_len = strlen(name);
	if (strcmp(name, ctx->symbol_name)) {
		if (name_len <= ctx->symbol_len ||
		    strncmp(name, ctx->symbol_name, ctx->symbol_len) ||
		    (name[ctx->symbol_len] != '.' &&
		     name[ctx->symbol_len] != '$'))
			return 0;
	}

#if !YZ_USE_KCFI
	if (yz_symbol_has_suffix(name, name_len, yz_cfi_suffix,
				 yz_cfi_suffix_len)) {
		ctx->match = (void *)addr;
		return 1;
	}
#endif

	if (!ctx->match) {
		ctx->match = (void *)addr;
#if YZ_USE_KCFI
		return 1;
#endif
	}

	return 0;
}

static YZ_INDIRECT_CALL void *
yz_resolve_symbol_variant(const char *name, size_t name_len)
{
	struct yz_lookup_symbol_ctx ctx = {
		.symbol_name = name,
		.symbol_len = name_len,
	};

	if (yz_kallsyms_on_each_symbol)
		yz_kallsyms_on_each_symbol(yz_lookup_symbol_variant_cb, &ctx);
	return ctx.match;
}

static YZ_INDIRECT_CALL unsigned long
yz_resolve_callable(const char *name)
{
	void *addr;
	size_t name_len;

	if (!name || !name[0])
		return 0;
	name_len = strlen(name);

#if !YZ_USE_KCFI
	{
		char cfi_name[KSYM_NAME_LEN];
		int len = snprintf(cfi_name, sizeof(cfi_name), "%s.cfi_jt",
				   name);

		if (len > 0 && (size_t)len < sizeof(cfi_name)) {
			addr = (void *)yz_find_kernel_symbol_exact(cfi_name);
			if (addr)
				return (unsigned long)addr;
		}
	}

	addr = yz_resolve_symbol_variant(name, name_len);
	if (addr)
		return (unsigned long)addr;
	return yz_find_kernel_symbol_exact(name);
#else
	addr = (void *)yz_find_kernel_symbol_exact(name);
	if (addr)
		return (unsigned long)addr;
	return (unsigned long)yz_resolve_symbol_variant(name, name_len);
#endif
}

YZ_INDIRECT_CALL unsigned long yz_lookup_name(const char *name)
{
	unsigned long addr = yz_find_kernel_symbol_exact(name);

	if (!addr || IS_ERR_VALUE(addr)) {
		pr_alert("yukizygisk: symbol %s unavailable\n", name);
		return 0;
	}
	return addr;
}

YZ_INDIRECT_CALL unsigned long yz_lookup_name_quiet(const char *name)
{
	unsigned long addr = yz_find_kernel_symbol_exact(name);

	return addr && !IS_ERR_VALUE(addr) ? addr : 0;
}

YZ_INDIRECT_CALL unsigned long yz_lookup_callable(const char *name)
{
	unsigned long addr = yz_resolve_callable(name);

	if (!addr || IS_ERR_VALUE(addr)) {
		pr_alert("yukizygisk: callable %s unavailable\n", name);
		return 0;
	}
	return addr;
}

YZ_INDIRECT_CALL unsigned long yz_lookup_callable_quiet(const char *name)
{
	unsigned long addr = yz_resolve_callable(name);

	return addr && !IS_ERR_VALUE(addr) ? addr : 0;
}

static int yz_init_symbol_resolver(void)
{
	unsigned long addr = yz_lookup_via_kprobe("kallsyms_lookup_name");

	if (!addr) {
		pr_err("yukizygisk: failed to bootstrap kallsyms_lookup_name\n");
		return -ENOENT;
	}
	yz_kallsyms_lookup_name = (void *)addr;
	yz_kallsyms_on_each_symbol =
		(yz_kallsyms_on_each_symbol_fn)yz_resolve_callable(
			"kallsyms_on_each_symbol");
	yz_kallsyms_on_each_match_symbol =
		(yz_kallsyms_on_each_match_symbol_fn)yz_resolve_callable(
			"kallsyms_on_each_match_symbol");
	return 0;
}

bool yz_kernel_read_nofault(void *dst, unsigned long src, size_t size)
{
	if (!yz_copy_from_kernel_nofault_fn)
		yz_copy_from_kernel_nofault_fn =
			(void *)yz_lookup_callable_quiet(
				"copy_from_kernel_nofault");

	return yz_copy_from_kernel_nofault_fn &&
	       yz_copy_from_kernel_nofault_fn(dst, (const void *)src, size) == 0;
}

__attribute__((__noinline__)) bool
yz_lookup_size_offset(unsigned long addr, unsigned long *symbolsize,
		      unsigned long *offset)
{
	if (!yz_kallsyms_lookup_size_offset_fn) {
		unsigned long sym;

#if YZ_USE_KCFI
		sym = yz_lookup_name_quiet("kallsyms_lookup_size_offset");
#else
		sym = yz_lookup_callable_quiet("kallsyms_lookup_size_offset");
#endif
		if (sym && yz_valid_kernel_addr(sym))
			yz_kallsyms_lookup_size_offset_fn = (void *)sym;
	}

	return yz_kallsyms_lookup_size_offset_fn &&
	       yz_kallsyms_lookup_size_offset_fn(addr, symbolsize, offset) != 0;
}

YZ_INDIRECT_CALL struct cred *yz_prepare_creds(void)
{
	return yz_prepare_creds_fn ? yz_prepare_creds_fn() : NULL;
}

YZ_INDIRECT_CALL void yz_abort_creds(struct cred *cred)
{
	if (yz_abort_creds_fn)
		yz_abort_creds_fn(cred);
}

YZ_INDIRECT_CALL const struct cred *yz_override_creds(const struct cred *cred)
{
	return yz_override_creds_fn ? yz_override_creds_fn(cred) : NULL;
}

YZ_INDIRECT_CALL void yz_revert_creds(const struct cred *cred)
{
	if (yz_revert_creds_fn)
		yz_revert_creds_fn(cred);
}

YZ_INDIRECT_CALL struct file *yz_file_open(const char *filename, int flags,
					   umode_t mode)
{
	return yz_filp_open ? yz_filp_open(filename, flags, mode) :
			      ERR_PTR(-ENOENT);
}

YZ_INDIRECT_CALL int yz_file_close(struct file *file, fl_owner_t id)
{
	if (yz_filp_close)
		return yz_filp_close(file, id);
	fput(file);
	return 0;
}

YZ_INDIRECT_CALL ssize_t yz_kernel_read(struct file *file, void *buf,
					size_t count, loff_t *pos)
{
	return yz_kernel_read_fn ? yz_kernel_read_fn(file, buf, count, pos) :
				   -ENOENT;
}

YZ_INDIRECT_CALL ssize_t yz_kernel_write(struct file *file, const void *buf,
					 size_t count, loff_t *pos)
{
	return yz_kernel_write_fn ? yz_kernel_write_fn(file, buf, count, pos) :
				    -ENOENT;
}

YZ_INDIRECT_CALL int yz_kern_path(const char *name, unsigned int flags,
				  struct path *path)
{
	return yz_kern_path_fn ? yz_kern_path_fn(name, flags, path) : -ENOENT;
}

void yz_path_put(const struct path *path)
{
	if (yz_path_put_fn)
		yz_path_put_fn(path);
}

YZ_INDIRECT_CALL int yz_close_fd(unsigned int fd)
{
#if YZ_USE_LEGACY_CLOSE_FD
	return yz_close_fd_fn ? yz_close_fd_fn(current->files, fd): -ENOENT;
#else
	return yz_close_fd_fn ? yz_close_fd_fn(fd) : -ENOENT;
#endif
}

noinline struct file *yz_get_current_exe_file(void)
{
#if YZ_USE_KCFI
	/* This declared API has a KCFI type word at its raw entry. */
	return yz_get_task_exe_file_fn ? yz_get_task_exe_file_fn(current) : NULL;
#else
	struct mm_struct *mm = current->mm;
	struct file *exe;

	/* Older CFI kernels can export an anonymous jump-table slot while
	 * kallsyms names only the raw body. Do not call that unchecked body.
	 * Current holds its mm alive: acquire the executable through the
	 * target headers' RCU and file-reference primitives instead. This
	 * deliberately is not an arbitrary-task executable lookup. */
	if (!mm)
		return NULL;
	rcu_read_lock();
	exe = rcu_dereference(mm->exe_file);
	if (exe && !get_file_rcu(exe))
		exe = NULL;
	rcu_read_unlock();
	return exe;
#endif
}

YZ_INDIRECT_CALL int yz_task_work_add(struct task_struct *task,
				      struct callback_head *twork,
				      enum task_work_notify_mode mode)
{
	if (!yz_task_work_add_fn)
		return -ENOENT;
	return yz_task_work_add_fn(task, twork, mode);
}

static int yz_resolve_runtime_symbols(void)
{
	yz_prepare_creds_fn =
		(void *)yz_lookup_callable_quiet("prepare_creds");
	yz_abort_creds_fn = (void *)yz_lookup_callable_quiet("abort_creds");
	yz_override_creds_fn =
		(void *)yz_lookup_callable_quiet("override_creds");
	yz_revert_creds_fn =
		(void *)yz_lookup_callable_quiet("revert_creds");
	yz_filp_open = (void *)yz_lookup_callable_quiet("filp_open");
	yz_filp_close = (void *)yz_lookup_callable_quiet("filp_close");
	yz_kernel_read_fn =
		(void *)yz_lookup_callable_quiet("kernel_read");
	yz_kernel_write_fn =
		(void *)yz_lookup_callable_quiet("kernel_write");
	yz_kern_path_fn = (void *)yz_lookup_callable_quiet("kern_path");
	yz_path_put_fn = (void *)yz_lookup_callable_quiet("path_put");
#if YZ_USE_LEGACY_CLOSE_FD
	yz_close_fd_fn = (void *)yz_lookup_callable_quiet("__close_fd");
#else
	yz_close_fd_fn = (void *)yz_lookup_callable_quiet("close_fd");
#endif
#if YZ_USE_KCFI
	yz_task_work_cancel_match_fn =
	    (typeof(yz_task_work_cancel_match_fn))yz_lookup_callable(
		"task_work_cancel_match");
	if (!yz_task_work_cancel_match_fn)
		return -ENOENT;
#endif
	yz_task_work_add_fn =
		(void *)yz_lookup_callable_quiet("task_work_add");
#if YZ_USE_KCFI
	yz_get_task_exe_file_fn =
		(typeof(yz_get_task_exe_file_fn))yz_lookup_callable_quiet("get_task_exe_file");
	if (!yz_get_task_exe_file_fn)
		return -ENOENT;
#endif

	if (!yz_prepare_creds_fn || !yz_abort_creds_fn ||
	    !yz_override_creds_fn || !yz_revert_creds_fn || !yz_filp_open ||
	    !yz_kernel_read_fn || !yz_kernel_write_fn || !yz_kern_path_fn ||
	    !yz_path_put_fn || !yz_close_fd_fn || !yz_task_work_add_fn) {
		pr_err("yukizygisk: required runtime symbol missing: "
		       "prepare=%d abort=%d override=%d revert=%d open=%d "
		       "read=%d write=%d kern_path=%d path_put=%d close=%d "
		       "task_work=%d\n",
		       !!yz_prepare_creds_fn, !!yz_abort_creds_fn,
		       !!yz_override_creds_fn, !!yz_revert_creds_fn,
		       !!yz_filp_open, !!yz_kernel_read_fn,
		       !!yz_kernel_write_fn, !!yz_kern_path_fn,
		       !!yz_path_put_fn, !!yz_close_fd_fn,
		       !!yz_task_work_add_fn);
		return -ENOENT;
	}
	if (!yz_filp_close)
		pr_warn("yukizygisk: filp_close not found, falling back to fput\n");

	return 0;
}

struct callback_head *
yz_task_work_cancel_match(struct task_struct *task,
			  bool (*match)(struct callback_head *, void *),
			  void *data)
{
#if YZ_USE_KCFI
	if (!yz_task_work_cancel_match_fn)
		return NULL;
	return yz_task_work_cancel_match_fn(task, match, data);
#else
	/* Linux 5.x does not expose an old-CFI jump-table entry for this
	 * private symbol. Use its task_work.c cancellation algorithm locally;
	 * never pass the raw entry to an unchecked indirect call. The target's
	 * task_work_run() waits on pi_lock before executing a detached list. */
	struct callback_head **pprev = &task->task_works;
	struct callback_head *work;
	unsigned long flags;

	if (!READ_ONCE(task->task_works))
		return NULL;
	/* Failed cmpxchg leaves pprev in place: add may have prepended a new
	 * node, or run may have exchanged the head for NULL/work_exited. */
	raw_spin_lock_irqsave(&task->pi_lock, flags);
	while ((work = READ_ONCE(*pprev))) {
		if (!match(work, data))
			pprev = &work->next;
		else if (cmpxchg(pprev, work, work->next) == work)
			break;
	}
	raw_spin_unlock_irqrestore(&task->pi_lock, flags);
	return work;
#endif
}

int yz_host_runtime_init(void)
{
	int ret;

	ret = yz_init_symbol_resolver();
	if (ret)
		return ret;

	ret = yz_resolve_runtime_symbols();
	if (ret) {
		yz_host_runtime_exit();
		return ret;
	}

	ret = yz_host_root_detect();
	if (ret) {
		yz_host_runtime_exit();
		return ret;
	}
	return 0;
}

void yz_host_runtime_exit(void)
{
	yz_host_root_exit();
	yz_prepare_creds_fn = NULL;
	yz_abort_creds_fn = NULL;
	yz_override_creds_fn = NULL;
	yz_revert_creds_fn = NULL;
	yz_filp_open = NULL;
	yz_filp_close = NULL;
	yz_kernel_read_fn = NULL;
	yz_kernel_write_fn = NULL;
	yz_kern_path_fn = NULL;
	yz_path_put_fn = NULL;
	yz_close_fd_fn = NULL;
	yz_task_work_add_fn = NULL;
#if YZ_USE_KCFI
	yz_task_work_cancel_match_fn = NULL;
#endif
	yz_get_task_exe_file_fn = NULL;
	yz_kallsyms_lookup_name = NULL;
	yz_kallsyms_on_each_symbol = NULL;
	yz_kallsyms_on_each_match_symbol = NULL;
	yz_kallsyms_lookup_size_offset_fn = NULL;
	yz_copy_from_kernel_nofault_fn = NULL;
}
