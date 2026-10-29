/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * YukiZygisk - Kernel text and table patch helper.
 *
 * Derived from KernelSU hook/arm64/patch_memory.c.
 *
 * License: GPL-2.0-only
 *
 * Author: bmax121 and Anatdx
 */

#ifndef __aarch64__
#error "YukiZygisk supports ARM64 kernels only"
#endif

#include <linux/cpumask.h>
#include <linux/gfp.h>
#include <linux/stop_machine.h>
#include <linux/uaccess.h>
#include <asm/cacheflush.h>
#include <asm/fixmap.h>

#include "host/patch_text.h"
#include "host/runtime.h"

static struct mm_struct *yz_init_mm;
static typeof(&__set_fixmap) yz_set_fixmap;
static typeof(&copy_to_kernel_nofault) yz_copy_to_kernel_nofault;
#ifdef KSU_HAS_NEW_DCACHE_FLUSH
static typeof(&dcache_clean_inval_poc) yz_dcache_clean_inval_poc;
static typeof(&caches_clean_inval_pou) yz_caches_clean_inval_pou;
#else
static typeof(&__flush_dcache_area) yz_flush_dcache_area;
static typeof(&__flush_icache_range) yz_flush_icache_range;
#endif

static int yz_patch_resolve_symbols(void)
{
	if (!yz_init_mm)
		yz_init_mm = (void *)yz_lookup_name_quiet("init_mm");
	if (!yz_set_fixmap)
		yz_set_fixmap =
			(void *)yz_lookup_callable_quiet("__set_fixmap");
	if (!yz_copy_to_kernel_nofault)
		yz_copy_to_kernel_nofault =
			(void *)yz_lookup_callable_quiet(
				"copy_to_kernel_nofault");
#ifdef KSU_HAS_NEW_DCACHE_FLUSH
	if (!yz_dcache_clean_inval_poc)
		yz_dcache_clean_inval_poc =
			(void *)yz_lookup_callable_quiet(
				"dcache_clean_inval_poc");
	if (!yz_caches_clean_inval_pou)
		yz_caches_clean_inval_pou =
			(void *)yz_lookup_callable_quiet(
				"caches_clean_inval_pou");
	if (!yz_init_mm || !yz_set_fixmap || !yz_copy_to_kernel_nofault ||
	    !yz_dcache_clean_inval_poc || !yz_caches_clean_inval_pou)
#else
	if (!yz_flush_dcache_area)
		yz_flush_dcache_area =
			(void *)yz_lookup_callable_quiet(
				"__flush_dcache_area");
	if (!yz_flush_icache_range)
		yz_flush_icache_range =
			(void *)yz_lookup_callable_quiet(
				"__flush_icache_range");
	if (!yz_init_mm || !yz_set_fixmap || !yz_copy_to_kernel_nofault ||
	    !yz_flush_dcache_area || !yz_flush_icache_range)
#endif
		return -ENOENT;

	return 0;
}

static unsigned long yz_phys_from_virt(unsigned long addr, int *err)
{
	struct mm_struct *mm = yz_init_mm;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	*err = 0;
	if (!mm)
		goto fail;

	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		goto fail;

	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		goto fail;
#if defined(p4d_leaf)
	if (p4d_leaf(*p4d))
		return __p4d_to_phys(*p4d) + (addr & ~P4D_MASK);
#endif

	pud = pud_offset(p4d, addr);
	if (pud_none(*pud) || pud_bad(*pud))
		goto fail;
#if defined(pud_leaf)
	if (pud_leaf(*pud))
		return __pud_to_phys(*pud) + (addr & ~PUD_MASK);
#endif

	pmd = pmd_offset(pud, addr);
#if defined(pmd_leaf)
	if (pmd_leaf(*pmd))
		return __pmd_to_phys(*pmd) + (addr & ~PMD_MASK);
#endif
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		goto fail;

	pte = pte_offset_kernel(pmd, addr);
	if (!pte || !pte_present(*pte))
		goto fail;

	return __pte_to_phys(*pte) + (addr & ~PAGE_MASK);

fail:
	*err = -ENOENT;
	return 0;
}

/* Arm64 cache helpers may be assembly entries without KCFI type IDs. */
static YZ_INDIRECT_CALL void yz_flush_dcache(unsigned long start, size_t size)
{
#ifdef KSU_HAS_NEW_DCACHE_FLUSH
	yz_dcache_clean_inval_poc(start, start + size);
#else
	yz_flush_dcache_area((void *)start, size);
#endif
}

static YZ_INDIRECT_CALL void yz_flush_icache(unsigned long start,
					      unsigned long end)
{
#ifdef KSU_HAS_NEW_DCACHE_FLUSH
	yz_caches_clean_inval_pou(start, end);
#else
	yz_flush_icache_range(start, end);
#endif
}

struct yz_patch_text_info {
	void *dst;
	void *src;
	size_t len;
	atomic_t cpu_count;
	int flags;
};

/* __set_fixmap and copy_to_kernel_nofault may only have raw old-CFI entries. */
static YZ_LEGACY_INDIRECT_CALL int
yz_patch_text_nosync(void *dst, void *src, size_t len, int flags)
{
	unsigned long target = (unsigned long)dst;
	unsigned long phys;
	void *map;
	int phys_err;
	int ret;

	phys = yz_phys_from_virt(target, &phys_err);
	if (phys_err) {
		pr_err("yukizygisk: failed to resolve patch target phys addr 0x%lx\n",
		       target);
		return phys_err;
	}

	yz_set_fixmap(FIX_TEXT_POKE0, phys, FIXMAP_PAGE_NORMAL);
	map = (void *)(fix_to_virt(FIX_TEXT_POKE0) + (phys & ~PAGE_MASK));
	ret = (int)yz_copy_to_kernel_nofault(map, src, len);
	yz_set_fixmap(FIX_TEXT_POKE0, 0, FIXMAP_PAGE_CLEAR);

	if (!ret) {
		if (flags & YZ_PATCH_TEXT_FLUSH_ICACHE)
			yz_flush_icache(target, target + len);
		if (flags & YZ_PATCH_TEXT_FLUSH_DCACHE)
			yz_flush_dcache(target, len);
	}

	return ret;
}

static int yz_patch_text_cb(void *arg)
{
	struct yz_patch_text_info *info = arg;
	int ret = 0;

	if (atomic_inc_return(&info->cpu_count) == num_online_cpus()) {
		ret = yz_patch_text_nosync(info->dst, info->src, info->len,
					   info->flags);
		atomic_inc(&info->cpu_count);
	} else {
		while (atomic_read(&info->cpu_count) <= num_online_cpus())
			cpu_relax();
		isb();
	}

	return ret;
}

int yz_patch_text(void *dst, void *src, size_t len, int flags)
{
	struct yz_patch_text_info info = {
		.dst = dst,
		.src = src,
		.len = len,
		.cpu_count = ATOMIC_INIT(0),
		.flags = flags,
	};
	int ret;

	ret = yz_patch_resolve_symbols();
	if (ret) {
		pr_err("yukizygisk: patch_text infrastructure unavailable\n");
		return ret;
	}

	return stop_machine(yz_patch_text_cb, &info, cpu_online_mask);
}
