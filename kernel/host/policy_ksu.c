/* SPDX-License-Identifier: GPL-2.0-only */
/* Carry tiann/KernelSU's original-type cache across a YukiZygisk policy update. */
#include <linux/module.h>
#include <linux/version.h>

#include "host/policy_ksu.h"
#include "host/root_impl.h"
#include "host/runtime.h"

#define KSU_ADVANCE_TYPES "ksu_advance_original_types"

static typeof(&yz_ksu_policy_advance) advance_types;
static struct module *ksu_module;

YZ_LEGACY_INDIRECT_CALL bool yz_ksu_policy_advance(struct policydb *new_db,
						   struct policydb *old_db,
						   u32 old_generation,
						   u32 new_generation)
{
	return !advance_types ||
	       advance_types(new_db, old_db, old_generation, new_generation);
}

static unsigned long advance_address(void)
{
#if defined(CONFIG_CFI_CLANG) && LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	unsigned long address = yz_lookup_name_quiet(KSU_ADVANCE_TYPES ".cfi_jt");

	if (address)
		return address;
#endif
	return yz_lookup_name_quiet(KSU_ADVANCE_TYPES);
}

static YZ_LEGACY_INDIRECT_CALL struct module *pin_advance_owner(unsigned long address)
{
	typeof(&__module_text_address) module_at =
		(void *)yz_lookup_callable_quiet("__module_text_address");
	struct module *owner;

	if (!module_at)
		return NULL;

	preempt_disable();
	owner = module_at(address);
	/* try_module_get() also accepts COMING modules, whose init can still fail. */
	if (owner && (READ_ONCE(owner->state) != MODULE_STATE_LIVE ||
		      !try_module_get(owner)))
		owner = NULL;
	preempt_enable();

	/* Symbol lookup and module pinning can race an unload/reload. */
	if (owner && advance_address() != address) {
		module_put(owner);
		owner = NULL;
	}
	return owner;
}

void yz_ksu_policy_bind(void)
{
	unsigned long address, text, end;

	if (advance_types || READ_ONCE(yz_root_owner) != YZ_ROOT_OWNER_KERNELSU)
		return;

	address = advance_address();
	if (!address)
		goto unavailable;
	text = yz_lookup_name_quiet("_stext");
	end = yz_lookup_name_quiet("_etext");
	if (!(text && text <= address && address < end)) {
		ksu_module = pin_advance_owner(address);
		if (!ksu_module)
			goto unavailable;
	}

	advance_types = (typeof(advance_types))address;
	pr_info("yukizygisk: temporary SELinux policy synchronizes KernelSU original types (%s)\n",
		ksu_module ? module_name(ksu_module) : "built-in");
	return;
unavailable:
	pr_info("yukizygisk: KernelSU original-type callback unavailable\n");
}

void yz_ksu_policy_unbind(void)
{
	advance_types = NULL;
	module_put(ksu_module);
	ksu_module = NULL;
}
