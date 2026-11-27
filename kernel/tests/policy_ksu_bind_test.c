/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <stdbool.h>
#include <string.h>

#define KERNEL_VERSION(a, b, c) (((a) << 16) | ((b) << 8) | (c))
#define LINUX_VERSION_CODE KERNEL_VERSION(5, 10, 0)
#define CONFIG_CFI_CLANG 1
#define YZ_LEGACY_INDIRECT_CALL
#define READ_ONCE(v) (v)
#define pr_info(...) ((void)0)

enum { YZ_ROOT_OWNER_KERNELPATCH, YZ_ROOT_OWNER_KERNELSU } yz_root_owner;
enum module_state { MODULE_STATE_LIVE, MODULE_STATE_COMING, MODULE_STATE_GOING };
struct module {
	const char *name;
	enum module_state state;
	int refs;
};
static struct module host = {"kernelsu", MODULE_STATE_LIVE, 0}, *ksu_module;
static void (*advance_types)(void);
static unsigned long entry, jump_table, text_start, text_end;
static int lookups, preempt_depth;
static bool replace_on_pin, unload_on_pin;

static void callback(void) {}
static void thunk(void) {}

static unsigned long yz_lookup_name_quiet(const char *name)
{
	++lookups;
	if (!strcmp(name, "_stext"))
		return text_start;
	if (!strcmp(name, "_etext"))
		return text_end;
	if (!strcmp(name, "ksu_advance_original_types.cfi_jt"))
		return jump_table;
	assert(!strcmp(name, "ksu_advance_original_types"));
	return entry;
}

static struct module *__module_text_address(unsigned long address)
{
	assert(preempt_depth == 1);
	return address == entry || address == jump_table ? &host : NULL;
}

static unsigned long yz_lookup_callable_quiet(const char *name)
{
	assert(!strcmp(name, "__module_text_address"));
	return (unsigned long)__module_text_address;
}

#define preempt_disable() (++preempt_depth)
#define preempt_enable() (--preempt_depth)
#define module_name(owner) ((owner)->name)

static bool try_module_get(struct module *owner)
{
	assert(preempt_depth == 1);
	if (unload_on_pin)
		owner->state = MODULE_STATE_GOING;
	if (owner->state == MODULE_STATE_GOING)
		return false;
	if (replace_on_pin)
		entry = 0;
	++owner->refs;
	return true;
}

static void module_put(struct module *owner)
{
	assert(!preempt_depth);
	if (owner) {
		assert(owner->refs > 0);
		--owner->refs;
	}
}

#include "production.inc"

int main(void)
{
	yz_root_owner = YZ_ROOT_OWNER_KERNELPATCH;
	yz_ksu_policy_bind();
	assert(!lookups && !advance_types);

	yz_root_owner = YZ_ROOT_OWNER_KERNELSU;
	yz_ksu_policy_bind();
	assert(!advance_types && !host.refs);

	entry = (unsigned long)callback;
	host.state = MODULE_STATE_COMING;
	yz_ksu_policy_bind();
	assert(!advance_types && !host.refs);
	host.state = MODULE_STATE_LIVE;
	unload_on_pin = true;
	yz_ksu_policy_bind();
	assert(host.state == MODULE_STATE_GOING && !advance_types && !host.refs);
	host.state = MODULE_STATE_LIVE;
	unload_on_pin = false;
	replace_on_pin = true;
	yz_ksu_policy_bind();
	assert(!advance_types && !host.refs);

	entry = (unsigned long)callback;
	replace_on_pin = false;
	yz_ksu_policy_bind();
	yz_ksu_policy_bind();
	assert(advance_types == callback && host.refs == 1);
	yz_ksu_policy_unbind();
	assert(!advance_types && !host.refs);

	jump_table = (unsigned long)thunk;
	text_start = jump_table;
	text_end = jump_table + 1;
	yz_ksu_policy_bind();
	assert(advance_types == thunk && !host.refs);
	yz_ksu_policy_unbind();
	return 0;
}
