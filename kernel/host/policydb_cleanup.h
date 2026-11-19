#ifndef YZ_POLICYDB_CLEANUP_H
#define YZ_POLICYDB_CLEANUP_H

#include <linux/overflow.h>
#include "ss/policydb.h"

static inline bool policydb_snapshot_capacity(const struct policydb *p,
					      size_t *capacity)
{
	size_t extra;

	/* policydb_read() can add one serialized ebitmap entry per type. */
	return !check_mul_overflow((size_t)p->p_types.nprim,
				   sizeof(u32) + sizeof(u64), &extra) &&
	       !check_add_overflow(p->len, extra, capacity);
}

static inline bool policydb_read_needs_destroy(const struct policydb *p)
{
	u32 i;

	/* The symtab/roles init exits retain only these allocation roots.
	 * policydb_destroy() clears them on every already-cleaned error path.
	 */
	for (i = 0; i < SYM_NUM; i++) {
		if (p->symtab[i].table.htable)
			return true;
	}
	return p->policycaps.node || p->permissive_map.node;
}

#endif
