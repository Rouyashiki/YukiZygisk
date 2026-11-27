/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef YZ_HOST_POLICY_KSU_H
#define YZ_HOST_POLICY_KSU_H

#include <linux/types.h>

struct policydb;

/* Serialized by the host policy lock. Advance also requires the SELinux
 * policy mutex, with both policy objects still alive. */
void yz_ksu_policy_bind(void);
bool yz_ksu_policy_advance(struct policydb *new_db, struct policydb *old_db,
			   u32 old_generation, u32 new_generation);
void yz_ksu_policy_unbind(void);

#endif
