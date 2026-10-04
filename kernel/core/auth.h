/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Viola process-bound control and payload admission.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef YUKIZYGISK_AUTH_H
#define YUKIZYGISK_AUTH_H

#include <linux/types.h>

struct file;
struct task_struct;
struct yz_auth_session;
struct yz_auth_ticket {
	u64 epoch;
	u64 generation;
};

int yz_auth_init(void);
void yz_auth_exit(void);
struct yz_auth_session *yz_auth_open(bool launcher);
void yz_auth_release(struct yz_auth_session *session);
/* A successful begin holds the authorization mutex until end. */
int yz_auth_begin(struct yz_auth_session *session, unsigned int request,
		  void __user *arg);
void yz_auth_end(void);
/* Capture while begin holds the lock; queued work must begin the ticket
 * again in process context before applying its mutation. */
int yz_auth_current_ticket(struct yz_auth_ticket *ticket);
bool yz_auth_ticket_begin(const struct yz_auth_ticket *ticket);
int yz_auth_query_ticket(struct yz_auth_ticket *ticket);
bool yz_auth_query_ticket_begin(const struct yz_auth_ticket *ticket);
int yz_auth_target_task(struct task_struct *task);
int yz_auth_target_report(u32 pid, u32 generation);
long yz_auth_ioctl(struct yz_auth_session *session, unsigned int request,
		   void __user *arg);
bool yz_auth_catalog_ready(void);
bool yz_auth_injection_allowed(bool early_native, bool compat);
bool yz_auth_injection_ticket(bool early_native, bool compat,
			      struct yz_auth_ticket *ticket);
bool yz_auth_injection_ticket_alive(const struct yz_auth_ticket *ticket);
int yz_auth_check_payload(unsigned int role, bool compat,
			  const void *bytes, size_t size);
int yz_auth_seal_image(struct file *file);

#endif
