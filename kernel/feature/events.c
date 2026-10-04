/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - kernel <-> zygiskd netlink channel (lifecycle event push).
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/net_namespace.h>
#include <net/netlink.h>
#include <net/sock.h>

#include "internal.h"
#include "klog.h" // IWYU pragma: keep

static struct sock *yz_events_sock;

static void yz_events_emit_event(u32 type, u32 pid, u32 appid)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	struct yz_event *ev;

	if (!yz_events_sock)
		return;

	skb = nlmsg_new(sizeof(*ev), GFP_ATOMIC);
	if (!skb)
		return;

	nlh = nlmsg_put(skb, 0, 0, YZ_NL_MSG_EVENT, sizeof(*ev), 0);
	if (!nlh) {
		nlmsg_free(skb);
		return;
	}

	ev = nlmsg_data(nlh);
	ev->type = type;
	ev->pid = pid;
	ev->appid = appid;

	/* -ESRCH just means no zygiskd is listening yet -- harmless. */
	nlmsg_multicast(yz_events_sock, skb, 0, YZ_NL_GROUP_EVENTS, GFP_ATOMIC);
}

void yz_events_emit_specialize(u32 pid, u32 appid)
{
	yz_events_emit_event(YZ_EV_SPECIALIZE, pid, appid);
}

/* Ask every listening zygiskd to re-read yzconfig.json (manager changed it). */
void yz_events_emit_reload(void)
{
	yz_events_emit_event(YZ_EV_RELOAD, 0, 0);
}

void yz_events_emit_viola_recovery(u32 owner)
{
	yz_events_emit_event(YZ_EV_VIOLA_RECOVERY, owner, 0);
}

void yz_events_emit_safemode(u32 pid, u32 crashes)
{
	yz_events_emit_event(YZ_EV_SAFEMODE, pid, crashes);
}

void yz_events_emit_policy_refresh(u32 owner, u32 uid)
{
	yz_events_emit_event(YZ_EV_POLICY_REFRESH, owner, uid);
}

static void yz_events_emit_exit(const void *event, size_t size)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;

	if (!yz_events_sock)
		return;
	skb = nlmsg_new(size, GFP_KERNEL);
	if (!skb)
		return;
	nlh = nlmsg_put(skb, 0, 0, YZ_NL_MSG_EVENT, size, 0);
	if (!nlh) {
		nlmsg_free(skb);
		return;
	}
	memcpy(nlmsg_data(nlh), event, size);
	nlmsg_multicast(yz_events_sock, skb, 0, YZ_NL_GROUP_EVENTS, GFP_KERNEL);
}

void yz_events_emit_zygote_exit(const struct yz_zygote_exit_event *event)
{
	yz_events_emit_exit(event, sizeof(*event));
}

void yz_events_emit_target_exit(const struct yz_target_exit_event *event)
{
	yz_events_emit_exit(event, sizeof(*event));
}

void yz_events_init(void)
{
	struct netlink_kernel_cfg cfg = {
	    .groups = YZ_NL_GROUP_EVENTS,
	};

	yz_events_sock =
	    netlink_kernel_create(&init_net, YZ_NETLINK_PROTO, &cfg);
	if (!yz_events_sock)
		pr_err("yukizygisk: events: netlink_kernel_create failed\n");
	else
		pr_info("yukizygisk: events: channel up (proto=%d)\n",
			YZ_NETLINK_PROTO);
}

void yz_events_exit(void)
{
	if (yz_events_sock) {
		netlink_kernel_release(yz_events_sock);
		yz_events_sock = NULL;
	}
}
