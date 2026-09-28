/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Zygote exit diagnostics.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include <linux/errno.h>
#include <linux/ktime.h>
#include <linux/sched/signal.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/tracepoint.h>
#include <linux/workqueue.h>
#include <trace/events/sched.h>

#include "uapi/yukizygisk.h"
#include "zygote_exit.h"
#include "zygote_nl.h"

#define YZ_EXIT_CAPACITY 16

static DEFINE_SPINLOCK(yz_exit_lock);
static struct yz_zygote_exit_event yz_exit_tracked[YZ_EXIT_CAPACITY];
static struct yz_zygote_exit_event yz_exit_pending[YZ_EXIT_CAPACITY];
static unsigned int yz_exit_head;
static unsigned int yz_exit_tail;
static bool yz_exit_enabled;
static struct tracepoint *yz_exit_tracepoint;

static void yz_exit_work_fn(struct work_struct *work)
{
	struct yz_zygote_exit_event event;
	unsigned long flags;

	(void)work;
	for (;;) {
		spin_lock_irqsave(&yz_exit_lock, flags);
		if (yz_exit_head == yz_exit_tail) {
			spin_unlock_irqrestore(&yz_exit_lock, flags);
			return;
		}
		event = yz_exit_pending[yz_exit_tail];
		yz_exit_tail = (yz_exit_tail + 1) % YZ_EXIT_CAPACITY;
		spin_unlock_irqrestore(&yz_exit_lock, flags);
		yz_zygote_nl_emit_zygote_exit(&event);
	}
}

static DECLARE_WORK(yz_exit_work, yz_exit_work_fn);

void yz_zygote_exit_track(u32 pid, u64 start, u32 generation, u8 abi)
{
	unsigned long flags;
	unsigned int i;
	int slot = -1;

	if (!generation)
		return;
	spin_lock_irqsave(&yz_exit_lock, flags);
	for (i = 0; i < YZ_EXIT_CAPACITY; ++i) {
		if (yz_exit_tracked[i].event.pid == pid) {
			slot = (int)i;
			break;
		}
		if (!yz_exit_tracked[i].event.pid && slot < 0)
			slot = (int)i;
	}
	if (slot >= 0) {
		struct yz_zygote_exit_event *event = &yz_exit_tracked[slot];

		memset(event, 0, sizeof(*event));
		event->event.type = YZ_EV_ZYGOTE_EXIT;
		event->event.pid = pid;
		event->start_boottime = start;
		event->generation = generation;
		event->abi = abi;
	}
	spin_unlock_irqrestore(&yz_exit_lock, flags);
}

#ifdef CONFIG_TRACEPOINTS
static void yz_exit_on_exit(void *data, struct task_struct *task
#ifdef YZ_EXIT_HAS_GROUP_DEAD
			    ,
			    bool group_dead
#endif
)
{
	unsigned long flags;
	unsigned int i, next;
	int status;

	(void)data;
#ifdef YZ_EXIT_HAS_GROUP_DEAD
	(void)group_dead;
#endif
	if (task->pid != task->tgid)
		return;
	status = READ_ONCE(task->signal->flags) & SIGNAL_GROUP_EXIT
		     ? READ_ONCE(task->signal->group_exit_code)
		     : READ_ONCE(task->exit_code);
	spin_lock_irqsave(&yz_exit_lock, flags);
	for (i = 0; i < YZ_EXIT_CAPACITY; ++i) {
		struct yz_zygote_exit_event *event = &yz_exit_tracked[i];

		if (event->event.pid != (u32)task->tgid ||
		    event->start_boottime != READ_ONCE(task->start_boottime))
			continue;
		next = (yz_exit_head + 1) % YZ_EXIT_CAPACITY;
		/* Ignore ordinary exits and SIGTERM. */
		if (yz_exit_enabled && (status & 0x7f) &&
		    (status & 0x7f) != SIGTERM && next != yz_exit_tail) {
			event->event.appid = (u32)status;
			event->observed_boottime = ktime_get_boottime_ns();
			yz_exit_pending[yz_exit_head] = *event;
			yz_exit_head = next;
			schedule_work(&yz_exit_work);
		}
		memset(event, 0, sizeof(*event));
		break;
	}
	spin_unlock_irqrestore(&yz_exit_lock, flags);
}

static void yz_exit_find_tracepoint(struct tracepoint *tp, void *data)
{
	(void)data;
	if (!strcmp(tp->name, "sched_process_exit"))
		yz_exit_tracepoint = tp;
}
#endif

int yz_zygote_exit_enable(void)
{
#ifdef CONFIG_TRACEPOINTS
	int ret;

	if (READ_ONCE(yz_exit_enabled))
		return 0;
	for_each_kernel_tracepoint(yz_exit_find_tracepoint, NULL);
	if (!yz_exit_tracepoint)
		return -ENOENT;
	check_trace_callback_type_sched_process_exit(yz_exit_on_exit);
	ret = tracepoint_probe_register(yz_exit_tracepoint,
					(void *)yz_exit_on_exit, NULL);
	if (!ret)
		WRITE_ONCE(yz_exit_enabled, true);
	return ret;
#else
	return -EOPNOTSUPP;
#endif
}

void yz_zygote_exit_disable(void)
{
	unsigned long flags;

#ifdef CONFIG_TRACEPOINTS
	if (READ_ONCE(yz_exit_enabled)) {
		WRITE_ONCE(yz_exit_enabled, false);
		tracepoint_probe_unregister(yz_exit_tracepoint,
					    (void *)yz_exit_on_exit, NULL);
		tracepoint_synchronize_unregister();
	}
#endif
	cancel_work_sync(&yz_exit_work);
	spin_lock_irqsave(&yz_exit_lock, flags);
	memset(yz_exit_tracked, 0, sizeof(yz_exit_tracked));
	yz_exit_head = 0;
	yz_exit_tail = 0;
	spin_unlock_irqrestore(&yz_exit_lock, flags);
}
