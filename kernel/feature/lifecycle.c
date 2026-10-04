/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - App process lifecycle and specialization events.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#include <linux/compat.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/hashtable.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/tracepoint.h>
#include <linux/types.h>
#include <linux/uidgid.h>
#include <linux/workqueue.h>

#include <asm/syscall.h>
#include <asm/unistd.h>
#include <trace/events/sched.h>
#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
#include <trace/events/syscalls.h>
#endif

#include "host/host.h"
#include "internal.h"
#include "klog.h" // IWYU pragma: keep

enum yz_lifecycle_state {
	YZ_LIFECYCLE_FORKED, /* born from zygote; identity not yet known */
	YZ_LIFECYCLE_SPECIALIZED, /* dropped to its app uid */
	YZ_LIFECYCLE_EXITED,
};

struct yz_lifecycle_child {
	struct hlist_node pid_node;
	pid_t pid; /* tgid of the app process; 0 == free slot */
	uid_t uid;
	u64 start_boottime;
	enum yz_lifecycle_state state;
};

/* Holds only live app processes; the free probe reclaims slots. */
#define YZ_LIFECYCLE_MAX_CHILDREN 512
static struct yz_lifecycle_child
    yz_lifecycle_children[YZ_LIFECYCLE_MAX_CHILDREN];
static DEFINE_SPINLOCK(yz_lifecycle_lock);
static DEFINE_HASHTABLE(yz_lifecycle_pids, 9);
static bool yz_lifecycle_trace_sys_exit_registered;
static struct tracepoint *yz_lifecycle_trace_sys_exit_tp;
static struct tracepoint *yz_lifecycle_trace_fork_tp;
static struct tracepoint *yz_lifecycle_trace_free_tp;

struct yz_lifecycle_specialize_event {
	pid_t pid;
	uid_t uid;
	u32 appid;
};

#define YZ_LIFECYCLE_MAX_SPECIALIZE_EVENTS 128
static struct yz_lifecycle_specialize_event
    yz_lifecycle_specialize_events[YZ_LIFECYCLE_MAX_SPECIALIZE_EVENTS];
static unsigned int yz_lifecycle_specialize_head;
static unsigned int yz_lifecycle_specialize_tail;
static unsigned int yz_lifecycle_specialize_dropped;
static bool yz_lifecycle_specialize_work_queued;
static DEFINE_SPINLOCK(yz_lifecycle_event_lock);
static void yz_lifecycle_specialize_work_fn(struct work_struct *work);
static DECLARE_WORK(yz_lifecycle_specialize_work,
		    yz_lifecycle_specialize_work_fn);

static void yz_lifecycle_reset(void)
{
	unsigned long flags;

	spin_lock_irqsave(&yz_lifecycle_lock, flags);
	memset(yz_lifecycle_children, 0, sizeof(yz_lifecycle_children));
	hash_init(yz_lifecycle_pids);
	spin_unlock_irqrestore(&yz_lifecycle_lock, flags);
}

/* yz_lifecycle_lock must be held. */
static int yz_lifecycle_slot_of(pid_t pid)
{
	struct yz_lifecycle_child *child;
	int i;

	if (!pid) {
		for (i = 0; i < YZ_LIFECYCLE_MAX_CHILDREN; i++)
			if (!yz_lifecycle_children[i].pid)
				return i;
		return -1;
	}
	hash_for_each_possible(yz_lifecycle_pids, child, pid_node, pid)
	{
		if (child->pid == pid)
			return child - yz_lifecycle_children;
	}
	return -1;
}

static void yz_lifecycle_track(struct task_struct *task)
{
	pid_t pid = task->tgid;
	unsigned long flags;
	int i;

	spin_lock_irqsave(&yz_lifecycle_lock, flags);
	i = yz_lifecycle_slot_of(pid);
	if (i < 0)
		i = yz_lifecycle_slot_of(0);
	if (i >= 0 &&
	    (!yz_lifecycle_children[i].pid ||
	     yz_lifecycle_children[i].start_boottime != task->start_boottime)) {
		hash_del(&yz_lifecycle_children[i].pid_node);
		yz_lifecycle_children[i].pid = pid;
		yz_lifecycle_children[i].uid = (uid_t)-1;
		yz_lifecycle_children[i].start_boottime = task->start_boottime;
		yz_lifecycle_children[i].state = YZ_LIFECYCLE_FORKED;
		hash_add(yz_lifecycle_pids, &yz_lifecycle_children[i].pid_node,
			 pid);
	}
	spin_unlock_irqrestore(&yz_lifecycle_lock, flags);
}

void yz_lifecycle_on_exit(struct task_struct *task)
{
	unsigned long flags;
	int i;

	spin_lock_irqsave(&yz_lifecycle_lock, flags);
	i = yz_lifecycle_slot_of(task->tgid);
	if (i >= 0 && yz_lifecycle_children[i].start_boottime ==
			  READ_ONCE(task->group_leader->start_boottime))
		yz_lifecycle_children[i].state = YZ_LIFECYCLE_EXITED;
	spin_unlock_irqrestore(&yz_lifecycle_lock, flags);
	yz_fd_handoff_release(task);
}

static void yz_lifecycle_queue_specialize_event(pid_t pid, uid_t uid, u32 appid)
{
	unsigned long flags;
	bool schedule = false;
	unsigned int next;

	spin_lock_irqsave(&yz_lifecycle_event_lock, flags);
	next = (yz_lifecycle_specialize_head + 1) %
	       YZ_LIFECYCLE_MAX_SPECIALIZE_EVENTS;
	if (next == yz_lifecycle_specialize_tail) {
		yz_lifecycle_specialize_dropped++;
	} else {
		yz_lifecycle_specialize_events[yz_lifecycle_specialize_head]
		    .pid = pid;
		yz_lifecycle_specialize_events[yz_lifecycle_specialize_head]
		    .uid = uid;
		yz_lifecycle_specialize_events[yz_lifecycle_specialize_head]
		    .appid = appid;
		yz_lifecycle_specialize_head = next;
	}
	if (!yz_lifecycle_specialize_work_queued) {
		yz_lifecycle_specialize_work_queued = true;
		schedule = true;
	}
	spin_unlock_irqrestore(&yz_lifecycle_event_lock, flags);

	if (schedule)
		schedule_work(&yz_lifecycle_specialize_work);
}

static bool
yz_lifecycle_pop_specialize_event(struct yz_lifecycle_specialize_event *event,
				  unsigned int *dropped)
{
	unsigned long flags;
	bool have_event = false;

	spin_lock_irqsave(&yz_lifecycle_event_lock, flags);
	if (yz_lifecycle_specialize_tail != yz_lifecycle_specialize_head) {
		*event = yz_lifecycle_specialize_events
		    [yz_lifecycle_specialize_tail];
		yz_lifecycle_specialize_tail =
		    (yz_lifecycle_specialize_tail + 1) %
		    YZ_LIFECYCLE_MAX_SPECIALIZE_EVENTS;
		have_event = true;
	} else {
		*dropped = yz_lifecycle_specialize_dropped;
		yz_lifecycle_specialize_dropped = 0;
		if (!*dropped)
			yz_lifecycle_specialize_work_queued = false;
	}
	spin_unlock_irqrestore(&yz_lifecycle_event_lock, flags);
	return have_event;
}

static void yz_lifecycle_specialize_work_fn(struct work_struct *work)
{
	struct yz_lifecycle_specialize_event event;
	unsigned int dropped = 0;

	(void)work;

	for (;;) {
		dropped = 0;
		if (yz_lifecycle_pop_specialize_event(&event, &dropped)) {
			pr_info("yukizygisk: lifecycle: [specialize] pid=%d "
				"uid=%u appid=%u\n",
				event.pid, event.uid, event.appid);
			yz_events_emit_specialize(event.pid, event.appid);
			continue;
		}
		if (dropped) {
			pr_warn("yukizygisk: lifecycle: dropped %u specialize "
				"event(s)\n",
				dropped);
			continue;
		}
		break;
	}
}

static void yz_lifecycle_specialize_events_reset(void)
{
	unsigned long flags;

	cancel_work_sync(&yz_lifecycle_specialize_work);

	spin_lock_irqsave(&yz_lifecycle_event_lock, flags);
	yz_lifecycle_specialize_head = 0;
	yz_lifecycle_specialize_tail = 0;
	yz_lifecycle_specialize_dropped = 0;
	yz_lifecycle_specialize_work_queued = false;
	spin_unlock_irqrestore(&yz_lifecycle_event_lock, flags);
}

struct yz_lifecycle_tracepoint_lookup {
	const char *name;
	struct tracepoint *tp;
};

static void yz_lifecycle_tracepoint_find(struct tracepoint *tp, void *priv)
{
	struct yz_lifecycle_tracepoint_lookup *lookup = priv;

	if (!lookup->tp && tp->name && !strcmp(tp->name, lookup->name))
		lookup->tp = tp;
}

static struct tracepoint *yz_lifecycle_lookup_tracepoint(const char *name)
{
	struct yz_lifecycle_tracepoint_lookup lookup = {
	    .name = name,
	};

	for_each_kernel_tracepoint(yz_lifecycle_tracepoint_find, &lookup);
	return lookup.tp;
}

static int yz_lifecycle_register_tracepoint(struct tracepoint **slot,
					    const char *name, void *probe)
{
	struct tracepoint *tp;
	int ret;

	if (*slot)
		return -EALREADY;

	tp = yz_lifecycle_lookup_tracepoint(name);
	if (!tp)
		return -ENOENT;

	ret = tracepoint_probe_register(tp, probe, NULL);
	if (ret)
		return ret;

	*slot = tp;
	return 0;
}

static void yz_lifecycle_unregister_tracepoint(struct tracepoint **slot,
					       void *probe)
{
	if (!*slot)
		return;

	tracepoint_probe_unregister(*slot, probe, NULL);
	*slot = NULL;
}

#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
static void yz_lifecycle_on_sys_exit(void *data, struct pt_regs *regs, long ret)
{
	int nr;

	(void)data;

	if (ret < 0)
		return;
#ifdef CONFIG_COMPAT
	if (is_compat_task())
		return;
#endif

	nr = syscall_get_nr(current, regs);
	if (nr != __NR_setresuid)
		return;

	yz_lifecycle_on_setresuid((uid_t)-1, current_uid().val);
}

static int yz_lifecycle_tracepoint_init(void)
{
	int ret;

	ret = yz_lifecycle_register_tracepoint(
	    &yz_lifecycle_trace_sys_exit_tp, "sys_exit",
	    (void *)yz_lifecycle_on_sys_exit);
	if (ret)
		return ret;
	yz_lifecycle_trace_sys_exit_registered = true;
	pr_info("yukizygisk: lifecycle: setresuid sys_exit monitor armed\n");
	return 0;
}

static void yz_lifecycle_tracepoint_exit(void)
{
	if (!yz_lifecycle_trace_sys_exit_registered)
		return;
	yz_lifecycle_unregister_tracepoint(&yz_lifecycle_trace_sys_exit_tp,
					   (void *)yz_lifecycle_on_sys_exit);
	tracepoint_synchronize_unregister();
	yz_lifecycle_trace_sys_exit_registered = false;
}
#else
static int yz_lifecycle_tracepoint_init(void)
{
	return -EOPNOTSUPP;
}

static void yz_lifecycle_tracepoint_exit(void)
{
}
#endif

static void yz_lifecycle_setresuid_monitor_init(void)
{
#ifdef __NR_setresuid
	int ret;

	ret = yz_lifecycle_tracepoint_init();
	if (!ret)
		return;

	pr_warn("yukizygisk: lifecycle: sys_exit monitor unavailable: %d; "
		"setresuid specialize events disabled\n",
		ret);
#else
	pr_warn("yukizygisk: lifecycle: __NR_setresuid unavailable; specialize "
		"events disabled\n");
#endif
}

static void yz_lifecycle_setresuid_monitor_exit(void)
{
	yz_lifecycle_tracepoint_exit();
}

#ifdef CONFIG_TRACEPOINTS

static void yz_lifecycle_on_fork(void *data, struct task_struct *parent,
				 struct task_struct *child)
{
	bool from_zygote;

	(void)data;

	/* thread-group leaders only -- skip the zygote's own worker threads */
	if (child->pid != child->tgid)
		return;

	rcu_read_lock();
	from_zygote = yz_host_is_zygote(__task_cred(parent));
	rcu_read_unlock();
	if (!from_zygote)
		return;

	yz_lifecycle_track(child);
	pr_info(
	    "yukizygisk: lifecycle: [fork] app pid=%d born from zygote %d\n",
	    child->pid, parent->pid);
}

static void yz_lifecycle_on_free(void *data, struct task_struct *p)
{
	unsigned long flags;
	bool tracked = false;
	uid_t uid = 0;
	int i;

	(void)data;

	if (p->pid != p->tgid)
		return;

	spin_lock_irqsave(&yz_lifecycle_lock, flags);
	i = yz_lifecycle_slot_of(p->pid);
	if (i >= 0 && yz_lifecycle_children[i].start_boottime ==
			  READ_ONCE(p->start_boottime)) {
		tracked = true;
		uid = yz_lifecycle_children[i].uid;
		hash_del(&yz_lifecycle_children[i].pid_node);
		yz_lifecycle_children[i].pid = 0;
	}
	spin_unlock_irqrestore(&yz_lifecycle_lock, flags);

	if (tracked) {
		pr_info("yukizygisk: lifecycle: [gone] app pid=%d uid=%u\n",
			p->pid, uid);
		yz_fd_handoff_release(p);
	}
}

void yz_lifecycle_init(void)
{
	int ret = yz_lifecycle_register_tracepoint(
	    &yz_lifecycle_trace_fork_tp, "sched_process_fork",
	    (void *)yz_lifecycle_on_fork);

	if (ret) {
		pr_err(
		    "yukizygisk: lifecycle: register fork probe failed: %d\n",
		    ret);
		return;
	}

	ret = yz_lifecycle_register_tracepoint(&yz_lifecycle_trace_free_tp,
					       "sched_process_free",
					       (void *)yz_lifecycle_on_free);
	if (ret) {
		pr_err(
		    "yukizygisk: lifecycle: register free probe failed: %d\n",
		    ret);
		yz_lifecycle_unregister_tracepoint(
		    &yz_lifecycle_trace_fork_tp, (void *)yz_lifecycle_on_fork);
		tracepoint_synchronize_unregister();
		return;
	}

	yz_lifecycle_setresuid_monitor_init();
	pr_info("yukizygisk: lifecycle: lifecycle state machine armed\n");
}

void yz_lifecycle_exit(void)
{
	yz_lifecycle_setresuid_monitor_exit();
	yz_lifecycle_specialize_events_reset();
	yz_lifecycle_unregister_tracepoint(&yz_lifecycle_trace_fork_tp,
					   (void *)yz_lifecycle_on_fork);
	yz_lifecycle_unregister_tracepoint(&yz_lifecycle_trace_free_tp,
					   (void *)yz_lifecycle_on_free);
	tracepoint_synchronize_unregister();
	yz_lifecycle_reset();
	yz_fd_handoff_cancel_all();
}

#else /* !CONFIG_TRACEPOINTS */

void yz_lifecycle_init(void)
{
	pr_warn("yukizygisk: lifecycle: CONFIG_TRACEPOINTS off; lifecycle "
		"monitor disabled\n");
}

void yz_lifecycle_exit(void)
{
	yz_lifecycle_reset();
	yz_fd_handoff_cancel_all();
}

#endif /* CONFIG_TRACEPOINTS */

/* current == the specializing child; dropping to an app uid reveals its
 * identity -- the injection decision point. */
void yz_lifecycle_on_setresuid(uid_t old_uid, uid_t new_uid)
{
	unsigned long flags;
	pid_t pid = current->pid;
	bool specialized = false;
	int i;

	(void)old_uid;

	if (new_uid < 10000) /* app uids only */
		return;

	/* Isolated processes (appId 90000-99999) live in a tightly confined
	 * sandbox the core already tears itself out of in-process. The kernel
	 * must not specialize them or broker fds into them -- that domain is
	 * expected to stay pristine, and any kernel-side residue there is
	 * observable from inside the sandbox. */
	if (new_uid % 100000 >= 90000)
		return;

	spin_lock_irqsave(&yz_lifecycle_lock, flags);
	i = yz_lifecycle_slot_of(pid);
	if (i >= 0 && yz_lifecycle_children[i].state == YZ_LIFECYCLE_FORKED &&
	    yz_lifecycle_children[i].start_boottime ==
		current->start_boottime) {
		yz_lifecycle_children[i].uid = new_uid;
		yz_lifecycle_children[i].state = YZ_LIFECYCLE_SPECIALIZED;
		specialized = true;
	}
	spin_unlock_irqrestore(&yz_lifecycle_lock, flags);

	if (specialized) {
		yz_lifecycle_queue_specialize_event(pid, new_uid,
						    new_uid % 100000);
	}
}
