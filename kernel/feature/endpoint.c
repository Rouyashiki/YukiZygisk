#include <linux/binfmts.h>
#include <linux/cred.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/highmem.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/pagemap.h>
#include <linux/pid.h>
#include <linux/sched/signal.h>
#include <linux/shmem_fs.h>
#include <linux/spinlock.h>
#include <linux/tracepoint.h>
#include <linux/uaccess.h>
#include <linux/un.h>
#include <linux/version.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <trace/events/sched.h>

#include "core/auth.h"
#include "internal.h"

struct yz_endpoint_slot {
	struct file *file;
	struct page *page;
	struct yz_endpoint_state *state;
	struct pid *owner;
	u64 generation;
	u64 start_boottime;
	char name[YZ_ENDPOINT_NAME_LENGTH];
};

static struct yz_endpoint_slot yz_endpoints[2];
static DEFINE_SPINLOCK(yz_endpoint_lock);
static struct tracepoint *yz_endpoint_exit_tp;
static struct tracepoint *yz_endpoint_exec_tp;
static bool yz_endpoint_ready;
static bool yz_endpoint_accepting;

static struct yz_endpoint_slot *yz_endpoint_slot(u32 abi)
{
	if (abi != YZ_RUNTIME_ABI_32 && abi != YZ_RUNTIME_ABI_64)
		return NULL;
	return &yz_endpoints[abi - 1];
}

static void yz_endpoint_publish(struct yz_endpoint_slot *slot, const char *name)
{
	struct yz_endpoint_state *state = slot->state;
	u32 sequence = READ_ONCE(state->sequence);

	WRITE_ONCE(state->sequence, sequence + 1);
	smp_wmb();
	state->available = name != NULL;
	state->pid = name ? pid_nr(slot->owner) : 0;
	state->start_boottime = name ? slot->start_boottime : 0;
	state->generation = slot->generation;
	state->name_length = name ? YZ_ENDPOINT_NAME_LENGTH : 0;
	if (name)
		memcpy(state->name, name, sizeof(state->name));
	else
		memset(state->name, 0, sizeof(state->name));
	smp_wmb();
	WRITE_ONCE(state->sequence, sequence + 2);
}

static void yz_endpoint_clear(struct yz_endpoint_slot *slot)
{
	if (!slot->state)
		return;
	yz_endpoint_publish(slot, NULL);
	put_pid(slot->owner);
	slot->owner = NULL;
	memset(slot->name, 0, sizeof(slot->name));
	slot->start_boottime = 0;
}

void yz_endpoint_enable(void)
{
	unsigned long flags;
	unsigned int i;

	spin_lock_irqsave(&yz_endpoint_lock, flags);
	yz_endpoint_accepting = true;
	for (i = 0; i < ARRAY_SIZE(yz_endpoints); ++i) {
		struct yz_endpoint_slot *slot = &yz_endpoints[i];

		if (slot->owner)
			yz_endpoint_publish(slot, slot->name);
	}
	spin_unlock_irqrestore(&yz_endpoint_lock, flags);
}

void yz_endpoint_suspend(void)
{
	unsigned long flags;
	unsigned int i;

	spin_lock_irqsave(&yz_endpoint_lock, flags);
	yz_endpoint_accepting = false;
	for (i = 0; i < ARRAY_SIZE(yz_endpoints); ++i)
		if (yz_endpoints[i].state)
			yz_endpoint_publish(&yz_endpoints[i], NULL);
	spin_unlock_irqrestore(&yz_endpoint_lock, flags);
}

void yz_endpoint_invalidate(void)
{
	unsigned long flags;
	unsigned int i;

	spin_lock_irqsave(&yz_endpoint_lock, flags);
	yz_endpoint_accepting = false;
	for (i = 0; i < ARRAY_SIZE(yz_endpoints); ++i)
		yz_endpoint_clear(&yz_endpoints[i]);
	spin_unlock_irqrestore(&yz_endpoint_lock, flags);
}

static void yz_endpoint_retire(struct task_struct *task)
{
	unsigned long flags;
	unsigned int i;

	spin_lock_irqsave(&yz_endpoint_lock, flags);
	for (i = 0; i < ARRAY_SIZE(yz_endpoints); ++i) {
		struct yz_endpoint_slot *slot = &yz_endpoints[i];

		if (slot->owner && slot->owner == task_tgid(task))
			yz_endpoint_clear(slot);
	}
	spin_unlock_irqrestore(&yz_endpoint_lock, flags);
}

static void yz_endpoint_on_exit(void *data, struct task_struct *task
#ifdef YZ_EXIT_HAS_GROUP_DEAD
				,
				bool group_dead
#endif
)
{
#ifdef YZ_EXIT_HAS_GROUP_DEAD
	if (!group_dead)
		return;
#else
	if (atomic_read(&task->signal->live))
		return;
#endif
	yz_endpoint_retire(task);
}

static void yz_endpoint_on_exec(void *data, struct task_struct *task,
				pid_t old_pid, struct linux_binprm *bprm)
{
	yz_endpoint_retire(task);
}

static void yz_endpoint_find_tp(struct tracepoint *tp, void *data)
{
	if (!strcmp(tp->name, "sched_process_exit"))
		yz_endpoint_exit_tp = tp;
	else if (!strcmp(tp->name, "sched_process_exec"))
		yz_endpoint_exec_tp = tp;
}

bool yz_endpoint_supported(void)
{
	return READ_ONCE(yz_endpoint_ready);
}

int yz_endpoint_install_fd(u32 abi)
{
	struct yz_endpoint_slot *slot = yz_endpoint_slot(abi);
	struct file *file;
	int fd;

	if (!slot)
		return -EINVAL;
	if (!yz_endpoint_supported())
		return -EOPNOTSUPP;
	/* Bind FD security to the recipient without widening domain
	 * permissions. */
	file = dentry_open(&slot->file->f_path, O_RDONLY, current_cred());
	if (IS_ERR(file))
		return PTR_ERR(file);
	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		fput(file);
		return fd;
	}
	fd_install(fd, file);
	return fd;
}

int yz_endpoint_get_fd(void __user *arg)
{
	struct yz_endpoint_fd_cmd cmd;
	int fd;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	if (cmd.version != YZ_ENDPOINT_VERSION || cmd.reserved)
		return -EINVAL;
	fd = yz_endpoint_install_fd(cmd.abi);
	if (fd < 0)
		return fd;
	cmd.fd = fd;
	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		yz_payload_close_fd(fd);
		return -EFAULT;
	}
	return 0;
}

int yz_endpoint_register(void __user *arg)
{
	struct yz_endpoint_register_cmd cmd;
	struct yz_endpoint_slot *slot;
	struct sockaddr_un address = {0};
	struct socket *socket;
	unsigned long flags;
	int error, length, i;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	if (!yz_auth_endpoint_abi(cmd.abi))
		return -EPERM;
	slot = yz_endpoint_slot(cmd.abi);
	if (!slot || cmd.generation)
		return -EINVAL;
	if (!yz_endpoint_supported())
		return -EOPNOTSUPP;
	socket = sockfd_lookup(cmd.listener_fd, &error);
	if (!socket)
		return error;
	error = -EINVAL;
	if (socket->type != SOCK_STREAM || !socket->sk ||
	    socket->sk->sk_family != AF_UNIX ||
	    READ_ONCE(socket->sk->sk_state) != TCP_LISTEN)
		goto out;
	length = kernel_getsockname(socket, (struct sockaddr *)&address);
	if (length != offsetof(struct sockaddr_un, sun_path) + 1 +
			  YZ_ENDPOINT_NAME_LENGTH ||
	    address.sun_path[0])
		goto out;
	for (i = 1; i <= YZ_ENDPOINT_NAME_LENGTH; ++i)
		if (!((address.sun_path[i] >= '0' &&
		       address.sun_path[i] <= '9') ||
		      (address.sun_path[i] >= 'a' &&
		       address.sun_path[i] <= 'f')))
			goto out;
	spin_lock_irqsave(&yz_endpoint_lock, flags);
	if (!yz_endpoint_accepting) {
		spin_unlock_irqrestore(&yz_endpoint_lock, flags);
		error = -ESHUTDOWN;
		goto out;
	}
	put_pid(slot->owner);
	slot->owner = get_pid(task_tgid(current));
	if (!++slot->generation)
		++slot->generation;
	cmd.generation = slot->generation;
	slot->start_boottime = current->group_leader->start_boottime;
	memcpy(slot->name, address.sun_path + 1, sizeof(slot->name));
	yz_endpoint_publish(slot, slot->name);
	spin_unlock_irqrestore(&yz_endpoint_lock, flags);
	error = 0;
	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		spin_lock_irqsave(&yz_endpoint_lock, flags);
		if (slot->generation == cmd.generation &&
		    slot->owner == task_tgid(current))
			yz_endpoint_clear(slot);
		spin_unlock_irqrestore(&yz_endpoint_lock, flags);
		error = -EFAULT;
	}
out:
	sockfd_put(socket);
	return error;
}

int yz_endpoint_unregister(void __user *arg)
{
	struct yz_endpoint_unregister_cmd cmd;
	struct yz_endpoint_slot *slot;
	unsigned long flags;
	int ret = -ESTALE;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	if (!yz_auth_endpoint_abi(cmd.abi))
		return -EPERM;
	slot = yz_endpoint_slot(cmd.abi);
	if (!slot || cmd.reserved || !cmd.generation)
		return -EINVAL;
	spin_lock_irqsave(&yz_endpoint_lock, flags);
	if (slot->generation == cmd.generation &&
	    slot->owner == task_tgid(current)) {
		yz_endpoint_clear(slot);
		ret = 0;
	}
	spin_unlock_irqrestore(&yz_endpoint_lock, flags);
	return ret;
}

static void yz_endpoint_free(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(yz_endpoints); ++i) {
		struct yz_endpoint_slot *slot = &yz_endpoints[i];

		if (slot->state)
			kunmap(slot->page);
		if (slot->page)
			put_page(slot->page);
		if (slot->file)
			fput(slot->file);
		memset(slot, 0, sizeof(*slot));
	}
}

int yz_endpoint_init(void)
{
	unsigned int i;
	int ret;

	for (i = 0; i < ARRAY_SIZE(yz_endpoints); ++i) {
		struct yz_endpoint_slot *slot = &yz_endpoints[i];
		struct file *writable, *readonly;
		struct page *page;

		writable = shmem_file_setup(YZ_VMA_NAME, PAGE_SIZE, 0);
		if (IS_ERR(writable)) {
			ret = PTR_ERR(writable);
			goto fail;
		}
		/* shmem_kernel_file_setup is not exported by every supported
		 * GKI. */
		file_inode(writable)->i_flags |= S_PRIVATE;
		file_inode(writable)->i_uid = GLOBAL_ROOT_UID;
		file_inode(writable)->i_gid = GLOBAL_ROOT_GID;
		file_inode(writable)->i_mode = S_IFREG | 0400;
		readonly =
		    dentry_open(&writable->f_path, O_RDONLY, current_cred());
		fput(writable);
		if (IS_ERR(readonly)) {
			ret = PTR_ERR(readonly);
			goto fail;
		}
		slot->file = readonly;
		mapping_set_unevictable(readonly->f_mapping);
		ret = mapping_deny_writable(readonly->f_mapping);
		if (ret)
			goto fail;
		/* Seal before publication, including privileged /proc/fd
		 * reopeners. */
		SHMEM_I(file_inode(readonly))->seals |=
		    F_SEAL_SEAL | F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW;
		page = shmem_read_mapping_page_gfp(readonly->f_mapping, 0,
						   GFP_KERNEL);
		if (IS_ERR(page)) {
			ret = PTR_ERR(page);
			goto fail;
		}
		slot->page = page;
		slot->state = kmap(page);
		memset(slot->state, 0, sizeof(*slot->state));
		slot->state->version = YZ_ENDPOINT_VERSION;
		slot->state->size = sizeof(*slot->state);
		slot->state->abi = i + 1;
	}
	for_each_kernel_tracepoint(yz_endpoint_find_tp, NULL);
	if (!yz_endpoint_exit_tp || !yz_endpoint_exec_tp) {
		ret = -EOPNOTSUPP;
		goto fail;
	}
	check_trace_callback_type_sched_process_exit(yz_endpoint_on_exit);
	check_trace_callback_type_sched_process_exec(yz_endpoint_on_exec);
	ret = tracepoint_probe_register(yz_endpoint_exit_tp,
					(void *)yz_endpoint_on_exit, NULL);
	if (ret)
		goto fail;
	ret = tracepoint_probe_register(yz_endpoint_exec_tp,
					(void *)yz_endpoint_on_exec, NULL);
	if (ret) {
		tracepoint_probe_unregister(yz_endpoint_exit_tp,
					    (void *)yz_endpoint_on_exit, NULL);
		tracepoint_synchronize_unregister();
		goto fail;
	}
	yz_endpoint_enable();
	WRITE_ONCE(yz_endpoint_ready, true);
	return 0;
fail:
	yz_endpoint_free();
	return ret;
}

void yz_endpoint_exit(void)
{
	if (!yz_endpoint_supported())
		return;
	WRITE_ONCE(yz_endpoint_ready, false);
	tracepoint_probe_unregister(yz_endpoint_exit_tp,
				    (void *)yz_endpoint_on_exit, NULL);
	tracepoint_probe_unregister(yz_endpoint_exec_tp,
				    (void *)yz_endpoint_on_exec, NULL);
	tracepoint_synchronize_unregister();
	yz_endpoint_invalidate();
	/* Only native shmem operations remain reachable through client VMAs. */
	yz_endpoint_free();
}

#ifdef YZ_ENDPOINT_VFS_NS
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS(__stringify(YZ_ENDPOINT_VFS_NS));
#else
MODULE_IMPORT_NS(YZ_ENDPOINT_VFS_NS);
#endif
#endif
