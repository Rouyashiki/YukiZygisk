#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>

#include "fixed_policy.h"

#include "host/host.h"
#include "host/policy.h"
#include "host/runtime.h"
#define yz_policy_open(path)                                                   \
	yz_file_open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK, 0)
#define yz_policy_read yz_kernel_read
#define yz_policy_close(file) yz_file_close(file, NULL)
#define YZ_POLICY_PRIMARY "/dev/yukizygisk-policy.boot"

static DEFINE_MUTEX(yz_fixed_lock);
static DEFINE_SPINLOCK(yz_fixed_missing_lock);
static struct yz_fixed_policy_config yz_fixed_config;
static struct yz_fixed_policy_status yz_fixed_status = {
    .version = YZ_FIXED_POLICY_VERSION,
};
static bool yz_fixed_latched;
static int yz_fixed_primary_error;

static int yz_fixed_read_config(void)
{
	const struct cred *saved;
	struct file *file;
	loff_t pos = 0;
	ssize_t size;
	u32 i;
	int ret = 0;

	saved = yz_host_override_creds();

	file = yz_policy_open(YZ_POLICY_PRIMARY);
#ifdef YZ_POLICY_SECONDARY
	if (IS_ERR(file) && PTR_ERR(file) == -ENOENT)
		file = yz_policy_open(YZ_POLICY_SECONDARY);
#endif
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		goto out;
	}
	if (!S_ISREG(file_inode(file)->i_mode) ||
	    !uid_eq(file_inode(file)->i_uid, GLOBAL_ROOT_UID) ||
	    (file_inode(file)->i_mode & 0022) ||
	    i_size_read(file_inode(file)) != sizeof(yz_fixed_config)) {
		ret = -EINVAL;
		goto close;
	}
	size = yz_policy_read(file, &yz_fixed_config, sizeof(yz_fixed_config),
			      &pos);
	if (size != sizeof(yz_fixed_config)) {
		ret = size < 0 ? size : -EIO;
		goto close;
	}
	if (yz_fixed_config.version != YZ_FIXED_POLICY_VERSION ||
	    yz_fixed_config.enabled > 1 || yz_fixed_config.reserved ||
	    yz_fixed_config.count > YZ_FIXED_DOMAIN_MAX) {
		ret = -EINVAL;
		goto close;
	}
	for (i = 0; i < yz_fixed_config.count; i++) {
		const char *name = yz_fixed_config.domains[i];
		size_t len = strnlen(name, YZ_FIXED_NAME_MAX);
		size_t j;

		if (!len || len == YZ_FIXED_NAME_MAX || !strcmp(name, "self")) {
			ret = -EINVAL;
			goto close;
		}
		for (j = 0; j < len; j++) {
			if (!((name[j] >= 'a' && name[j] <= 'z') ||
			      (name[j] >= 'A' && name[j] <= 'Z') ||
			      (j && name[j] >= '0' && name[j] <= '9') ||
			      name[j] == '_')) {
				ret = -EINVAL;
				goto close;
			}
		}
	}
close:
	yz_policy_close(file);
out:
	yz_host_revert_creds(saved);

	return ret;
}

int yz_fixed_policy_latch(void)
{
	int ret = 0;

	mutex_lock(&yz_fixed_lock);
	if (!yz_fixed_latched) {
		ret = yz_fixed_read_config();
		yz_fixed_status.error = ret;
		if (!ret) {
			yz_fixed_status.requested = yz_fixed_config.enabled;
			if (!yz_fixed_status.requested) {
				yz_host_policy_select_temporary();
				smp_store_release(&yz_fixed_status.initialized, 1);
			}
			yz_fixed_latched = true;
		}
	}
	mutex_unlock(&yz_fixed_lock);
	return ret;
}

int yz_fixed_policy_bind_daemon(const struct cred *cred, bool primary)
{
	int ret = 0;

	mutex_lock(&yz_fixed_lock);
	if (!yz_fixed_latched) {
		ret = yz_fixed_status.error ?: -EAGAIN;
	} else if (!yz_fixed_status.initialized) {
		yz_fixed_set_missing(&yz_fixed_status, "", "", "", 0);
		ret = yz_fixed_policy_verify(&yz_fixed_config, cred,
					     &yz_fixed_status);
		yz_fixed_status.error = ret;
		if (!ret) {
			smp_store_release(&yz_fixed_status.active, 1);
			smp_store_release(&yz_fixed_status.initialized, 1);
		}
		pr_info_ratelimited("yukizygisk: fixed policy requested=%u "
				    "active=%u error=%d\n",
				    yz_fixed_status.requested,
				    yz_fixed_status.active, ret);
	} else if (yz_fixed_status.active) {
		ret = yz_fixed_policy_live_error(cred, NULL);
	}
	if (primary)
		yz_fixed_primary_error = ret;
	mutex_unlock(&yz_fixed_lock);
	return ret;
}

bool yz_fixed_policy_active(void)
{
	/* Keep the fixed enforcement path selected even after a revocation. */
	return smp_load_acquire(&yz_fixed_status.active) != 0;
}

bool yz_fixed_policy_ready(void)
{
	return smp_load_acquire(&yz_fixed_status.initialized) != 0 &&
	       (!READ_ONCE(yz_fixed_status.requested) ||
		(yz_fixed_policy_active() &&
		 !yz_fixed_policy_live_error(NULL, NULL)));
}

void yz_fixed_set_missing(struct yz_fixed_policy_status *status,
			  const char *source, const char *target,
			  const char *class_name, u32 av)
{
	strscpy(status->source, source, sizeof(status->source));
	strscpy(status->target, target, sizeof(status->target));
	strscpy(status->class_name, class_name, sizeof(status->class_name));
	status->missing_av = av;
}

void yz_fixed_policy_missing(const char *source, const char *target,
			     const char *class_name, u32 av)
{
	unsigned long flags;

	spin_lock_irqsave(&yz_fixed_missing_lock, flags);
	yz_fixed_set_missing(&yz_fixed_status, source, target, class_name, av);
	spin_unlock_irqrestore(&yz_fixed_missing_lock, flags);
}

void yz_fixed_policy_status(struct yz_fixed_policy_status *status)
{
	unsigned long flags;

	mutex_lock(&yz_fixed_lock);
	spin_lock_irqsave(&yz_fixed_missing_lock, flags);
	*status = yz_fixed_status;
	spin_unlock_irqrestore(&yz_fixed_missing_lock, flags);
	if (status->active) {
		struct yz_fixed_policy_status detail = {};

		status->error = yz_fixed_policy_live_error(NULL, &detail) ?:
				yz_fixed_primary_error;
		if (status->error) {
			status->active = 0;
			yz_fixed_set_missing(status, detail.source,
					     detail.target, detail.class_name,
					     detail.missing_av);
		}
	}
	mutex_unlock(&yz_fixed_lock);
}
