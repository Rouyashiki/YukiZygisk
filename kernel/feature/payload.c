/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Authenticated payload staging and file descriptor installation.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>

#include "internal.h"
#include "klog.h"
#include "host/host.h"
#include "host/runtime.h"
#include "core/auth.h"

void yz_payload_close_fd(int fd)
{
	yz_close_fd((unsigned int)fd);
}

void yz_payload_cache_name(char *buf, size_t len)
{
	size_t i;

	if (!len)
		return;
	for (i = 0; i + 1 < len && i < sizeof(YZ_VMA_NAME) - 1; i++)
		buf[i] = YZ_VMA_NAME[i];
	buf[i] = '\0';
}

/* Stage a private shmem payload fd in current. */
int yz_payload_stage_image(const char *path, const char *name,
			   struct yz_file_load_policy *policy_state,
			   unsigned int core_role, bool compat)
{
	const struct cred *old_cred;
	struct file *src, *mfd;
	void *buf;
	loff_t sz, pos;
	ssize_t r;
	int fd, ret;

	/* Read payload with the host-provided privileged credential. */
	old_cred = yz_host_override_creds();

	src = yz_file_open(path, O_RDONLY, 0);
	if (IS_ERR(src)) {
		yz_host_revert_creds(old_cred);
		pr_info("yukizygisk: payload: [2c-3b] open %s failed: %ld\n",
			path, PTR_ERR(src));
		return -ENOENT;
	}
	if (!S_ISREG(file_inode(src)->i_mode)) {
		yz_file_close(src, NULL);
		yz_host_revert_creds(old_cred);
		return -EINVAL;
	}

	sz = i_size_read(file_inode(src));
	if (sz <= 0 || sz > YZ_LOADER_MAX_SZ) {
		yz_file_close(src, NULL);
		yz_host_revert_creds(old_cred);
		return -EINVAL;
	}

	buf = kvmalloc(sz, GFP_KERNEL);
	if (!buf) {
		yz_file_close(src, NULL);
		yz_host_revert_creds(old_cred);
		return -ENOMEM;
	}
	pos = 0;
	r = yz_kernel_read(src, buf, sz, &pos);

	yz_host_revert_creds(old_cred);
	old_cred = NULL;

	if (r != sz) {
		pr_info(
		    "yukizygisk: payload: [2c-3b] read %s short: %zd/%lld\n",
		    path, r, (long long)sz);
		yz_file_close(src, NULL);
		kvfree(buf);
		return r < 0 ? (int)r : -EIO;
	}

	yz_file_close(src, NULL);

	if (core_role) {
		ret = yz_auth_check_payload(core_role, compat, buf, sz);
		if (ret) {
			kvfree(buf);
			return ret;
		}
	}

	mfd = shmem_file_setup(name, sz, 0);
	if (IS_ERR(mfd)) {
		long err = PTR_ERR(mfd);

		pr_info("yukizygisk: payload: [2c-3b] shmem %s failed: %ld\n",
			name, err);
		if (policy_state)
			yz_load_policy_restore_state(policy_state);
		kvfree(buf);
		return err;
	}
	/* shmem_file_setup lacks FMODE_PREAD/PWRITE by default. */
	mfd->f_mode |= FMODE_PREAD | FMODE_PWRITE | FMODE_LSEEK;
	pos = 0;
	old_cred = yz_host_override_creds();
	r = yz_kernel_write(mfd, buf, sz, &pos);
	yz_host_revert_creds(old_cred);
	old_cred = NULL;
	kvfree(buf);
	if (r != sz) {
		pr_info("yukizygisk: payload: [2c-3b] write staged %s short: "
			"%zd/%lld\n",
			path, r, (long long)sz);
		if (policy_state)
			yz_load_policy_restore_state(policy_state);
		fput(mfd);
		return r < 0 ? (int)r : -EIO;
	}
	if (core_role) {
		ret = yz_auth_seal_image(mfd);
		if (ret) {
			fput(mfd);
			return ret;
		}
	}

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		fput(mfd);
		return fd;
	}
	if (policy_state) {
		ret = yz_host_file_load_policy_allow_current(mfd, policy_state);
		if (ret) {
			pr_info("yukizygisk: payload: [2c-3b] staged policy "
				"allow %s "
				"failed: %d\n",
				path, ret);
			put_unused_fd(fd);
			fput(mfd);
			return ret;
		}
	}
	fd_install(fd, mfd); /* consumes the shmem reference */

	pr_info(
	    "yukizygisk: payload: [2c-3b] staged %s (%lld bytes) -> fd=%d\n",
	    path, (long long)sz, fd);
	return fd;
}

/* Third-party native modules retain their existing independent trust model. */
int yz_payload_stage_fd(const char *path, const char *name,
			struct yz_file_load_policy *policy_state)
{
	return yz_payload_stage_image(path, name, policy_state, 0, false);
}

/* Stage a real file-backed payload fd in current. */
int yz_payload_stage_file_fd(const char *path,
			     struct yz_file_load_policy *policy_state)
{
	const struct cred *old_cred;
	struct file *file;
	loff_t sz;
	int fd;
	int ret;

	old_cred = yz_host_override_creds();
	file = yz_file_open(path, O_RDONLY, 0);
	yz_host_revert_creds(old_cred);
	if (IS_ERR(file)) {
		pr_info(
		    "yukizygisk: payload: [2c-3b] open real %s failed: %ld\n",
		    path, PTR_ERR(file));
		return PTR_ERR(file);
	}
	if (!S_ISREG(file_inode(file)->i_mode)) {
		yz_file_close(file, NULL);
		return -EINVAL;
	}

	sz = i_size_read(file_inode(file));
	if (sz <= 0 || sz > YZ_LOADER_MAX_SZ) {
		yz_file_close(file, NULL);
		return -EINVAL;
	}

	if (policy_state) {
		ret =
		    yz_host_file_load_policy_allow_current(file, policy_state);
		if (ret) {
			pr_info(
			    "yukizygisk: payload: [2c-3b] load policy allow %s "
			    "failed: %d\n",
			    path, ret);
			yz_file_close(file, NULL);
			return ret;
		}
	}

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		if (policy_state)
			yz_load_policy_restore_state(policy_state);
		yz_file_close(file, NULL);
		return fd;
	}
	fd_install(fd, file);

	pr_info("yukizygisk: payload: [2c-3b] staged real %s (%lld bytes) -> "
		"fd=%d\n",
		path, (long long)sz, fd);
	return fd;
}
