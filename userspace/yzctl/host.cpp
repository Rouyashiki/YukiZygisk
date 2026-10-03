/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Reusable standalone kernel control client.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */

#include "host.hpp"

#include "uapi/yukizygisk.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace yzctl {

Host::~Host() {
  if (fd_ >= 0)
    close(fd_);
}

bool Host::open(std::string *error) {
  if (fd_ >= 0)
    return true;

  int delivered_fd = -ENODEV;
  errno = 0;
  const long result =
      syscall(SYS_prctl, static_cast<unsigned long>(YZ_PRCTL_CONTROL_OPTION),
              static_cast<unsigned long>(YZ_PRCTL_CONTROL_MAGIC),
              reinterpret_cast<unsigned long>(&delivered_fd), 0UL, 0UL);
  const int saved_errno = errno;
  (void)result;

  if (delivered_fd < 0) {
    // The prctl probe delivers the session result through out_fd; the
    // underlying prctl may still return EINVAL for this private option.
    const int session_errno = delivered_fd >= -4095
                                  ? -delivered_fd
                                  : (saved_errno ? saved_errno : EIO);
    if (error != nullptr) {
      *error = "cannot open YukiZygisk kernel control session: ";
      *error += strerror(session_errno);
    }
    errno = session_errno;
    return false;
  }

  const int flags = fcntl(delivered_fd, F_GETFD);
  if (flags < 0 || fcntl(delivered_fd, F_SETFD, flags | FD_CLOEXEC) != 0) {
    const int fd_errno = errno;
    close(delivered_fd);
    if (error != nullptr) {
      *error = "cannot secure YukiZygisk kernel control fd: ";
      *error += strerror(fd_errno);
    }
    errno = fd_errno;
    return false;
  }

  fd_ = delivered_fd;
  return true;
}

int Host::call(unsigned long request, void *arg) const {
  if (fd_ < 0) {
    errno = ENODEV;
    return -1;
  }
  return ioctl(fd_, request, arg);
}

bool Host::query_viola(yz_viola_status *status, bool *supported,
                       std::string *error) const {
  if (!status || !supported) {
    errno = EINVAL;
    return false;
  }
  *supported = false;
  *status = {};
  status->size = sizeof(*status);
  status->version = YZ_VIOLA_VERSION;
  if (call(YZ_IOCTL_VIOLA_STATUS, status) != 0) {
    // Existing kernels have no Viola ioctl. Keep their status ABI usable,
    // without interpreting its absence as successful authentication.
    if (errno == ENOTTY)
      return true;
    if (error) {
      *error = "cannot query Viola status: ";
      *error += strerror(errno);
    }
    return false;
  }
  if (status->size != sizeof(*status) ||
      status->version != YZ_VIOLA_VERSION) {
    if (error)
      *error = "unsupported Viola status ABI";
    errno = EPROTO;
    return false;
  }
  *supported = true;
  return true;
}

bool Host::available() const { return fd_ >= 0; }

} // namespace yzctl
