/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Authenticated daemon health for explicit Viola recovery.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */
#include "recovery.h"
#include "userspace/zygisk/daemon_health_client.hpp"

namespace health = yukizygisk::health;

int viola_recovery_lock(void) {
  const int directory = health::open_recovery_directory();
  if (directory < 0)
    return -errno;
  const int fd =
      openat(directory, "ensure.lock",
             O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600);
  const int saved = errno;
  close(directory);
  if (fd < 0)
    return -saved;
  struct stat status{};
  int result = fstat(fd, &status) ? -errno : 0;
  if (!result && (!S_ISREG(status.st_mode) || status.st_uid != 0 ||
                  status.st_nlink != 1 || (status.st_mode & 0777) != 0600))
    result = -EACCES;
  if (!result && flock(fd, LOCK_EX | LOCK_NB))
    result = -errno;
  if (result) {
    close(fd);
    return result;
  }
  return fd;
}

int viola_daemon_lock(unsigned abi) {
  if (abi != 1 && abi != 2)
    return -EINVAL;
  const int fd = health::lock_daemon(abi);
  return fd < 0 ? -errno : fd;
}

void viola_daemon_health(int control, int timeout_ms,
                         struct viola_health replies[2]) {
  health::ViolaIdentityContext context{control};
  const auto values =
      health::query_all(timeout_ms, health::verify_viola_identity, &context);
  for (unsigned index = 0; index < values.size(); ++index) {
    const auto &value = values[index];
    auto &reply = replies[index];
    reply = {};
    switch (value.availability) {
    case health::Availability::Available:
      reply.state = VIOLA_HEALTH_AVAILABLE;
      break;
    case health::Availability::Missing:
      reply.state = VIOLA_HEALTH_MISSING;
      break;
    case health::Availability::Unresponsive:
      reply.state = VIOLA_HEALTH_UNRESPONSIVE;
      break;
    case health::Availability::Unsupported:
      reply.state = VIOLA_HEALTH_UNSUPPORTED;
      break;
    case health::Availability::IdentityError:
      reply.state = VIOLA_HEALTH_IDENTITY_ERROR;
      break;
    default:
      reply.state = VIOLA_HEALTH_ERROR;
      break;
    }
    reply.error = value.error;
    reply.pid = value.snapshot.pid;
    reply.ready = (value.snapshot.flags & health::Ready) != 0;
    reply.reboot_required =
        (value.snapshot.flags & health::RebootRequired) != 0;
    reply.catalog_error = value.snapshot.catalog_error;
  }
}
