/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Runtime and early load policy transport.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */

#pragma once

#include "userspace/zygisk/daemon/zygiskd.hpp"
#include "userspace/zygisk/endpoint.hpp"
#include "userspace/zygisk/load_policy.hpp"

#include <cerrno>
#include <cstring>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

namespace yukizygisk::config {

inline yz_config early_config(int packet_fd) {
  yz_bootstrap_packet_header header{};
  if (packet_fd >= 0 &&
      pread(packet_fd, &header, sizeof(header), 0) == sizeof(header) &&
      header.magic == YZ_BOOTSTRAP_PACKET_MAGIC &&
      header.version == YZ_BOOTSTRAP_PACKET_VERSION &&
      header.header_size == sizeof(header) &&
      header.entry_size == sizeof(yz_early_native_packet_entry) &&
      header.count <= YZ_NATIVE_TARGET_MAX)
    return from_flags(header.load_flags);
  return defaults;
}

inline bool read_runtime(yz_config *config) {
  int fd = yukizygisk::endpoint::connect();
  if (fd < 0)
    return false;
  timeval timeout{2, 0};
  if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
      setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) {
    close(fd);
    return false;
  }
  const auto request = static_cast<uint8_t>(zygiskd::Request::GetConfig);
  bool ok =
      send(fd, &request, sizeof(request), MSG_NOSIGNAL) == sizeof(request);
  yz_config incoming{};
  size_t received = 0;
  while (ok && received < sizeof(incoming)) {
    ssize_t count = read(fd, reinterpret_cast<char *>(&incoming) + received,
                         sizeof(incoming) - received);
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0) {
      ok = false;
      break;
    }
    received += static_cast<size_t>(count);
  }
  close(fd);
  if (ok)
    *config = incoming;
  return ok;
}

} // namespace yukizygisk::config
