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
#include "userspace/zygisk/load_policy.hpp"

#include <cerrno>
#include <cstring>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

namespace yukizygisk::config {

inline yz_config early_config(int packet_fd) {
  yz_early_native_packet_header header{};
  if (packet_fd >= 0 &&
      pread(packet_fd, &header, sizeof(header), 0) == sizeof(header) &&
      header.magic == YZ_EARLY_NATIVE_PACKET_MAGIC &&
      header.version == YZ_EARLY_NATIVE_VERSION &&
      header.header_size == sizeof(header) &&
      header.entry_size == sizeof(yz_early_native_packet_entry) &&
      header.count <= YZ_NATIVE_TARGET_MAX)
    return from_flags(header.load_flags);
  return defaults;
}

inline bool read_runtime(yz_config *config) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0)
    return false;
  timeval timeout{2, 0};
  if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
      setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) {
    close(fd);
    return false;
  }
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  constexpr size_t name_size = sizeof(zygiskd::kSocketName) - 1;
  memcpy(address.sun_path + 1, zygiskd::kSocketName, name_size);
  const auto size =
      static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 + name_size);
  const auto request = static_cast<uint8_t>(zygiskd::Request::GetConfig);
  bool ok =
      connect(fd, reinterpret_cast<sockaddr *>(&address), size) == 0 &&
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
