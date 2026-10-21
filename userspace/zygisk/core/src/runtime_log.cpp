/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Non-blocking runtime log transport.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */

#include "log.hpp"
#include "userspace/zygisk/endpoint.hpp"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <cstring>

#ifndef YUKIZYGISK_LOG_SOURCE
#error "YUKIZYGISK_LOG_SOURCE must identify the runtime component"
#endif

namespace {

constexpr auto kLogSource =
    static_cast<zygiskd::LogSource>(YUKIZYGISK_LOG_SOURCE);

struct ErrnoGuard {
  ErrnoGuard() : value(errno) {}
  ErrnoGuard(const ErrnoGuard &) = delete;
  ErrnoGuard &operator=(const ErrnoGuard &) = delete;
  ErrnoGuard(ErrnoGuard &&) = delete;
  ErrnoGuard &operator=(ErrnoGuard &&) = delete;
  ~ErrnoGuard() { errno = value; }

  int value;
};

int connect_zygiskd() {
  return yukizygisk::endpoint::connect(yukizygisk::endpoint::Clock::now(),
                                       true);
}

} // namespace

extern "C" void yz_log(uint8_t level, const char *format, ...) {
  const ErrnoGuard errno_guard;
  if (level > static_cast<uint8_t>(zygiskd::LogLevel::Error))
    return;

  std::array<char, zygiskd::kLogMessageMax + 1> message{};
  va_list args;
  va_start(args, format);
  const int formatted = vsnprintf(message.data(), message.size(), format, args);
  va_end(args);
  if (formatted <= 0)
    return;

  zygiskd::LogHeader header{
      static_cast<zygiskd::LogLevel>(level), kLogSource,
      static_cast<uint16_t>(
          std::min(static_cast<size_t>(formatted), message.size() - 1))};
  const int socket = connect_zygiskd();
  if (socket < 0)
    return;

  std::array<uint8_t, 1 + sizeof(header) + zygiskd::kLogMessageMax> frame{};
  frame[0] = static_cast<uint8_t>(zygiskd::Request::WriteLog);
  memcpy(frame.data() + 1, &header, sizeof(header));
  memcpy(frame.data() + 1 + sizeof(header), message.data(), header.length);
  const size_t frame_size = 1 + sizeof(header) + header.length;
  (void)send(socket, frame.data(), frame_size, MSG_DONTWAIT | MSG_NOSIGNAL);
  close(socket);
}
