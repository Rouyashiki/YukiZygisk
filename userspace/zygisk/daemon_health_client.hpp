/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Authenticated daemon health client.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */
#pragma once

#include "daemon_health.hpp"
#include "daemon_state.hpp"
#include "kernel/uapi/viola.h"
#include "kernel/uapi/viola_health.h"

#include <sys/ioctl.h>

#include <elf.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/un.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <vector>

namespace yukizygisk::health {

enum class Availability {
  Available,
  Missing,
  Unresponsive,
  Unsupported,
  IdentityError,
  Error,
};

enum class ExecutionBackend { Unknown, Native, Tango };

struct QueryResult {
  Availability availability = Availability::Error;
  int error = 0;
  Snapshot snapshot;
  ExecutionBackend execution_backend = ExecutionBackend::Unknown;
};

using IdentityVerifier = bool (*)(uint32_t abi, pid_t pid, uint64_t start_ticks,
                                  void *context);

// One context per query: both ends of the exchange must name the same
// authenticated kernel session, even across revocation, exec or KO reload.
struct ViolaIdentityContext {
  int control_fd = -1;
  std::array<yz_viola_daemon_identity_cmd, 2> identities{};
};

inline bool verify_viola_identity(uint32_t abi, pid_t pid, uint64_t start_ticks,
                                  void *opaque) {
  if (opaque == nullptr || (abi != 1 && abi != 2) || pid <= 0) {
    errno = EINVAL;
    return false;
  }
  auto &context = *static_cast<ViolaIdentityContext *>(opaque);
  yz_viola_daemon_identity_cmd identity{};
  identity.size = sizeof(identity);
  identity.version = YZ_VIOLA_DAEMON_IDENTITY_VERSION;
  identity.abi = abi;
  const long ticks = sysconf(_SC_CLK_TCK);
  if (ticks <= 0 || ticks > 1000000000) {
    errno = EINVAL;
    return false;
  }
  if (ioctl(context.control_fd, YZ_IOCTL_VIOLA_DAEMON_IDENTITY, &identity) != 0)
    return false;
  if (identity.size != sizeof(identity) ||
      identity.version != YZ_VIOLA_DAEMON_IDENTITY_VERSION ||
      identity.abi != abi || identity.reserved != 0 ||
      identity.pid != static_cast<uint32_t>(pid) ||
      identity.state != YZ_VIOLA_READY || identity.owner_alive != 1 ||
      identity.role != (abi == 1 ? YZ_VIOLA_DAEMON32 : YZ_VIOLA_DAEMON64) ||
      identity.start_boottime_ns == 0 || identity.epoch == 0 ||
      identity.generation == 0) {
    errno = EACCES;
    return false;
  }
  const uint64_t expected_ticks =
      (identity.start_boottime_ns / 1000000000) * static_cast<uint64_t>(ticks) +
      ((identity.start_boottime_ns % 1000000000) *
       static_cast<uint64_t>(ticks)) /
          1000000000;
  if (expected_ticks != start_ticks) {
    errno = ESTALE;
    return false;
  }
  auto &previous = context.identities[abi - 1];
  if (previous.epoch != 0 &&
      (previous.pid != identity.pid ||
       previous.start_boottime_ns != identity.start_boottime_ns ||
       previous.epoch != identity.epoch ||
       previous.generation != identity.generation)) {
    errno = ESTALE;
    return false;
  }
  previous = identity;
  return true;
}

namespace client_detail {

using Deadline = std::chrono::steady_clock::time_point;

struct Connection {
  Connection() = default;
  Connection(const Connection &) = delete;
  Connection &operator=(const Connection &) = delete;
  Connection(Connection &&) = delete;
  Connection &operator=(Connection &&) = delete;
  int fd = -1;
  int pidfd = -1;
  pid_t pid = 0;
  uint64_t start_ticks = 0;
  dev_t executable_device = 0;
  ino_t executable_inode = 0;
  size_t received = 0;
  unsigned stage = 0;
  ExecutionBackend execution_backend = ExecutionBackend::Unknown;
  QueryResult result;
  ~Connection() {
    if (fd >= 0)
      close(fd);
    if (pidfd >= 0)
      close(pidfd);
  }
  void finish(Availability availability, int error) {
    result.availability = availability;
    result.error = error;
    result.execution_backend = availability == Availability::Available
                                   ? execution_backend
                                   : ExecutionBackend::Unknown;
    stage = 0;
  }
};

inline bool identity(Connection &connection, uint32_t abi, Deadline deadline,
                     IdentityVerifier verify, void *context) {
  struct ucred peer{};
  socklen_t length = sizeof(peer);
  if (verify == nullptr ||
      getsockopt(connection.fd, SOL_SOCKET, SO_PEERCRED, &peer, &length) != 0 ||
      length != sizeof(peer) || peer.uid != 0 || peer.pid <= 0)
    return false;
  connection.pid = peer.pid;
  connection.start_ticks = process_start_ticks(peer.pid);
  if (connection.start_ticks == 0 ||
      !verify(abi, peer.pid, connection.start_ticks, context))
    return false;
#ifdef SYS_pidfd_open
  connection.pidfd = static_cast<int>(syscall(SYS_pidfd_open, peer.pid, 0));
  if (connection.pidfd < 0)
    return false;
#endif
  char path[64];
  (void)snprintf(path, sizeof(path), "/proc/%d/exe", peer.pid);
  const int executable = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
  if (executable < 0)
    return false;
  struct stat actual{};
  Elf32_Ehdr header{};
  const bool ok = fstat(executable, &actual) == 0 && S_ISREG(actual.st_mode) &&
                  pread(executable, &header, sizeof(header), 0) ==
                      static_cast<ssize_t>(sizeof(header)) &&
                  memcmp(header.e_ident, ELFMAG, SELFMAG) == 0 &&
                  header.e_ident[EI_DATA] == ELFDATA2LSB;
  close(executable);
  if (!ok)
    return false;
  // The kernel authenticates frozen daemon bytes and Tango's interpreter.
  // The ELF class describes the already-authenticated execution backend only.
  if (abi == 1 && header.e_ident[EI_CLASS] == ELFCLASS64 &&
      header.e_machine == EM_AARCH64)
    connection.execution_backend = ExecutionBackend::Tango;
  else if ((abi == 1 && header.e_ident[EI_CLASS] == ELFCLASS32 &&
            header.e_machine == EM_ARM) ||
           (abi == 2 && header.e_ident[EI_CLASS] == ELFCLASS64 &&
            header.e_machine == EM_AARCH64))
    connection.execution_backend = ExecutionBackend::Native;
  else
    return false;
  connection.executable_device = actual.st_dev;
  connection.executable_inode = actual.st_ino;
  return connection.start_ticks == process_start_ticks(peer.pid) &&
         std::chrono::steady_clock::now() < deadline;
}

inline std::array<QueryResult, 2> query_mask(unsigned mask, int timeout_ms,
                                             IdentityVerifier verify,
                                             void *context) {
  using Clock = std::chrono::steady_clock;
  const auto deadline =
      Clock::now() + std::chrono::milliseconds(std::max(0, timeout_ms));
  std::array<Connection, 2> connections;
  for (size_t index = 0; index < connections.size(); ++index) {
    auto &connection = connections[index];
    if ((mask & (1U << index)) == 0)
      continue;
    connection.fd =
        socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (connection.fd < 0) {
      connection.finish(Availability::Error, errno);
      continue;
    }
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    const char *name = index == 0 ? "zygiskd32" : "zygiskd64";
    const size_t name_length = strlen(name);
    memcpy(address.sun_path + 1, name, name_length);
    const auto address_length = static_cast<socklen_t>(
        offsetof(sockaddr_un, sun_path) + 1 + name_length);
    if (connect(connection.fd, reinterpret_cast<sockaddr *>(&address),
                address_length) != 0 &&
        errno != EINPROGRESS) {
      const int error = errno;
      connection.finish(error == ENOENT || error == ECONNREFUSED
                            ? Availability::Missing
                        : error == EAGAIN ? Availability::Unresponsive
                                          : Availability::Error,
                        error);
      continue;
    }
    connection.stage = 1;
  }
  for (;;) {
    std::array<pollfd, 2> descriptors{};
    bool pending = false;
    for (size_t index = 0; index < connections.size(); ++index) {
      const auto &connection = connections[index];
      descriptors[index] = {
          connection.stage == 0 ? -1 : connection.fd,
          static_cast<short>(connection.stage == 3 ? POLLIN : POLLOUT), 0};
      pending |= connection.stage != 0;
    }
    if (!pending)
      break;
    const auto remaining =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline -
                                                              Clock::now());
    if (remaining.count() <= 0)
      break;
    const int ready = poll(descriptors.data(), descriptors.size(),
                           static_cast<int>(remaining.count()));
    if (ready < 0 && errno == EINTR)
      continue;
    if (ready <= 0)
      break;
    for (size_t index = 0; index < connections.size(); ++index) {
      auto &connection = connections[index];
      if (connection.stage == 0 || descriptors[index].revents == 0)
        continue;
      if (connection.stage == 1) {
        int error = 0;
        socklen_t length = sizeof(error);
        if (getsockopt(connection.fd, SOL_SOCKET, SO_ERROR, &error, &length) !=
                0 ||
            error != 0) {
          connection.finish(Availability::Error, error != 0 ? error : errno);
          continue;
        }
        errno = 0;
        if (!identity(connection, static_cast<uint32_t>(index + 1), deadline,
                      verify, context)) {
          const int error = errno != 0 ? errno : EACCES;
          const bool expired = Clock::now() >= deadline;
          const bool busy = error == EAGAIN || error == EWOULDBLOCK;
          connection.finish(expired || busy ? Availability::Unresponsive
                                            : Availability::IdentityError,
                            expired ? ETIMEDOUT : error);
          continue;
        }
        connection.stage = 2;
      }
      if (connection.stage == 2) {
        const ssize_t sent = send(connection.fd, &kRequest, sizeof(kRequest),
                                  MSG_DONTWAIT | MSG_NOSIGNAL);
        if (sent < 0 && (errno == EAGAIN || errno == EINTR))
          continue;
        if (sent != 1) {
          connection.finish(Availability::Error, sent < 0 ? errno : EIO);
          continue;
        }
        connection.stage = 3;
      }
      auto *bytes =
          reinterpret_cast<unsigned char *>(&connection.result.snapshot);
      const ssize_t received =
          recv(connection.fd, bytes + connection.received,
               sizeof(Snapshot) - connection.received, MSG_DONTWAIT);
      if (received < 0 && (errno == EAGAIN || errno == EINTR))
        continue;
      if (received <= 0) {
        const bool unsupported = received == 0 && connection.received == 0;
        connection.finish(unsupported ? Availability::Unsupported
                                      : Availability::Error,
                          unsupported     ? EOPNOTSUPP
                          : received == 0 ? EPROTO
                                          : errno);
        continue;
      }
      connection.received += static_cast<size_t>(received);
      const auto &snapshot = connection.result.snapshot;
      if (connection.received >= 8 &&
          (snapshot.version != kVersion || snapshot.size != sizeof(Snapshot))) {
        connection.finish(Availability::Unsupported, EPROTONOSUPPORT);
        continue;
      }
      if (connection.received != sizeof(Snapshot))
        continue;
      if (snapshot.pid != static_cast<uint32_t>(connection.pid) ||
          snapshot.abi != index + 1 ||
          snapshot.start_ticks != connection.start_ticks ||
          process_start_ticks(connection.pid) != connection.start_ticks) {
        connection.finish(Availability::IdentityError, ESTALE);
        continue;
      }
      if (connection.pidfd >= 0) {
        pollfd process{connection.pidfd, POLLIN, 0};
        if (poll(&process, 1, 0) != 0) {
          connection.finish(Availability::IdentityError, ESTALE);
          continue;
        }
      }
      char executable_path[64];
      (void)snprintf(executable_path, sizeof(executable_path), "/proc/%d/exe",
                     connection.pid);
      struct stat executable{};
      if (stat(executable_path, &executable) != 0 ||
          executable.st_dev != connection.executable_device ||
          executable.st_ino != connection.executable_inode) {
        connection.finish(Availability::IdentityError, ESTALE);
        continue;
      }
      errno = 0;
      if (verify == nullptr ||
          !verify(static_cast<uint32_t>(index + 1), connection.pid,
                  connection.start_ticks, context)) {
        const int error = errno != 0 ? errno : ESTALE;
        connection.finish(error == EAGAIN || error == EWOULDBLOCK
                              ? Availability::Unresponsive
                              : Availability::IdentityError,
                          error);
        continue;
      }
      if (snapshot.catalog_error < 0 || snapshot.read_error < 0 ||
          snapshot.save_error < 0 || snapshot.reserved64 != 0 ||
          (snapshot.flags & ~uint32_t{63}) != 0 ||
          static_cast<uint32_t>(snapshot.reader_state) >
              static_cast<uint32_t>(ReaderState::Retrying)) {
        connection.finish(Availability::Error, EPROTO);
        continue;
      }
      connection.finish(Availability::Available, 0);
    }
  }
  std::array<QueryResult, 2> result;
  for (size_t index = 0; index < connections.size(); ++index) {
    auto &connection = connections[index];
    if (connection.stage != 0)
      connection.finish(Availability::Unresponsive, ETIMEDOUT);
    result[index] = connection.result;
  }
  return result;
}

} // namespace client_detail

inline std::array<QueryResult, 2> query_all(int timeout_ms = kQueryTimeoutMs,
                                            IdentityVerifier verify = nullptr,
                                            void *context = nullptr) {
  return client_detail::query_mask(3, timeout_ms, verify, context);
}

inline QueryResult query(uint32_t abi, int timeout_ms = kQueryTimeoutMs,
                         IdentityVerifier verify = nullptr,
                         void *context = nullptr) {
  if (abi != 1 && abi != 2) {
    QueryResult result;
    result.error = EINVAL;
    return result;
  }
  return client_detail::query_mask(1U << (abi - 1), timeout_ms, verify,
                                   context)[abi - 1];
}

} // namespace yukizygisk::health
