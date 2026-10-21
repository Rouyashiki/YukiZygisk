/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Standalone userspace log storage.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */

#include "log.hpp"

#include <ctime>
#include <fcntl.h>
#include <limits.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>

namespace zygiskd::logging {
namespace {

constexpr char kDefaultLogDir[] = "/data/adb/yukizygisk/log";
constexpr off_t kMaxLogSize = static_cast<off_t>(1024) * 1024;
constexpr uint64_t kRateTickMilliseconds = 250;
constexpr uint16_t kRateBurst = 256;
constexpr uint64_t kPriorityRateTickMilliseconds = 1000;
constexpr uint16_t kPriorityRateBurst = 64;
constexpr uint16_t kDaemonRateBurst = 128;
constexpr uint16_t kDaemonPriorityRateBurst = 32;
constexpr size_t kKernelRecordSize = 960;

struct LogPaths {
  std::array<char, PATH_MAX> current{};
  std::array<char, PATH_MAX> rollover{};
};

const LogPaths &log_paths() {
  static const LogPaths paths = [] {
    LogPaths value;
    const char *directory = getenv("YUKIZYGISK_LOG_DIR");
    if (directory == nullptr || *directory == '\0')
      directory = kDefaultLogDir;
    (void)snprintf(value.current.data(), value.current.size(),
                   "%s/zygiskd64.log", directory);
    (void)snprintf(value.rollover.data(), value.rollover.size(),
                   "%s/zygiskd64.1.log", directory);
    return value;
  }();
  return paths;
}

std::atomic_bool g_kernel_mirror{false};
std::atomic<uint64_t> g_runtime_rate_state{kRateBurst};
std::atomic<uint64_t> g_runtime_priority_rate_state{kPriorityRateBurst};
std::atomic<uint64_t> g_daemon_rate_state{kDaemonRateBurst};
std::atomic<uint64_t> g_daemon_priority_rate_state{kDaemonPriorityRateBurst};
std::atomic<uint32_t> g_runtime_dropped{0};
std::atomic<uint32_t> g_daemon_dropped{0};
std::atomic_int g_kernel_fd{-1};

bool take_rate_token(std::atomic<uint64_t> &state, uint16_t burst,
                     uint64_t tick_milliseconds) {
  timespec now{};
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
    return true;
  const uint64_t milliseconds = (static_cast<uint64_t>(now.tv_sec) * 1000) +
                                (static_cast<uint64_t>(now.tv_nsec) / 1000000);
  const uint64_t tick = milliseconds / tick_milliseconds;

  uint64_t old = state.load(std::memory_order_relaxed);
  for (;;) {
    const uint64_t old_tick = old >> 16;
    uint64_t tokens = old & 0xffff;
    if (tick > old_tick)
      tokens = std::min<uint64_t>(burst, tokens + tick - old_tick);
    if (tokens == 0)
      return false;

    const uint64_t next = (tick << 16) | (tokens - 1);
    if (state.compare_exchange_weak(old, next, std::memory_order_relaxed))
      return true;
  }
}

bool should_write(LogLevel level, LogSource source) {
  auto &rate_state =
      source == LogSource::Daemon ? g_daemon_rate_state : g_runtime_rate_state;
  const uint16_t rate_burst =
      source == LogSource::Daemon ? kDaemonRateBurst : kRateBurst;
  if (take_rate_token(rate_state, rate_burst, kRateTickMilliseconds))
    return true;

  auto &priority_rate_state = source == LogSource::Daemon
                                  ? g_daemon_priority_rate_state
                                  : g_runtime_priority_rate_state;
  const uint16_t priority_rate_burst = source == LogSource::Daemon
                                           ? kDaemonPriorityRateBurst
                                           : kPriorityRateBurst;
  return level >= LogLevel::Warning &&
         take_rate_token(priority_rate_state, priority_rate_burst,
                         kPriorityRateTickMilliseconds);
}

int kernel_log_fd() {
  int fd = g_kernel_fd.load(std::memory_order_relaxed);
  if (fd >= 0)
    return fd;

  const int opened = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
  if (opened < 0)
    return -1;
  if (g_kernel_fd.compare_exchange_strong(fd, opened,
                                          std::memory_order_relaxed))
    return opened;
  close(opened);
  return fd;
}

std::atomic<uint32_t> &dropped_counter(LogSource source) {
  return source == LogSource::Daemon ? g_daemon_dropped : g_runtime_dropped;
}

char level_char(LogLevel level) {
  switch (level) {
  case LogLevel::Debug:
    return 'D';
  case LogLevel::Info:
    return 'I';
  case LogLevel::Warning:
    return 'W';
  case LogLevel::Error:
    return 'E';
  }
  return '?';
}

const char *source_name(LogSource source) {
  switch (source) {
  case LogSource::Daemon:
    return "daemon";
  case LogSource::Zygisk:
    return "zygisk";
  case LogSource::Native:
    return "native";
  case LogSource::Linker:
    return "linker";
  }
  return "unknown";
}

int kernel_priority(LogLevel level) {
  switch (level) {
  case LogLevel::Debug:
    return 7;
  case LogLevel::Info:
    return 6;
  case LogLevel::Warning:
    return 4;
  case LogLevel::Error:
    return 3;
  }
  return 6;
}

void sanitize(char *message) {
  for (char *cursor = message; *cursor != '\0'; ++cursor) {
    if (*cursor == '\n' || *cursor == '\r')
      *cursor = ' ';
  }
}

bool write_all(int fd, const char *data, size_t size) {
  while (size > 0) {
    const ssize_t written = ::write(fd, data, size);
    if (written < 0 && errno == EINTR)
      continue;
    if (written <= 0)
      return false;
    data += written;
    size -= static_cast<size_t>(written);
  }
  return true;
}

int open_log_file() {
  const int fd =
      open(log_paths().current.data(),
           O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
           0600);
  if (fd < 0)
    return -1;

  struct stat status{};
  if (flock(fd, LOCK_EX) != 0 || fstat(fd, &status) != 0 ||
      !S_ISREG(status.st_mode) || status.st_uid != 0) {
    close(fd);
    return -1;
  }
  if (fchmod(fd, 0600) != 0) {
    (void)flock(fd, LOCK_UN);
    close(fd);
    return -1;
  }
  return fd;
}

void close_log_file(int fd) {
  (void)flock(fd, LOCK_UN);
  close(fd);
}

void write_file(const char *record, size_t length) {
  int fd = open_log_file();
  if (fd < 0)
    return;

  struct stat status{};
  if (fstat(fd, &status) == 0 &&
      status.st_size >= kMaxLogSize - static_cast<off_t>(length)) {
    if (rename(log_paths().current.data(), log_paths().rollover.data()) == 0) {
      close_log_file(fd);
      fd = open_log_file();
      if (fd < 0)
        return;
    } else {
      (void)ftruncate(fd, 0);
    }
  }
  (void)write_all(fd, record, length);
  close_log_file(fd);
}

void write_kernel(LogLevel level, LogSource source, pid_t pid, uid_t uid,
                  const char *message) {
  if (!g_kernel_mirror.load(std::memory_order_relaxed))
    return;

  std::array<char, kKernelRecordSize> record{};
  const int length =
      snprintf(record.data(), record.size(), "<%d>yukizygisk: %s %s[%d:%u]: %s",
               kernel_priority(level), kDaemonLabel, source_name(source), pid,
               static_cast<unsigned int>(uid), message);
  if (length <= 0)
    return;
  if (static_cast<size_t>(length) >= record.size()) {
    record[record.size() - 4] = '.';
    record[record.size() - 3] = '.';
    record[record.size() - 2] = '.';
  }

  const int fd = kernel_log_fd();
  if (fd < 0)
    return;
  const size_t size = std::min(static_cast<size_t>(length), record.size() - 1);
  (void)write_all(fd, record.data(), size);
}

void emit(LogLevel level, LogSource source, pid_t pid, uid_t uid,
          const char *message) {
  std::array<char, kLogMessageMax + 1> clean{};
  (void)snprintf(clean.data(), clean.size(), "%s", message);
  sanitize(clean.data());

  timespec now{};
  (void)clock_gettime(CLOCK_REALTIME, &now);
  tm local{};
  (void)localtime_r(&now.tv_sec, &local);

  std::array<char, 1400> record{};
  const int length =
      snprintf(record.data(), record.size(),
               "%04d-%02d-%02d %02d:%02d:%02d.%03ld %c/%s %s[%d:%u]: %s\n",
               local.tm_year + 1900, local.tm_mon + 1, local.tm_mday,
               local.tm_hour, local.tm_min, local.tm_sec, now.tv_nsec / 1000000,
               level_char(level), kDaemonLabel, source_name(source), pid,
               static_cast<unsigned int>(uid), clean.data());
  if (length > 0) {
    const size_t size =
        std::min(static_cast<size_t>(length), record.size() - 1);
    write_file(record.data(), size);
  }
  write_kernel(level, source, pid, uid, clean.data());
}

} // namespace

void set_kernel_mirror(bool enabled) {
  g_kernel_mirror.store(enabled, std::memory_order_relaxed);
}

void write(LogLevel level, LogSource source, pid_t pid, uid_t uid,
           const char *message) {
  const int saved_errno = errno;
  if (message == nullptr) {
    errno = saved_errno;
    return;
  }

  auto &dropped = dropped_counter(source);
  if (!should_write(level, source)) {
    (void)dropped.fetch_add(1, std::memory_order_relaxed);
    errno = saved_errno;
    return;
  }
  const uint32_t dropped_count = dropped.exchange(0, std::memory_order_relaxed);
  if (dropped_count > 0) {
    std::array<char, 80> summary{};
    (void)snprintf(summary.data(), summary.size(),
                   "rate limit dropped %u messages", dropped_count);
    emit(LogLevel::Warning, source, pid, uid, summary.data());
  }
  emit(level, source, pid, uid, message);
  errno = saved_errno;
}

void writef(LogLevel level, LogSource source, const char *format, ...) {
  const int saved_errno = errno;
  std::array<char, kLogMessageMax + 1> message{};
  va_list args;
  va_start(args, format);
  const int length = vsnprintf(message.data(), message.size(), format, args);
  va_end(args);
  if (length < 0) {
    errno = saved_errno;
    return;
  }
  write(level, source, getpid(), getuid(), message.data());
  errno = saved_errno;
}

} // namespace zygiskd::logging
