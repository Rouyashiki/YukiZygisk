/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Kernel control boundary for configuration reload regressions.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */

#include "kernel/uapi/yukizygisk.h"

#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iterator>
#include <string>
#include <sys/syscall.h>

namespace {
int control_fd = -1;
}

extern "C" long __real_syscall(long number, ...);
extern "C" int __real_ioctl(int fd, unsigned long request, ...);

extern "C" long __wrap_syscall(long number, ...) {
  assert(number == SYS_prctl);
  va_list args;
  va_start(args, number);
  const auto option = va_arg(args, unsigned long);
  const auto magic = va_arg(args, unsigned long);
  const auto output = va_arg(args, unsigned long);
  const auto unused1 = va_arg(args, unsigned long);
  const auto unused2 = va_arg(args, unsigned long);
  va_end(args);
  assert(option == YZ_PRCTL_CONTROL_OPTION && magic == YZ_PRCTL_CONTROL_MAGIC);
  assert(output && !unused1 && !unused2);

  const char *mode = std::getenv("YZ_TEST_CONTROL");
  if (!mode)
    return __real_syscall(number, option, magic, output, unused1, unused2);

  auto *delivered_fd = reinterpret_cast<int *>(output);
  if (std::strcmp(mode, "denied") == 0) {
    *delivered_fd = -EACCES;
  } else {
    assert(std::strcmp(mode, "available") == 0 ||
           std::strcmp(mode, "reload-failed") == 0);
    control_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    assert(control_fd >= 0);
    *delivered_fd = control_fd; // Owned and closed by the production Host.
  }
  errno = EINVAL; // The private prctl delivers its result through out_fd.
  return -1;
}

extern "C" int __wrap_ioctl(int fd, unsigned long request, ...) {
  va_list args;
  va_start(args, request);
  void *argument = va_arg(args, void *);
  va_end(args);
  const char *mode = std::getenv("YZ_TEST_CONTROL");
  if (!mode)
    return __real_ioctl(fd, request, argument);

  assert(fd == control_fd && request == YZ_IOCTL_RELOAD && !argument);
  if (std::strcmp(mode, "reload-failed") == 0) {
    errno = EIO;
    return -1;
  }
  // Capture the configuration visible when the reload notification is sent.
  const char *config_path = std::getenv("YZ_TEST_CONFIG");
  const char *trace_path = std::getenv("YZ_TEST_RELOAD_TRACE");
  assert(config_path && trace_path);
  std::ifstream config(config_path);
  assert(config.good());
  const std::string contents{std::istreambuf_iterator<char>(config), {}};
  assert(!config.bad());
  std::ofstream trace(trace_path, std::ios::app);
  trace << contents << '\n';
  trace.flush();
  assert(trace.good());
  return 0;
}
