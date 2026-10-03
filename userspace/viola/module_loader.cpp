/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - In-process lkmloader compatibility for verified kernel images.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */
#include "module_loader.h"
#include "third_party/lkmloader/src/loader.hpp"

#include <cerrno>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <linux/memfd.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace {
// lkmloader's syscall adapter is compiled only into its loader translation
// unit. Keep every module-loading SVC inside Viola's authenticated text.
thread_local viola_module_syscall active_admission;
thread_local int module_error;

int sealed_image(const void *image, size_t size) {
  int fd = static_cast<int>(syscall(SYS_memfd_create, "viola-ko",
                                    MFD_CLOEXEC | MFD_ALLOW_SEALING));
  if (fd < 0)
    return -errno;
  const auto *cursor = static_cast<const unsigned char *>(image);
  size_t remaining = size;
  while (remaining) {
    ssize_t count = write(fd, cursor, remaining);
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0) {
      int error = count < 0 ? errno : EIO;
      close(fd);
      return -error;
    }
    cursor += count;
    remaining -= static_cast<size_t>(count);
  }
  constexpr int seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
  if (fcntl(fd, F_ADD_SEALS, seals)) {
    int error = errno;
    close(fd);
    return -error;
  }
  return fd;
}
} // namespace

// The upstream loader uses exactly these three syscall signatures. Do not
// forward arbitrary varargs or let finit_module fall back to libc's SVC.
extern "C" long viola_lkm_syscall(long number, ...) noexcept {
  va_list args;
  va_start(args, number);
  unsigned long a0 = 0, a1 = 0, a2 = 0;
  if (number == SYS_memfd_create) {
    const char *name = va_arg(args, const char *);
    int flags = va_arg(args, int);
    va_end(args);
    return syscall(number, name, flags);
  }
  if (number == SYS_finit_module) {
    a0 = static_cast<unsigned long>(va_arg(args, int));
    a1 = reinterpret_cast<unsigned long>(va_arg(args, const char *));
    a2 = static_cast<unsigned long>(va_arg(args, int));
  } else if (number == SYS_init_module) {
    a0 = reinterpret_cast<unsigned long>(va_arg(args, std::uint8_t *));
    a1 = va_arg(args, size_t);
    a2 = reinterpret_cast<unsigned long>(va_arg(args, const char *));
  } else {
    va_end(args);
    errno = ENOSYS;
    return -1;
  }
  va_end(args);
  if (!active_admission) {
    errno = EPERM;
    return -1;
  }
  long result = active_admission(number, a0, a1, a2);
  module_error = result < 0 ? errno : 0;
  return result;
}

extern "C" int viola_load_verified_kernel(const void *image, size_t size,
                                           const char *parameters,
                                           viola_module_syscall admission) {
  if (!image || !size || size > 128U * 1024U * 1024U || !parameters || !admission)
    return -EINVAL;
  if (active_admission)
    return -EBUSY;
  if (!admission(SYS_init_module, reinterpret_cast<unsigned long>(image), size,
                  reinterpret_cast<unsigned long>(parameters)))
    return 0;
  int error = errno;
  // Only symbol resolution and image-format failures enter compatibility.
  // Authentication, policy, signature and resource failures stay fatal.
  if (error != ENOENT && error != ENOEXEC)
    return -error;

  int fd = sealed_image(image, size);
  if (fd < 0)
    return fd;
  char path[64];
  int length = std::snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
  if (length <= 0 || static_cast<size_t>(length) >= sizeof(path)) {
    close(fd);
    return -EOVERFLOW;
  }
  std::fprintf(stderr, "viola: kernel load: %s; trying embedded lkmloader\n",
               std::strerror(error));
  active_admission = admission;
  module_error = 0;
  bool loaded = lkmloader::load_module(path, parameters);
  error = module_error ? module_error : EBADMSG;
  active_admission = nullptr;
  close(fd);
  return loaded ? 0 : -error;
}
