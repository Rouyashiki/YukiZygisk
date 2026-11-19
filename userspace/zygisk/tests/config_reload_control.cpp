/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Kernel control boundary for configuration reload regressions.
 *
 * License: Apache-2.0
 *
 * Author: Rouyashiki Developers
 */

#include "kernel/uapi/viola.h"
#include "kernel/uapi/viola_health.h"
#include "kernel/uapi/yukizygisk.h"

#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iterator>
#include <string>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace {
int control_fd = -1;
unsigned identity_reads;
unsigned daemon_generation = 1;
}

extern "C" long __real_syscall(long number, ...);
extern "C" int __real_ioctl(int fd, unsigned long request, ...);
extern "C" ssize_t __real_write(int fd, const void *data, size_t size);
extern "C" int __real_renameat(int, const char *, int, const char *);
extern "C" int __real_unlinkat(int, const char *, int);
extern "C" int __real_fstatat(int, const char *, struct stat *, int);

extern "C" int __wrap_fstatat(int dir, const char *name, struct stat *st,
                              int flags) {
  const int result = __real_fstatat(dir, name, st, flags);
  if (result != 0 || std::strcmp(name, "sepolicy.rule") != 0)
    return result;
  // Model a directory lookup made before a backup acquired a second link.
  if (std::getenv("YZ_TEST_STALE_RULE_STAT"))
    st->st_nlink = 1;
  if (const char *module = std::getenv("YZ_TEST_PROMOTE_MODULE")) {
    const std::string active = module;
    assert(unsetenv("YZ_TEST_PROMOTE_MODULE") == 0);
    assert(rename(active.c_str(), (active + ".old").c_str()) == 0);
    assert(rename((active + ".upgrade").c_str(), active.c_str()) == 0);
  }
  return result;
}

extern "C" int __wrap_unlinkat(int dir, const char *name, int flags) {
  if (std::strcmp(name, "yzconfig.json.commit.v2") == 0 &&
      std::getenv("YZ_TEST_STOP_BEFORE_RETIRE"))
    _exit(75);
  return __real_unlinkat(dir, name, flags);
}

// A selinuxfs transaction leaves the file offset at zero for the response.
extern "C" ssize_t __wrap_write(int fd, const void *data, size_t size) {
  const char *mode = std::getenv("YZ_TEST_CONTROL");
  constexpr char header[] = "# YukiZygisk daemon ";
  if (mode && std::strcmp(mode, "identity-installer-write") == 0 &&
      size >= sizeof(header) - 1 && memcmp(data, header, sizeof(header) - 1) == 0)
    ++daemon_generation;
  const char *path = std::getenv("YZ_TEST_SELINUX_CONTEXT");
  struct stat fixture{}, file{};
  if (path && stat(path, &fixture) == 0 && fstat(fd, &file) == 0 &&
      fixture.st_dev == file.st_dev && fixture.st_ino == file.st_ino) {
    const char *reject = std::getenv("YZ_TEST_REJECT_CONTEXT");
    if (reject && size == strlen(reject) + 1 && memcmp(data, reject, size) == 0) {
      errno = EINVAL;
      return -1;
    }
    if (ftruncate(fd, 0) != 0)
      return -1;
    return pwrite(fd, data, size, 0);
  }
  return __real_write(fd, data, size);
}

extern "C" int __wrap_renameat(int old_dir, const char *old_name, int new_dir,
                               const char *new_name) {
  const bool publishing = std::strcmp(old_name, "sepolicy.rule.switch") == 0;
  if (publishing && std::getenv("YZ_TEST_STOP_BEFORE_PUBLISH"))
    _exit(75);
  const int ret = __real_renameat(old_dir, old_name, new_dir, new_name);
  const char *mode = std::getenv("YZ_TEST_CONTROL");
  if (ret == 0 && mode && std::strcmp(mode, "identity-before-publish") == 0 &&
      std::strcmp(old_name, ".sepolicy.rule.install") == 0)
    ++daemon_generation;
  const char *restored = std::getenv("YZ_TEST_RESTORE_AFTER_PUBLISH");
  if (ret == 0 && publishing && restored) {
    std::ofstream config(std::getenv("YZ_TEST_CONFIG"));
    config << restored;
    config.close();
    assert(config.good());
  }
  return ret;
}

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
           std::strcmp(mode, "reload-failed") == 0 ||
           std::strcmp(mode, "policy-ready") == 0 ||
           std::strncmp(mode, "identity-", 9) == 0 ||
           std::strncmp(mode, "status-", 7) == 0);
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

  assert(fd == control_fd);
  if (std::strcmp(mode, "status-failed") == 0) {
    assert(request == YZ_IOCTL_GET_RUNTIME);
    errno = EIO;
    return -1;
  }
  if (request == YZ_IOCTL_GET_RUNTIME)
    return 0;
  if (request == YZ_IOCTL_GET_FIXED_POLICY) {
    if (std::strcmp(mode, "status-legacy") == 0) {
      errno = ENOTTY;
      return -1;
    }
    auto *policy = static_cast<yz_fixed_policy_status *>(argument);
    policy->version = YZ_FIXED_POLICY_VERSION;
    if (std::strcmp(mode, "status-rejected") == 0) {
      policy->error = -EACCES;
      std::memset(policy->source, 's', sizeof(policy->source));
      std::strcpy(policy->target, "test_daemon");
      std::strcpy(policy->class_name, "fd");
      policy->missing_av = 4;
    }
    return 0;
  }
  if (request == YZ_IOCTL_GET_ROOT_STATUS) {
    static_cast<yz_root_status_cmd *>(argument)->owner =
        YZ_ROOT_OWNER_UAPI_KERNELSU;
    return 0;
  }
  if (std::strncmp(mode, "status-", 7) == 0) {
    errno = ENOTTY;
    return -1;
  }
  if (request == YZ_IOCTL_VIOLA_DAEMON_IDENTITY) {
    ++identity_reads;
    unsigned busy_read = 0;
    if (std::strcmp(mode, "identity-busy-first") == 0)
      busy_read = 1;
    else if (std::strcmp(mode, "identity-busy-second") == 0)
      busy_read = 2;
    if (std::strcmp(mode, "identity-busy") == 0 ||
        identity_reads == busy_read) {
      errno = EAGAIN;
      return -1;
    }
    auto *identity = static_cast<yz_viola_daemon_identity_cmd *>(argument);
    const bool replaced =
        (daemon_generation % 2 == 0 && std::strcmp(mode, "identity-before-publish") != 0) ||
        (busy_read && identity_reads > busy_read) ||
        (std::strcmp(mode, "identity-changed") == 0 && identity_reads == 2);
    identity->pid = replaced ? 43 : 42;
    identity->state = YZ_VIOLA_READY;
    identity->owner_alive = 1;
    identity->role = YZ_VIOLA_DAEMON64;
    identity->start_boottime_ns = identity->epoch = 1;
    identity->generation = daemon_generation;
    return 0;
  }
  if (request == YZ_IOCTL_VALIDATE_FIXED_POLICY) {
    if (std::strcmp(mode, "identity-replace-on-validate") == 0 ||
        std::strcmp(mode, "identity-reject-replacement") == 0 ||
        std::strcmp(mode, "identity-churn") == 0) {
      if (daemon_generation == 1 || std::strcmp(mode, "identity-churn") == 0)
        ++daemon_generation;
      else if (std::strcmp(mode, "identity-reject-replacement") == 0) {
        errno = ENETUNREACH;
        return -1;
      }
      return 0;
    }
    assert(std::strcmp(mode, "policy-ready") == 0 ||
           std::strcmp(mode, "identity-before-publish") == 0 ||
           std::strcmp(mode, "identity-installer-write") == 0 ||
           (std::strcmp(mode, "identity-busy-first") == 0 &&
            identity_reads == 3) ||
           (std::strcmp(mode, "identity-busy-second") == 0 &&
            identity_reads == 4));
    return 0;
  }
  assert(request == YZ_IOCTL_RELOAD && !argument);
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
