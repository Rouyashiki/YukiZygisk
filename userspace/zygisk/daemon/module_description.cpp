/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Runtime module description updates.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */

#include "module_description.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <string>
#include <time.h>

namespace yukizygisk::description {
namespace {

constexpr size_t kMaxPropSize = 16 * 1024;

bool trusted_dir(const struct stat &st) {
  return S_ISDIR(st.st_mode) && st.st_uid == 0 &&
         (st.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

bool trusted_data_dir(const struct stat &st) {
  constexpr uid_t kAndroidSystemId = 1000;
  return S_ISDIR(st.st_mode) && st.st_uid == kAndroidSystemId &&
         st.st_gid == kAndroidSystemId && (st.st_mode & S_IWOTH) == 0;
}

bool trusted_file(const struct stat &st) {
  return S_ISREG(st.st_mode) && st.st_uid == 0 && st.st_nlink == 1 &&
         st.st_size >= 0 && static_cast<uint64_t>(st.st_size) <= kMaxPropSize;
}

int open_trusted_dir(const std::string &path) {
  if (path.empty() || path.front() != '/')
    return -1;
  int dir = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (dir < 0)
    return -1;
  size_t begin = 1;
  while (begin < path.size()) {
    const size_t end = path.find('/', begin);
    const std::string part = path.substr(begin, end - begin);
    if (part.empty() || part == "." || part == "..") {
      close(dir);
      return -1;
    }
    int next = openat(dir, part.c_str(),
                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    close(dir);
    if (next < 0)
      return -1;
    struct stat st{};
    if (fstat(next, &st) != 0 ||
        !(trusted_dir(st) ||
          (begin == 1 && part == "data" && trusted_data_dir(st)))) {
      close(next);
      return -1;
    }
    dir = next;
    if (end == std::string::npos)
      break;
    begin = end + 1;
  }
  return dir;
}

bool disabled(int dir) {
  struct stat st{};
  return fstatat(dir, "disable", &st, AT_SYMLINK_NOFOLLOW) == 0 ||
         errno != ENOENT ||
         fstatat(dir, "remove", &st, AT_SYMLINK_NOFOLLOW) == 0 ||
         errno != ENOENT;
}

bool read_prop(int dir, const char *name, std::string *contents,
               struct stat *metadata) {
  int fd = openat(dir, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (fd < 0)
    return false;
  bool ok = fstat(fd, metadata) == 0 && trusted_file(*metadata);
  if (ok) {
    contents->resize(static_cast<size_t>(metadata->st_size));
    size_t offset = 0;
    while (offset < contents->size()) {
      const ssize_t n =
          read(fd, contents->data() + offset, contents->size() - offset);
      if (n < 0 && errno == EINTR)
        continue;
      if (n <= 0) {
        ok = false;
        break;
      }
      offset += static_cast<size_t>(n);
    }
    char extra;
    if (ok && read(fd, &extra, 1) != 0)
      ok = false;
    if (ok && contents->find('\0') != std::string::npos)
      ok = false;
  }
  close(fd);
  return ok;
}

bool description_range(const std::string &contents, size_t *begin,
                       size_t *end) {
  constexpr char kKey[] = "description=";
  size_t line = 0;
  bool found = false;
  while (line < contents.size()) {
    const size_t newline = contents.find('\n', line);
    const size_t limit =
        newline == std::string::npos ? contents.size() : newline;
    if (contents.compare(line, sizeof(kKey) - 1, kKey) == 0) {
      if (found)
        return false;
      found = true;
      *begin = line + sizeof(kKey) - 1;
      *end = limit;
      if (*end > *begin && contents[*end - 1] == '\r')
        --*end;
    }
    if (newline == std::string::npos)
      break;
    line = newline + 1;
  }
  return found;
}

std::string prop_value(const std::string &contents, const char *key) {
  const std::string prefix = std::string(key) + '=';
  std::string value;
  bool found = false;
  size_t line = 0;
  while (line < contents.size()) {
    size_t end = contents.find('\n', line);
    if (end == std::string::npos)
      end = contents.size();
    if (contents.compare(line, prefix.size(), prefix) == 0) {
      if (found)
        return {};
      found = true;
      size_t value_end = end;
      if (value_end > line && contents[value_end - 1] == '\r')
        --value_end;
      value = contents.substr(line + prefix.size(),
                              value_end - line - prefix.size());
    }
    line = end + 1;
  }
  return value;
}

bool write_all(int fd, const std::string &contents) {
  size_t offset = 0;
  while (offset < contents.size()) {
    const ssize_t n =
        write(fd, contents.data() + offset, contents.size() - offset);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      return false;
    offset += static_cast<size_t>(n);
  }
  return true;
}

} // namespace

std::string render(const yz_viola_status &viola,
                   const yz_runtime_query_cmd &runtime,
                   const yz_runtime_record *records, size_t count) {
  unsigned injected64 = 0;
  unsigned injected32 = 0;
  bool failed = false;
  bool safe_mode = runtime.safe_mode != 0;
  for (size_t i = 0; records != nullptr && i < count; ++i) {
    const auto &record = records[i];
    if (record.state == YZ_RUNTIME_STATE_EXITED)
      continue;
    if (record.state == YZ_RUNTIME_STATE_SAFEMODE)
      safe_mode = true;
    if (record.state == YZ_RUNTIME_STATE_FAILED)
      failed = true;
    if (record.kind != YZ_RUNTIME_KIND_ZYGOTE || record.module_id[0] != '\0')
      continue;
    if (record.state == YZ_RUNTIME_STATE_INJECTED) {
      bool duplicate = false;
      for (size_t j = 0; j < i; ++j) {
        const auto &prior = records[j];
        if (prior.kind == YZ_RUNTIME_KIND_ZYGOTE &&
            prior.module_id[0] == '\0' &&
            prior.state == YZ_RUNTIME_STATE_INJECTED &&
            prior.pid == record.pid && prior.generation == record.generation &&
            prior.abi == record.abi) {
          duplicate = true;
          break;
        }
      }
      if (duplicate)
        continue;
      if (record.abi == YZ_RUNTIME_ABI_64)
        ++injected64;
      else if (record.abi == YZ_RUNTIME_ABI_32)
        ++injected32;
    }
  }
  const bool daemon_lost =
      viola.daemon64 == YZ_VIOLA_LOST ||
      (viola.compat_required && viola.daemon32 == YZ_VIOLA_LOST);
  const bool daemon_ready =
      viola.catalog_ready && viola.daemon64 == YZ_VIOLA_READY &&
      (!viola.compat_required || viola.daemon32 == YZ_VIOLA_READY);
  std::string state;
  if (safe_mode)
    state = "safe mode⚠️ | ";
  else if (failed || (!daemon_ready && (viola.last_error ||
                                        viola.recovery_error || daemon_lost)))
    state = "error❌ | ";
  state += daemon_lost ? "daemon❌" : daemon_ready ? "daemon✅" : "daemon⏳";
  state += " kernel✅ | zygote64: " + std::to_string(injected64);
  state += ", zygote32: " + std::to_string(injected32);
  return state;
}

bool update(const std::string &module_dir, const std::string &state) {
  if (geteuid() != 0 || state.empty() ||
      state.find_first_of("\r\n") != std::string::npos ||
      state.find('\0') != std::string::npos)
    return false;
  int dir = open_trusted_dir(module_dir);
  if (dir < 0)
    return false;
  if (disabled(dir)) {
    close(dir);
    return false;
  }

  std::string original;
  std::string current;
  struct stat original_st{}, current_st{};
  bool ok = read_prop(dir, "module.prop.orig", &original, &original_st) &&
            read_prop(dir, "module.prop", &current, &current_st);
  size_t original_begin = 0, original_end = 0, current_begin = 0,
         current_end = 0;
  ok = ok && description_range(original, &original_begin, &original_end) &&
       description_range(current, &current_begin, &current_end);
  ok = ok && prop_value(original, "id") == "yukizygisk" &&
       prop_value(current, "id") == "yukizygisk";
  for (const char *key : {"version", "versionCode"}) {
    const std::string value = prop_value(original, key);
    ok = ok && !value.empty() && prop_value(current, key) == value;
  }
  if (!ok) {
    close(dir);
    return false;
  }
  std::string desired = current;
  desired.replace(current_begin, current_end - current_begin, "YZ: " + state);
  if (desired == current) {
    close(dir);
    return true;
  }
  if (desired.size() > kMaxPropSize) {
    close(dir);
    return false;
  }

  static uint64_t sequence = 0;
  struct timespec clock{};
  if (clock_gettime(CLOCK_MONOTONIC, &clock) != 0) {
    close(dir);
    return false;
  }
  const std::string temp = "module.prop.yz-" + std::to_string(getpid()) + "-" +
                           std::to_string(clock.tv_sec) + "-" +
                           std::to_string(clock.tv_nsec) + "-" +
                           std::to_string(++sequence);
  int fd = openat(dir, temp.c_str(),
                  O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                  current_st.st_mode & 07777);
  if (fd < 0) {
    close(dir);
    return false;
  }
  ok = fchown(fd, current_st.st_uid, current_st.st_gid) == 0 &&
       fchmod(fd, current_st.st_mode & 07777) == 0;
  char context[256];
  const int previous = openat(dir, "module.prop",
                              O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (previous >= 0) {
    const ssize_t size =
        fgetxattr(previous, "security.selinux", context, sizeof(context));
    if (size > 0) {
      char inherited[sizeof(context)];
      const ssize_t inherited_size =
          fgetxattr(fd, "security.selinux", inherited, sizeof(inherited));
      if ((inherited_size != size || memcmp(inherited, context, size) != 0) &&
          fsetxattr(fd, "security.selinux", context, static_cast<size_t>(size),
                    0) != 0)
        ok = false;
    } else if (size < 0 && errno != ENODATA && errno != ENOTSUP) {
      ok = false;
    }
    close(previous);
  } else {
    ok = false;
  }
  ok = ok && write_all(fd, desired) && fsync(fd) == 0;
  close(fd);

  std::string latest;
  std::string latest_original;
  struct stat latest_st{}, latest_original_st{};
  ok = ok && !disabled(dir) &&
       read_prop(dir, "module.prop.orig", &latest_original,
                 &latest_original_st) &&
       latest_original_st.st_dev == original_st.st_dev &&
       latest_original_st.st_ino == original_st.st_ino &&
       latest_original == original &&
       read_prop(dir, "module.prop", &latest, &latest_st) &&
       latest_st.st_dev == current_st.st_dev &&
       latest_st.st_ino == current_st.st_ino && latest == current &&
       renameat(dir, temp.c_str(), dir, "module.prop") == 0;
  if (ok)
    (void)fsync(dir);
  else
    (void)unlinkat(dir, temp.c_str(), 0);
  close(dir);
  return ok;
}

} // namespace yukizygisk::description
