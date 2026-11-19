#pragma once

#include "crash_evidence.hpp"
#include "uapi/fixed_policy.h"

#include <cstdio>
#include <cstring>
#include <sys/file.h>

namespace yukizygisk::fixed_policy {

inline constexpr char kBoot[] = "/dev/yukizygisk-policy.boot";
inline constexpr char kRuleScan[] = "/dev/yukizygisk-policy.scan";
inline constexpr char kRebootRequired[] =
    "/dev/yukizygisk-policy.reboot-required";

inline bool reboot_required() {
  struct stat st{};
  return lstat(kRebootRequired, &st) == 0;
}

inline bool domain_name(const std::string &name) {
  if (name.empty() || name.size() >= YZ_FIXED_NAME_MAX || name == "self")
    return false;
  for (size_t i = 0; i < name.size(); ++i) {
    const char c = name[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (i != 0 && c >= '0' && c <= '9') || c == '_'))
      return false;
  }
  return true;
}

inline bool encode(const json::Value &root, yz_fixed_policy_config *config) {
  *config = {};
  config->version = YZ_FIXED_POLICY_VERSION;
  const auto &enabled = root.at("fixed_sepolicy");
  if (!enabled.is_null() && !enabled.is_bool()) {
    errno = EINVAL;
    return false;
  }
  config->enabled = enabled.bool_or(false);
  return true;
}

inline bool write_boot_once(const std::string &path, const json::Value &root) {
  yz_fixed_policy_config config{};
  if (!encode(root, &config))
    return false;
  const auto separator = path.find_last_of('/');
  const std::string parent = separator == std::string::npos ? "."
                             : separator == 0               ? "/"
                                                            : path.substr(0, separator);
  const int directory =
      open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (directory < 0)
    return false;
  struct stat status{};
  if (fstat(directory, &status) != 0 || status.st_uid != 0 ||
      (status.st_mode & 0022)) {
    close(directory);
    errno = EPERM;
    return false;
  }
  std::string temporary = path + ".tmp.XXXXXX";
  const int fd = mkstemp(temporary.data());
  if (fd < 0) {
    close(directory);
    return false;
  }
  const char *bytes = reinterpret_cast<const char *>(&config);
  size_t written = 0;
  while (written < sizeof(config)) {
    const ssize_t count = write(fd, bytes + written, sizeof(config) - written);
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0) {
      if (count == 0)
        errno = EIO;
      break;
    }
    written += static_cast<size_t>(count);
  }
  bool ok = written == sizeof(config) && fsync(fd) == 0;
  int saved = errno;
  if (ok) {
    ok = link(temporary.c_str(), path.c_str()) == 0 && fsync(directory) == 0;
    if (!ok)
      saved = errno;
  }
  close(fd);
  (void)unlink(temporary.c_str());
  close(directory);
  errno = saved;
  return ok;
}

inline std::string missing_detail(const yz_fixed_policy_status &status) {
  if (!status.source[0] && !status.target[0] && !status.class_name[0] &&
      !status.missing_av)
    return {};
  char detail[sizeof(status.source) + sizeof(status.target) +
              sizeof(status.class_name) + 64];
  snprintf(detail, sizeof(detail),
           " source=%.*s target=%.*s class=%.*s missing_av=0x%x",
           static_cast<int>(sizeof(status.source)), status.source,
           static_cast<int>(sizeof(status.target)), status.target,
           static_cast<int>(sizeof(status.class_name)), status.class_name,
           status.missing_av);
  return detail;
}

inline std::string error_message(const yz_fixed_policy_status &status) {
  return "Fixed SELinux policy failed (error " + std::to_string(status.error) +
         ")" + missing_detail(status);
}

inline std::string denial_message(const yz_fixed_policy_status &status) {
  return "Fixed SELinux policy denied access" + missing_detail(status);
}

inline json::Value status_json(const yz_fixed_policy_status &status,
                               bool supported) {
  auto value = json::Value::object();
  value["supported"] = supported;
  value["reboot_required"] = reboot_required();
  value["initialized"] = supported && status.initialized != 0;
  value["requested"] = supported && status.requested != 0;
  value["active"] = supported && status.active != 0;
  value["error"] = supported ? status.error : -EOPNOTSUPP;
  value["missing_source"] =
      std::string(status.source, strnlen(status.source, sizeof(status.source)));
  value["missing_target"] =
      std::string(status.target, strnlen(status.target, sizeof(status.target)));
  value["missing_class"] = std::string(
      status.class_name, strnlen(status.class_name, sizeof(status.class_name)));
  value["missing_av"] = static_cast<double>(status.missing_av);
  return value;
}

} // namespace yukizygisk::fixed_policy
