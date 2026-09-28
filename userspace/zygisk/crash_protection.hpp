/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Boot-scoped module crash protection and configuration.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */
#pragma once

#include "crash_evidence.hpp"

#include <array>
#include <cstdlib>
#include <set>

namespace yukizygisk::crash {

inline constexpr size_t kMaxSuspendedModules = 1024;
inline constexpr std::array<const char *, 2> kProtectionFiles{
    "protection32.json", "protection64.json"};

inline std::set<std::string> read_suspensions(const std::string &path,
                                              const std::string &boot) {
  std::string text;
  std::set<std::string> result;
  if (boot.empty() || !read_bounded(path, kMaxDocument, &text))
    return result;
  const auto root = json::parse(text);
  if (root.at("boot_id").string_or("") != boot ||
      !root.at("modules").is_array())
    return result;
  for (const auto &value : root.at("modules").as_array()) {
    const auto id = value.string_or("");
    if (valid_id(id) && result.size() < kMaxSuspendedModules)
      result.insert(id);
  }
  return result;
}

inline json::Value suspended_modules(const std::string &directory) {
  const auto boot = boot_id();
  auto result = json::Value::array();
  if (!current_boot(directory, boot))
    return result;
  std::set<std::string> modules;
  for (const auto *name : kProtectionFiles) {
    const auto saved = read_suspensions(directory + "/" + name, boot);
    modules.insert(saved.begin(), saved.end());
  }
  for (const auto &id : modules)
    result.push_back(id);
  return result;
}

class Protection {
public:
  void start(std::string directory, uint8_t abi) {
    directory_ = std::move(directory);
    boot_ = boot_id();
    own_ = abi == 2 ? 1 : 0;
    refresh();
    local_ = cached_[own_];
  }

  void set_enabled(bool enabled) { enabled_ = enabled; }
  [[nodiscard]] bool enabled() const { return enabled_; }

  bool blocked(const std::string &id) {
    if (!enabled_)
      return false;
    refresh();
    return local_.count(id) != 0 || cached_[0].count(id) != 0 ||
           cached_[1].count(id) != 0;
  }

  bool suspend(const std::string &id) {
    if (!enabled_ || !valid_id(id) || local_.count(id) != 0 ||
        local_.size() >= kMaxSuspendedModules)
      return false;
    local_.insert(id);
    dirty_ = true;
    save();
    return true;
  }

  void tick() {
    if (dirty_)
      save();
  }
  [[nodiscard]] bool dirty() const { return dirty_; }

private:
  void refresh() {
    if (!current_boot(directory_, boot_))
      return;
    for (size_t index = 0; index < kProtectionFiles.size(); ++index) {
      const auto path = directory_ + "/" + kProtectionFiles[index];
      const auto identity = image_identity(path);
      if (identity == identities_[index])
        continue;
      cached_[index] = read_suspensions(path, boot_);
      identities_[index] = identity;
    }
  }

  void save() {
    if (!dirty_ || !current_boot(directory_, boot_))
      return;
    auto root = json::Value::object();
    root["boot_id"] = boot_;
    root["modules"] = json::Value::array();
    for (const auto &id : local_)
      root["modules"].push_back(id);
    const auto text = json::dump(root);
    const int dir = open(directory_.c_str(),
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dir < 0)
      return;
    const char *name = kProtectionFiles[own_];
    std::string temporary = directory_ + "/" + name + ".tmp.XXXXXX";
    const int fd = mkstemp(temporary.data());
    if (fd >= 0) {
      (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
      const auto basename = temporary.substr(temporary.find_last_of('/') + 1);
      size_t offset = 0;
      while (offset < text.size()) {
        const ssize_t count =
            write(fd, text.data() + offset, text.size() - offset);
        if (count < 0 && errno == EINTR)
          continue;
        if (count <= 0)
          break;
        offset += static_cast<size_t>(count);
      }
      bool ok = offset == text.size() && fsync(fd) == 0;
      close(fd);
      if (ok)
        ok = renameat(dir, basename.c_str(), dir, name) == 0;
      if (ok) {
        (void)fsync(dir);
        dirty_ = false;
      } else {
        (void)unlinkat(dir, basename.c_str(), 0);
      }
    }
    close(dir);
  }

  std::string directory_;
  std::string boot_;
  std::set<std::string> local_;
  std::array<std::set<std::string>, 2> cached_;
  std::array<std::string, 2> identities_;
  size_t own_ = 0;
  bool enabled_ = false;
  bool dirty_ = false;
};

} // namespace yukizygisk::crash
