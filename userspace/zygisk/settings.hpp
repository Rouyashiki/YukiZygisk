/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Boot-scoped module crash protection and configuration.
 *
 * License: Apache-2.0
 *
 * Author: Rouyashiki Developers
 */
#pragma once
#ifndef YUKIZYGISK_SETTINGS_HPP
#define YUKIZYGISK_SETTINGS_HPP

#include "policy_rules.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <initializer_list>
#include <iterator>
#include <string_view>
#include <sys/file.h>

namespace yukizygisk::settings {

inline constexpr char kConfig[] = "/data/adb/yukizygisk/yzconfig.json";
inline constexpr char kRules[] = "/data/adb/modules/yukizygisk/sepolicy.rule";
inline constexpr char kStagedModule[] = "/data/adb/modules_update/yukizygisk";
inline constexpr char kPendingRules[] =
    "# YukiZygisk fixed policy pending revalidation\n";
inline constexpr size_t kMaxRules = 128 * 1024;

inline bool retired_option(const std::string &key) {
  return key == "fixed_zn_domains";
}

inline json::Value defaults() {
  auto root = json::Value::object();
  root["yukilinker"] = true;
  root["anonymous_memory"] = true;
  root["fixed_sepolicy"] = false;
  root["early_load"] = false;
  root["denylist_mode"] = 0;
  root["dmesg_log"] = false;
  root["crash_protection"] = true;
  return root;
}

namespace detail {

class ScopedFd final {
public:
  explicit ScopedFd(int fd) : fd_(fd) {}
  ~ScopedFd() {
    const int saved_errno = errno;
    if (fd_ >= 0)
      close(fd_);
    errno = saved_errno;
  }
  ScopedFd(const ScopedFd &) = delete;
  ScopedFd &operator=(const ScopedFd &) = delete;
  int get() const { return fd_; }
  int release() {
    const int fd = fd_;
    fd_ = -1;
    return fd;
  }

private:
  int fd_;
};

inline std::string directory_of(const std::string &path) {
  const auto separator = path.find_last_of('/');
  return separator == std::string::npos ? "."
         : separator == 0               ? "/"
                                        : path.substr(0, separator);
}

inline int lock_config(const std::string &path) {
  const auto directory = directory_of(path);
  if (mkdir(directory.c_str(), 0700) != 0 && errno != EEXIST)
    return -1;
  ScopedFd lock(open((path + ".lock").c_str(),
                     O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
                     0600));
  if (lock.get() < 0)
    return -1;
  struct stat status{};
  if (fstat(lock.get(), &status) != 0)
    return -1;
  if (!S_ISREG(status.st_mode) || status.st_uid != 0 || status.st_nlink != 1) {
    errno = EPERM;
    return -1;
  }
  int result;
  do {
    result = flock(lock.get(), LOCK_EX);
  } while (result != 0 && errno == EINTR);
  return result == 0 ? lock.release() : -1;
}

enum class ReadResult { Ready, Missing, Rewrite, Invalid, Oversized, Error };

inline ReadResult read_once(const std::string &path, json::Value *root,
                            std::string *source = nullptr) {
  *root = defaults();
  std::string text;
  std::string &bytes = source ? *source : text;
  bytes.clear();
  if (!crash::read_bounded(path, crash::kMaxDocument, &bytes,
                           crash::FileSource::RootPrivate)) {
    if (path == kConfig && errno == EFBIG)
      return ReadResult::Oversized;
    return errno == ENOENT ? ReadResult::Missing : ReadResult::Error;
  }
  const auto saved = json::parse(bytes);
  if (!saved.is_object())
    return ReadResult::Invalid;
  bool rewrite = false;
  for (const auto &[key, value] : saved.as_object()) {
    if (retired_option(key))
      rewrite = true;
    else
      (*root)[key] = value;
  }
  if (!root->at("fixed_sepolicy").is_bool()) {
    (*root)["fixed_sepolicy"] = false;
    return ReadResult::Invalid;
  }
  return rewrite ? ReadResult::Rewrite : ReadResult::Ready;
}

inline bool write_and_sync(int fd, const std::string &text) {
  size_t offset = 0;
  while (offset < text.size()) {
    const ssize_t count = write(fd, text.data() + offset, text.size() - offset);
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0) {
      if (count == 0)
        errno = EIO;
      return false;
    }
    offset += static_cast<size_t>(count);
  }
  return fsync(fd) == 0;
}

// The same lock protects repairs and ordinary updates. Flush the replacement
// before rename so another crash cannot expose a partially written document.
inline bool write_text_atomic(const std::string &path,
                              const std::string &text) {
  ScopedFd directory(
      open(directory_of(path).c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  if (directory.get() < 0)
    return false;
  std::string temporary = path + ".tmp.XXXXXX";
  ScopedFd file(mkstemp(temporary.data()));
  if (file.get() < 0)
    return false;
  if (!write_and_sync(file.get(), text) ||
      rename(temporary.c_str(), path.c_str()) != 0) {
    const int saved_errno = errno;
    (void)unlink(temporary.c_str());
    errno = saved_errno;
    return false;
  }
  return fsync(directory.get()) == 0;
}

inline bool serialize_config(const std::string &source, const json::Value &root,
                             std::string *text, bool allow_sparse,
                             const json::Value *changes = nullptr) {
  *text = json::dump_object_members(root, source, changes);
  if (text->size() <= crash::kMaxDocument)
    return true;
  if (allow_sparse) {
    const auto standard = defaults();
    *text = json::dump_object_members(root, source, changes, &standard);
    if (text->size() <= crash::kMaxDocument)
      return true;
  }
  errno = EFBIG;
  return false;
}

inline bool write_repaired_config(const std::string &path,
                                  const json::Value &root,
                                  const std::string &original) {
  std::string text;
  return serialize_config(original, root, &text, true) &&
         write_text_atomic(path, text);
}

inline int open_private_directory(const std::string &path) {
  ScopedFd dir(open(path.c_str(),
                    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY));
  struct stat st{};
  if (dir.get() < 0 || fstat(dir.get(), &st) != 0)
    return -1;
  if (st.st_uid != 0 || (st.st_mode & 0022)) {
    errno = EPERM;
    return -1;
  }
  return dir.release();
}

inline bool unlink_optional(int dir, const char *name) {
  return unlinkat(dir, name, 0) == 0 || errno == ENOENT;
}

// The host scans this regular file before module scripts. Each installed
// generation owns its inode, independent of configuration backup and restore.
inline bool write_module_rules(const std::string &directory,
                               const std::string &rules, bool optional,
                               const std::function<bool()> &before_publish = {}) {
  ScopedFd dir(open_private_directory(directory));
  if (dir.get() < 0)
    return optional && errno == ENOENT;
  const int fd = dir.get();
  constexpr char temporary[] = ".sepolicy.rule.install";
  if (!unlink_optional(fd, temporary))
    return false;
  if (rules.empty())
    return unlink_optional(fd, "sepolicy.rule") && fsync(fd) == 0;
  ScopedFd file(openat(fd, temporary, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC,
                       0600));
  if (file.get() < 0)
    return false;
  if (!write_and_sync(file.get(), rules) ||
      (before_publish && !before_publish()) ||
      renameat(fd, temporary, fd, "sepolicy.rule") != 0) {
    const int error = errno;
    (void)unlinkat(fd, temporary, 0);
    errno = error;
    return false;
  }
  return fsync(fd) == 0;
}

inline bool read_rule_snapshot(const std::string &path, std::string *rules) {
  struct stat st{};
  if (lstat(path.c_str(), &st) != 0)
    return false;
  if (!S_ISREG(st.st_mode) ||
      !crash::read_bounded(path, kMaxRules, rules,
                           crash::FileSource::RootPrivate))
    *rules = policy_rules::kUnknownRules;
  return true;
}

inline bool mark_removed_rules(std::string_view loaded, std::string_view next) {
  if (policy_rules::keeps_all_rules(loaded, next))
    return true;
  ScopedFd marker(open(fixed_policy::kRebootRequired,
                       O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                       0600));
  return marker.get() >= 0 || errno == EEXIST;
}

// Each boot-script pass follows a host scan. Record a withdrawal before
// replacing its evidence, since a later scan cannot revoke earlier grants.
inline bool record_rule_scan() {
  std::string live, loaded;
  if (!read_rule_snapshot(kRules, &live) && errno != ENOENT)
    return false;
  if (read_rule_snapshot(fixed_policy::kRuleScan, &loaded)) {
    if (!mark_removed_rules(loaded, live))
      return false;
    if (loaded == live)
      return true;
  } else if (errno != ENOENT) {
    return false;
  }
  return write_text_atomic(fixed_policy::kRuleScan, live);
}

inline bool mark_removed_from_file(const std::string &path,
                                   std::string_view next) {
  std::string rules;
  if (!read_rule_snapshot(path, &rules))
    return errno == ENOENT;
  return mark_removed_rules(rules, next);
}

inline bool record_rule_withdrawal(std::string_view next = {},
                                   const std::string &previous = kRules) {
  // The host can read the published file before our scan callback gets to run.
  // Either the last scan or the outgoing file can contain a live grant.
  return mark_removed_from_file(fixed_policy::kRuleScan, next) &&
         mark_removed_from_file(previous, next);
}

inline bool withdraw_fixed_policy(const std::string &replacement = {}) {
  if (!record_rule_withdrawal(replacement))
    return false;
  const bool staged = write_module_rules(kStagedModule, replacement, true);
  const int staged_error = errno;
  const bool installed =
      write_module_rules(directory_of(kRules), replacement, true);
  if (!staged)
    errno = staged_error;
  return staged && installed;
}

inline constexpr char kPolicyIntent[] = "yzconfig.json.commit.v2";
inline constexpr char kUnscannedIntent[] = "yzconfig.json.commit";
inline constexpr char kLegacyIntent[] = "yzconfig.json.publish";
inline constexpr const char *kPolicyJournals[] = {
    kPolicyIntent, kUnscannedIntent, kLegacyIntent};
inline constexpr char kPreviousConfig[] = "yzconfig.json.previous";
inline constexpr char kPreviousRules[] = "sepolicy.rule.previous";
inline constexpr char kNextConfig[] = "yzconfig.json.next";
inline constexpr char kNextRules[] = "sepolicy.rule.next";
inline constexpr char kRuleSwitch[] = "sepolicy.rule.switch";

enum FileStat {
  kStatError = -1,
  kUntrustedFile = -2,
  kMissingFile = 0,
  kPrivateFile = 1
};

inline FileStat stat_private(int dir, const char *name, struct stat *st) {
  if (fstatat(dir, name, st, AT_SYMLINK_NOFOLLOW) != 0)
    return errno == ENOENT ? kMissingFile : kStatError;
  if (!S_ISREG(st->st_mode) || st->st_uid != 0 || (st->st_mode & 0022)) {
    errno = EPERM;
    return kUntrustedFile;
  }
  return kPrivateFile;
}

inline bool same_file(const struct stat &a, const struct stat &b) {
  return a.st_ino && a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}

inline FileStat stat_module_rule(int dir, const char *name, struct stat *st,
                                 bool allow_pins = true) {
  const auto status = stat_private(dir, name, st);
  if (status != kPrivateFile || st->st_nlink == 1)
    return status;
  if (allow_pins) {
    // Every link to this inode must be one of the installed transaction's names.
    nlink_t links = 0;
    for (const char *entry : {"sepolicy.rule", kPreviousRules, kNextRules, kRuleSwitch}) {
      struct stat pin{};
      if (fstatat(dir, entry, &pin, AT_SYMLINK_NOFOLLOW) == 0)
        links += same_file(*st, pin);
      else if (errno != ENOENT)
        return kStatError;
    }
    if (links == st->st_nlink)
      return kPrivateFile;
  }
  errno = EPERM;
  return kUntrustedFile;
}

inline bool preserve_oversized_config(int dir) {
  struct stat config{};
  if (stat_private(dir, "yzconfig.json", &config) != kPrivateFile ||
      config.st_size <= static_cast<off_t>(crash::kMaxDocument))
    return false;
  // Pin the original bytes before replacing the active file. A retry reuses
  // its pin and a later migration must leave earlier backups intact.
  const std::string base = "yzconfig.json.oversized";
  std::string name;
  for (size_t suffix = 0;; ++suffix) {
    name = suffix ? base + "." + std::to_string(suffix) : base;
    if (linkat(dir, "yzconfig.json", dir, name.c_str(), 0) == 0)
      break;
    struct stat existing{};
    if (errno != EEXIST ||
        fstatat(dir, name.c_str(), &existing, AT_SYMLINK_NOFOLLOW) != 0)
      return false;
    if (same_file(config, existing))
      break;
  }
  if (fsync(dir) != 0)
    return false;
  fprintf(stderr, "YukiZygisk: oversized configuration preserved in %s/%s\n",
          directory_of(kConfig).c_str(), name.c_str());
  return true;
}

inline bool repair_policy_config(int dir, ReadResult before, json::Value *root,
                                 const std::string &original,
                                 const char *previous_rules = nullptr) {
  if ((before == ReadResult::Oversized && !preserve_oversized_config(dir)) ||
      (previous_rules &&
       !mark_removed_from_file(directory_of(kRules) + "/" + previous_rules, {})) ||
      !withdraw_fixed_policy())
    return false;
  if (before == ReadResult::Ready && !root->at("fixed_sepolicy").as_bool())
    return true;
  (*root)["fixed_sepolicy"] = false;
  return write_repaired_config(kConfig, *root, original);
}

inline bool remove_policy_candidates(int dir, int module) {
  const auto remove = [](int fd, std::initializer_list<const char *> names) {
    bool changed = false;
    for (const char *name : names) {
      if (unlinkat(fd, name, 0) == 0)
        changed = true;
      else if (errno != ENOENT)
        return false;
    }
    return !changed || fsync(fd) == 0;
  };
  return (module < 0 ||
          remove(module, {kRuleSwitch, kNextRules, kPreviousRules})) &&
         remove(dir, {kNextConfig, kPreviousConfig});
}

// Older writers could publish rules before discovering their candidate JSON
// exceeded the read limit. Roll back only a proven old or newly published inode.
inline int restore_previous_rules(int dir, const struct stat &live,
                                  const struct stat &candidate, std::string *rules) {
  struct stat previous{};
  const auto pinned = stat_module_rule(dir, kPreviousRules, &previous);
  if (pinned == kStatError)
    return -1;
  if (pinned != kPrivateFile || !previous.st_size ||
      previous.st_size > static_cast<off_t>(kMaxRules) ||
      live.st_size > static_cast<off_t>(kMaxRules) ||
      (!same_file(live, previous) && !same_file(live, candidate)))
    return 0;
  if (!crash::read_bounded_at(dir, kPreviousRules, kMaxRules, rules,
                              crash::FileSource::RootPrivate, &previous))
    return -1;
  if (same_file(live, previous))
    return 1;
  std::string published;
  if (!crash::read_bounded_at(dir, "sepolicy.rule", kMaxRules, &published,
                              crash::FileSource::RootPrivate, &live))
    return -1;
  // A partial backup may have replaced the previous pin. Never reinstate a
  // grant absent from the live candidate while recovering an invalid update.
  if (!policy_rules::keeps_all_rules(*rules, published))
    return 0;
  if (!record_rule_withdrawal(*rules) || !unlink_optional(dir, kRuleSwitch) ||
      linkat(dir, kPreviousRules, dir, kRuleSwitch, 0) != 0 ||
      renameat(dir, kRuleSwitch, dir, "sepolicy.rule") != 0)
    return -1;
  return 1;
}

struct PolicyUpdate {
  const std::string &config;
  const std::string &rules;
};

// The host reads sepolicy.rule before our first boot script. Its atomic rename
// selects the generation. Recovery follows the inode the host could observe.
inline bool finish_policy_update(int dir, const PolicyUpdate *requested = nullptr) {
  struct stat intent{}, next{}, candidate{}, config{}, previous{}, rules{};
  const char *journal = nullptr;
  FileStat journal_state = kMissingFile;
  for (const char *name : kPolicyJournals) {
    // Older formats share the same pins. Retire their journals before
    // releasing the newest intent or its recovery evidence.
    if (journal) {
      if (!unlink_optional(dir, name))
        return false;
      continue;
    }
    journal_state = stat_private(dir, name, &intent);
    if (journal_state == kStatError)
      return false;
    if (journal_state != kMissingFile)
      journal = name;
  }
  if (!journal && requested) {
    errno = ESTALE;
    return false;
  }
  ScopedFd module(open_private_directory(directory_of(kRules)));
  if (module.get() < 0 && errno != ENOENT)
    return false;
  const int rule_dir = module.get();
  // A withdrawal can remove the live rule before the journal and pins retire.
  if (!journal)
    return remove_policy_candidates(dir, rule_dir);
  const bool legacy = journal == kLegacyIntent;
  const char *previous_evidence =
      journal == kPolicyIntent ? nullptr : kPreviousRules;
  const int have_next = stat_private(dir, kNextConfig, &next);
  const int staged =
      rule_dir < 0 ? kMissingFile : stat_module_rule(rule_dir, kNextRules, &candidate);
  const int live =
      rule_dir < 0 ? kMissingFile : stat_module_rule(rule_dir, "sepolicy.rule", &rules);
  const int source = stat_private(dir, "yzconfig.json", &config);
  // The old writer could publish over a group-writable source. Withdraw its
  // rules during repair without accepting that transaction's fixed profile.
  const bool mutable_source =
      journal_state == kPrivateFile && journal == kUnscannedIntent &&
      source == kUntrustedFile && S_ISREG(config.st_mode) &&
      config.st_uid == 0 && (config.st_mode & 0022);
  if (have_next == kStatError || staged == kStatError || live == kStatError ||
      (source < 0 && !mutable_source))
    return false;
  const int pinned = !mutable_source && !legacy && have_next == kPrivateFile
                         ? stat_private(dir, kPreviousConfig, &previous)
                         : 0;
  if (pinned == kStatError)
    return false;
  const bool trusted_intent = journal_state == kPrivateFile &&
                              have_next != kUntrustedFile &&
                              pinned != kUntrustedFile;

  json::Value saved = defaults(), selected;
  std::string source_bytes;
  // An old intent can authorize withdrawal, never the mutable source bytes.
  const auto before = mutable_source
                          ? ReadResult::Invalid
                          : read_once(kConfig, &saved, &source_bytes);
  const bool oversized =
      intent.st_size > static_cast<off_t>(crash::kMaxDocument);
  const auto journal_path = directory_of(kConfig) + "/" + journal;
  std::string selected_bytes;
  const auto after = !trusted_intent || oversized
                         ? ReadResult::Invalid
                         : read_once(journal_path, &selected,
                                     requested ? &selected_bytes : nullptr);
  if (before == ReadResult::Error || after == ReadResult::Error)
    return false;
  const bool fixed = selected.at("fixed_sepolicy").bool_or(false);
  // Promotion replaces the module directory and its pins. The committed JSON
  // can still be checked against the promoted directory's independent rule.
  const bool promoted = journal == kPolicyIntent && !staged &&
                        live == kPrivateFile && rules.st_nlink == 1 &&
                        same_file(intent, config);
  const auto &candidate_rule = promoted ? rules : candidate;
  const bool have_rule = staged == kPrivateFile || promoted;
  const auto readable = [](ReadResult r) {
    return r == ReadResult::Ready || r == ReadResult::Rewrite;
  };
  const bool valid_candidate =
      readable(after) &&
      candidate_rule.st_size <= static_cast<off_t>(kMaxRules) &&
      (!have_rule || fixed == (candidate_rule.st_size != 0));
  // A hard link from an older writer follows in-place restores of the source.
  const bool independent =
      trusted_intent && pinned == kPrivateFile && !same_file(config, previous);
  bool previous_matches = !have_next || same_file(config, previous);
  if (independent && readable(before) &&
      previous.st_size == static_cast<off_t>(source_bytes.size())) {
    std::string baseline;
    if (!crash::read_bounded(directory_of(kConfig) + "/" + kPreviousConfig,
                             crash::kMaxDocument, &baseline,
                             crash::FileSource::RootPrivate))
      return false;
    previous_matches = baseline == source_bytes;
  }
  const bool rollback_only = oversized && !legacy && have_next;
  // Older writers could withdraw the previous rules before replacing the JSON.
  const bool switch_legacy =
      legacy && staged &&
      (!have_next || (!live && saved.at("fixed_sepolicy").as_bool()));
  const bool published =
      !rollback_only &&
      (promoted || same_file(candidate, rules) || switch_legacy);
  // Untrusted rule entries may be unlinked from this private directory, but
  // their inode or contents cannot authorize rollback or publication.
  bool consistent = trusted_intent && live != kUntrustedFile &&
                    staged != kUntrustedFile && !mutable_source &&
                    readable(before) &&
                    same_file(intent, have_next ? next : config) &&
                    (legacy || (have_rule && previous_matches)) &&
                    (valid_candidate || rollback_only);
  std::string recovered_rules;
  if (consistent &&
      (published || (fixed && staged && same_file(intent, config)))) {
    // The journal aliases the candidate JSON on both sides of its rename.
    const bool read_live = published && !switch_legacy;
    if (!crash::read_bounded_at(
            rule_dir, read_live ? "sepolicy.rule" : kNextRules, kMaxRules,
            &recovered_rules, crash::FileSource::RootPrivate,
            read_live ? &rules : &candidate))
      return false;
    consistent =
        fixed ? recovered_rules == kPendingRules ||
                    policy_rules::matches_config(recovered_rules, selected)
              : recovered_rules.empty();
  }
  bool request_matches = false;
  if (consistent) {
    if (switch_legacy &&
        (!record_rule_withdrawal(recovered_rules) ||
         renameat(rule_dir, kNextRules, rule_dir, "sepolicy.rule") != 0))
      return false;
    if (published) {
      if (!mark_removed_from_file(fixed_policy::kRuleScan, recovered_rules) ||
          (previous_evidence &&
           !mark_removed_from_file(directory_of(kRules) + "/" +
                                       previous_evidence,
                                   recovered_rules)))
        return false;
      request_matches = requested && selected_bytes == requested->config &&
                        recovered_rules == requested->rules;
    }
    if (published && have_next) {
      if (independent) {
        if (fsync(rule_dir) != 0 ||
            renameat(dir, kNextConfig, dir, "yzconfig.json") != 0)
          return false;
      } else {
        // A legacy journal cannot distinguish an edit from the original JSON.
        // Keep the live document when its policy agrees, otherwise withdraw.
        consistent = fixed == saved.at("fixed_sepolicy").as_bool();
      }
    }
    if (published && !fixed &&
        (fsync(dir) != 0 || !withdraw_fixed_policy()))
      return false;
    if (!published) {
      recovered_rules.clear();
      const bool was_fixed = saved.at("fixed_sepolicy").as_bool();
      if (was_fixed && have_next && !legacy) {
        const int restored = restore_previous_rules(rule_dir, rules, candidate,
                                                    &recovered_rules);
        if (restored < 0)
          return false;
        consistent = restored == 1;
      } else {
        consistent = !was_fixed && (!live || rules.st_size == 0);
      }
    }
  }
  // Keep the journal until the withdrawal and the repaired mode are durable.
  if (!consistent && !repair_policy_config(dir, before, &saved, source_bytes,
                                           previous_evidence))
    return false;
  // An upgrade may promote its copy on the next boot. Keep the intent and
  // pins until both the installed and staged generations are durable.
  if ((rule_dir >= 0 && fsync(rule_dir) != 0) || fsync(dir) != 0 ||
      (consistent &&
       !write_module_rules(kStagedModule, recovered_rules, true)) ||
      !unlink_optional(dir, journal) || fsync(dir) != 0 ||
      !remove_policy_candidates(dir, rule_dir))
    return false;
  if (requested && !(consistent && request_matches)) {
    errno = ESTALE;
    return false;
  }
  return true;
}

inline bool persist_policy_update(const std::string *updated_config,
                                  const std::string &rules,
                                  const std::string &original,
                                  const std::function<bool()> &before_publish) {
  ScopedFd dir(open_private_directory(directory_of(kConfig)));
  ScopedFd module(open_private_directory(directory_of(kRules)));
  if (dir.get() < 0 || module.get() < 0)
    return false;
  const int fd = dir.get();
  const int rule_dir = module.get();
  const std::string parent = directory_of(kConfig) + "/";
  // Installation publishes only the rule file. Journal the existing config
  // inode so successful publication also preserves its exact contents.
  const auto stage_config = [&] {
    if (updated_config)
      return write_text_atomic(parent + kNextConfig, *updated_config);
    return unlink_optional(fd, kNextConfig) &&
           linkat(fd, "yzconfig.json", fd, kNextConfig, 0) == 0;
  };
  // The host can scan the outgoing rules before our boot callback. Only /dev
  // carries that evidence across readers in the same boot.
  if (!unlink_optional(rule_dir, kRuleSwitch) ||
      !unlink_optional(rule_dir, kPreviousRules) || !stage_config() ||
      !write_text_atomic(directory_of(kRules) + "/" + kNextRules, rules) ||
      !write_text_atomic(parent + kPreviousConfig, original) ||
      (linkat(rule_dir, "sepolicy.rule", rule_dir, kPreviousRules, 0) != 0 &&
       errno != ENOENT) ||
      linkat(rule_dir, kNextRules, rule_dir, kRuleSwitch, 0) != 0 ||
      fsync(rule_dir) != 0 || !record_rule_scan() ||
      linkat(fd, kNextConfig, fd, kPolicyIntent, 0) != 0) {
    const int error = errno;
    if (error != EEXIST)
      (void)remove_policy_candidates(fd, rule_dir);
    errno = error;
    return false;
  }
  // An upgrade can promote the staged module at the next boot. Leave it
  // inert until the matching configuration and installed rules are durable.
  if (fsync(fd) != 0 || !write_module_rules(kStagedModule, kPendingRules, true))
    return false;
  if (!before_publish()) {
    // The installed rule still selects the previous generation.
    const int error = errno;
    if (finish_policy_update(fd))
      errno = error;
    return false;
  }
  if (renameat(rule_dir, kRuleSwitch, rule_dir, "sepolicy.rule") != 0 ||
      fsync(rule_dir) != 0)
    return false;
  const PolicyUpdate requested{updated_config ? *updated_config : original, rules};
  return finish_policy_update(fd, &requested);
}

// Callers hold the config writer lock through withdrawal and repair.
inline bool read_locked(const std::string &path, json::Value *root,
                        std::string *source = nullptr) {
  const bool policy_config = path == kConfig;
  ScopedFd dir(policy_config ? open_private_directory(directory_of(kConfig)) : -1);
  if (policy_config && (dir.get() < 0 || !finish_policy_update(dir.get())))
    return false;
  std::string local;
  auto &original = source ? *source : local;
  const auto result = read_once(path, root, &original);
  if (result == ReadResult::Ready || result == ReadResult::Error)
    return result == ReadResult::Ready;
  if (result == ReadResult::Rewrite)
    return write_repaired_config(path, *root, original) &&
           (!source || read_once(path, root, source) == ReadResult::Ready);
  if (policy_config)
    return repair_policy_config(dir.get(), result, root, original) &&
           (!source || read_once(path, root, source) == ReadResult::Ready);
  return result == ReadResult::Missing ||
         write_repaired_config(path, *root, original);
}

} // namespace detail

inline bool read(const std::string &path, json::Value *root,
                 std::string *source = nullptr) {
  if (path == kConfig) {
    const auto parent = detail::directory_of(path) + "/";
    const auto pending = [&](const char *name) {
      struct stat st{};
      return lstat((parent + name).c_str(), &st) == 0 || errno != ENOENT;
    };
    if (std::any_of(std::begin(detail::kPolicyJournals),
                    std::end(detail::kPolicyJournals), pending) ||
        pending(detail::kPreviousConfig) || pending(detail::kNextConfig)) {
      detail::ScopedFd lock(detail::lock_config(path));
      return lock.get() >= 0 && detail::read_locked(path, root, source);
    }
  }
  const auto result = detail::read_once(path, root, source);
  if (result == detail::ReadResult::Ready)
    return true;
  if (result == detail::ReadResult::Error && errno != EAGAIN)
    return false;
  if (result == detail::ReadResult::Missing && path != kConfig)
    return true;
  detail::ScopedFd lock(detail::lock_config(path));
  return lock.get() >= 0 && detail::read_locked(path, root, source);
}

inline bool protection_enabled(const std::string &path) {
  json::Value root;
  return read(path, &root) && root.at("crash_protection").bool_or(false);
}

inline bool
update(const std::string &path, const std::vector<std::string> &pairs,
       const std::function<bool(const std::string &, const std::string &)>
           &save = {},
       bool (*apply_runtime)(bool pending) = nullptr,
       const std::function<bool(const json::Value &)> &before_save = {}) {
  if (pairs.empty() || pairs.size() % 2 != 0) {
    errno = EINVAL;
    return false;
  }
  auto changes = json::Value::object();
  const auto schema = defaults();
  for (size_t index = 0; index < pairs.size(); index += 2) {
    const auto &key = pairs[index];
    const auto &value = pairs[index + 1];
    if (schema.at(key).is_bool() && (value == "true" || value == "false")) {
      changes[key] = value == "true";
    } else if (key == "denylist_mode" &&
               (value == "0" || value == "1" || value == "2")) {
      changes[key] = value[0] - '0';
    } else {
      errno = EINVAL;
      return false;
    }
  }
  detail::ScopedFd lock(detail::lock_config(path));
  if (lock.get() < 0)
    return false;
  json::Value root;
  std::string original;
  if (!detail::read_locked(path, &root, &original))
    return false;
  // A nonempty lock file records a reload until a writer has notified the
  // daemon.
  const off_t marker = lseek(lock.get(), 0, SEEK_END);
  if (marker < 0)
    return false;
  // An explicit runtime-only set also synchronizes the running daemon.
  bool pending = marker != 0 || changes.at("fixed_sepolicy").is_null();
  for (const auto &[key, value] : changes.as_object()) {
    if (key != "fixed_sepolicy" &&
        json::dump(root.at(key)) != json::dump(value))
      pending = true;
    root[key] = value;
  }
  std::string document;
  const bool disabling_fixed = !changes.at("fixed_sepolicy").bool_or(true);
  if (!detail::serialize_config(original, root, &document, disabling_fixed,
                                &changes) ||
      (before_save && !before_save(root)))
    return false;
  if (pending && !marker &&
      (ftruncate(lock.get(), 1) != 0 || fsync(lock.get()) != 0))
    return false;
  if (!(save ? save(document, original)
             : detail::write_text_atomic(path, document)))
    return false;
  if (!apply_runtime)
    return true;
  if (!apply_runtime(pending))
    return false;
  return !pending || (ftruncate(lock.get(), 0) == 0 && fsync(lock.get()) == 0);
}

} // namespace yukizygisk::settings
#endif // YUKIZYGISK_SETTINGS_HPP
