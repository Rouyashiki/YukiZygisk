#include "policy.hpp"

#include "uapi/yukizygisk.h"
#include "userspace/zygisk/late_load.hpp"

#include <cstdio>

namespace yzctl::policy {
namespace {

using yukizygisk::fixed_policy::domain_name;
using yukizygisk::fixed_policy::kBoot;
using yukizygisk::settings::detail::ScopedFd;
using yukizygisk::settings::detail::directory_of;
using yukizygisk::settings::detail::open_private_directory;
using yukizygisk::settings::detail::write_module_rules;
using yukizygisk::settings::kPendingRules;
using yukizygisk::settings::kRules;
using yukizygisk::settings::kStagedModule;
namespace published = yukizygisk::policy_rules;
constexpr unsigned kMaxIdentityAttempts = 8;

bool daemon_identity(const Host &host, yz_viola_daemon_identity_cmd *id) {
  *id = {};
  id->size = sizeof(*id);
  id->version = YZ_VIOLA_DAEMON_IDENTITY_VERSION;
  id->abi = YZ_RUNTIME_ABI_64;
  if (host.call(YZ_IOCTL_VIOLA_DAEMON_IDENTITY, id) != 0)
    return false;
  if (id->size != sizeof(*id) ||
      id->version != YZ_VIOLA_DAEMON_IDENTITY_VERSION ||
      id->abi != YZ_RUNTIME_ABI_64 || id->role != YZ_VIOLA_DAEMON64 ||
      id->state != YZ_VIOLA_READY || id->owner_alive != 1 || !id->pid ||
      !id->generation || !id->epoch || !id->start_boottime_ns) {
    errno = ENXIO;
    return false;
  }
  return true;
}

bool same_daemon(const Host &host, const yz_viola_daemon_identity_cmd &before) {
  yz_viola_daemon_identity_cmd after{};
  if (!daemon_identity(host, &after))
    return false;
  if (before.pid != after.pid ||
      before.start_boottime_ns != after.start_boottime_ns ||
      before.epoch != after.epoch || before.generation != after.generation) {
    errno = ESTALE;
    return false;
  }
  return true;
}

bool read_daemon_domain(const Host &host, std::string *domain,
                        yz_viola_daemon_identity_cmd *identity) {
  yz_viola_daemon_identity_cmd before{};
  std::string context;
  if (!daemon_identity(host, &before) ||
      !yukizygisk::crash::read_bounded("/proc/" + std::to_string(before.pid) +
                                           "/attr/current",
                                       4096, &context) ||
      !same_daemon(host, before))
    return false;
  const auto end = context.find(':', 4);
  if (context.compare(0, 4, "u:r:") != 0 || end == std::string::npos) {
    errno = EINVAL;
    return false;
  }
  *domain = context.substr(4, end - 4);
  *identity = before;
  return true;
}

bool observed_daemon(Host &host, std::string *provider, std::string *domain,
                     yz_viola_daemon_identity_cmd *identity) {
  yz_root_status_cmd root{};
  if (!host.open(nullptr) || host.call(YZ_IOCTL_GET_ROOT_STATUS, &root) != 0)
    return false;
  if (root.owner == YZ_ROOT_OWNER_UAPI_KERNELSU)
    *provider = "ksu";
  else if (root.owner == YZ_ROOT_OWNER_UAPI_KERNELPATCH)
    *provider = "apatch";
  else {
    errno = EOPNOTSUPP;
    return false;
  }

  return read_daemon_domain(host, domain, identity);
}

bool concrete_context(const std::string &name) {
  if (!domain_name(name) || name == "self") {
    errno = EINVAL;
    return false;
  }
  ScopedFd fd(open("/sys/fs/selinux/context", O_RDWR | O_CLOEXEC | O_NOFOLLOW));
  if (fd.get() < 0)
    return false;
  const std::string context = "u:r:" + name + ":s0";
  ssize_t n;
  do {
    n = write(fd.get(), context.c_str(), context.size() + 1);
  } while (n < 0 && errno == EINTR);
  if (n < 0)
    return false;
  if (static_cast<size_t>(n) != context.size() + 1) {
    errno = EIO;
    return false;
  }
  char canonical[128];
  do {
    n = read(fd.get(), canonical, sizeof(canonical));
  } while (n < 0 && errno == EINTR);
  if (n < 0)
    return false;
  if (n != static_cast<ssize_t>(context.size() + 1) ||
      memcmp(canonical, context.c_str(), context.size() + 1) != 0) {
    errno = EINVAL;
    return false;
  }
  return true;
}

bool memfd_class_available(bool *present) {
  struct stat st{};
  *present = stat("/sys/fs/selinux/class/memfd_file", &st) == 0;
  return *present || errno == ENOENT;
}

bool render_checked(const std::string &provider, const std::string &daemon,
                    std::string *rules, const std::string *approved = nullptr) {
  bool memfd;
  if (!concrete_context(daemon) || !memfd_class_available(&memfd))
    return false;
  if (!approved) {
    *rules = published::render(provider, daemon, memfd);
    return true;
  }
  const auto match =
      published::compare_published_rules(*approved, provider, daemon, memfd);
  if (match == published::RuleMatch::Current) {
    *rules = *approved;
    return true;
  }
  if (match == published::RuleMatch::MemfdClassChanged) {
    *rules = kPendingRules;
    return true;
  }
  errno = ESTALE;
  return false;
}

bool trusted_rule_file(const struct stat &st) {
  return S_ISREG(st.st_mode) && st.st_uid == 0 && !(st.st_mode & 0022) &&
         st.st_nlink == 1;
}

// Old installations exposed a symlink to the data directory. Detach unsafe
// entries even when the restored configuration cannot be read.
bool retire_unsafe_rule(int dir, bool installed) {
  using namespace yukizygisk::settings::detail;
  struct stat st{};
  const auto state = stat_module_rule(dir, "sepolicy.rule", &st, installed);
  if (state != kUntrustedFile)
    return state != kStatError;
  return (!installed || record_rule_withdrawal()) &&
         unlinkat(dir, "sepolicy.rule", 0) == 0 && fsync(dir) == 0;
}

bool retire_unsafe_staged_rule() {
  ScopedFd dir(open_private_directory(kStagedModule));
  return dir.get() < 0 ? errno == ENOENT : retire_unsafe_rule(dir.get(), false);
}

bool read_saved(std::string *saved,
                size_t limit = yukizygisk::settings::kMaxRules,
                const std::string &directory = directory_of(kRules)) {
  namespace crash = yukizygisk::crash;
  ScopedFd module(open_private_directory(directory));
  struct stat st{};
  if (module.get() < 0 ||
      fstatat(module.get(), "sepolicy.rule", &st, AT_SYMLINK_NOFOLLOW) != 0)
    return false;
  if (!trusted_rule_file(st)) {
    errno = EPERM;
    return false;
  }
  if (!crash::read_bounded_at(module.get(), "sepolicy.rule", limit, saved,
                              crash::FileSource::RootPrivate, &st))
    return false;
  // An upgrade can replace the entire directory while its old fd stays valid.
  struct stat current{};
  const int status = lstat((directory + "/sepolicy.rule").c_str(), &current);
  if (status == 0 && crash::same_file_revision(st, current))
    return true;
  if (status == 0 || errno == ENOENT)
    errno = EAGAIN;
  saved->clear();
  return false;
}

bool staged_rules_match(const std::string &rules) {
  struct stat st{};
  if (lstat(kStagedModule, &st) != 0)
    return errno == ENOENT;
  std::string staged;
  return read_saved(&staged, rules.size(), kStagedModule) && staged == rules;
}

bool sync_staged_rules(const std::string &approved) {
  return staged_rules_match(approved) ||
         write_module_rules(kStagedModule, approved, true);
}

bool valid_boot_record() {
  ScopedFd fd(open(kBoot, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
  struct stat st{};
  if (fd.get() < 0 || fstat(fd.get(), &st) != 0)
    return false;
  yz_fixed_policy_config record{};
  if (!S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & 0022) ||
      st.st_size != sizeof(record)) {
    errno = EINVAL;
    return false;
  }
  ssize_t n;
  do {
    n = read(fd.get(), &record, sizeof(record));
  } while (n < 0 && errno == EINTR);
  if (n < 0)
    return false;
  if (n != sizeof(record) || record.version != YZ_FIXED_POLICY_VERSION ||
      record.enabled > 1 || record.reserved ||
      record.count > YZ_FIXED_DOMAIN_MAX) {
    errno = EINVAL;
    return false;
  }
  for (uint32_t i = 0; i < record.count; ++i) {
    const auto &name = record.domains[i];
    if (!memchr(name, '\0', sizeof(name)) || !domain_name(name)) {
      errno = EINVAL;
      return false;
    }
  }
  return true;
}

bool reconcile_published_rules(json::Value *settings, const std::string &original,
                               bool *pending) {
  using namespace yukizygisk::settings::detail;
  *pending = false;
  yz_fixed_policy_config config{};
  if (!yukizygisk::fixed_policy::encode(*settings, &config))
    return false;
  if (!config.enabled)
    return withdraw_fixed_policy();

  std::string saved, provider, daemon;
  if (read_saved(&saved)) {
    if (saved == kPendingRules) {
      *pending = true;
      return sync_staged_rules(saved);
    }
    if (published::comparable_rules(saved) &&
        published::saved_identity(saved, &provider, &daemon)) {
      bool memfd;
      if (!memfd_class_available(&memfd))
        return false;
      const auto match =
          published::compare_published_rules(saved, provider, daemon, memfd);
      if (match == published::RuleMatch::Current) {
        if (concrete_context(daemon))
          return sync_staged_rules(saved);
        if (errno != EINVAL)
          return false;
      }
      // An OS update may retire a domain or change the optional class.
      if (match != published::RuleMatch::Mismatch) {
        if (!withdraw_fixed_policy(kPendingRules))
          return false;
        *pending = true;
        return true;
      }
    }
  } else if (errno != ENOENT && errno != EPERM && errno != EFBIG) {
    return false;
  }
  ScopedFd dir(open_private_directory(directory_of(kConfig)));
  if (dir.get() < 0 ||
      !repair_policy_config(dir.get(), ReadResult::Ready, settings, original))
    return false;
  fprintf(stderr, "yzctl: published rules do not match the fixed policy; "
                  "reverted to temporary mode.\n");
  return true;
}

bool prepare_boot_locked() {
  using namespace yukizygisk::settings::detail;
  json::Value config;
  if (!record_rule_scan())
    return false;
  std::string original;
  if (!read_locked(kConfig, &config, &original)) {
    const int config_error = errno;
    const int error = retire_unsafe_staged_rule() ? config_error : errno;
    ScopedFd dir(open_private_directory(directory_of(kRules)));
    struct stat st{};
    if (dir.get() >= 0) {
      const auto live = stat_module_rule(dir.get(), "sepolicy.rule", &st);
      if (live == kStatError ||
          (live == kUntrustedFile && !withdraw_fixed_policy()))
        return false;
    } else if (errno != ENOENT) {
      return false;
    }
    errno = error;
    return false;
  }
  bool pending;
  if (!reconcile_published_rules(&config, original, &pending) ||
      !retire_unsafe_staged_rule())
    return false;
  if (valid_boot_record())
    return true;
  if (errno != ENOENT)
    return false;
  if (pending)
    config["fixed_sepolicy"] = false;
  return yukizygisk::fixed_policy::write_boot_once(kBoot, config) ||
         (errno == EEXIST && valid_boot_record());
}

} // namespace

bool prepare_boot() {
  using namespace yukizygisk::settings::detail;
  namespace late_load = yukizygisk::late_load;
  ScopedFd lock(lock_config(kConfig));
  const bool prepared = lock.get() >= 0 && prepare_boot_locked();
  const int error = errno;
  if (late_load::active()) {
    if (prepared)
      return unlink(late_load::kPolicyErrorFile) == 0 || errno == ENOENT;
    const std::string reason =
        std::string("boot policy preparation failed: ") + strerror(error);
    if (!write_text_atomic(late_load::kPolicyErrorFile, reason))
      fprintf(stderr, "yzctl: cannot save late-load error: %s\n",
              strerror(errno));
  }
  errno = error;
  return prepared;
}

bool record_launch_policy_error() {
  namespace late_load = yukizygisk::late_load;
  if (!late_load::activation_pending())
    return true;
  Host host;
  yz_fixed_policy_status status{};
  // An unavailable control session cannot clear an earlier launch rejection.
  if (!host.open(nullptr) ||
      host.call(YZ_IOCTL_GET_FIXED_POLICY, &status) != 0 ||
      status.version != YZ_FIXED_POLICY_VERSION)
    return true;
  if (!status.error)
    return unlink(late_load::kLaunchPolicyErrorFile) == 0 || errno == ENOENT;
  return yukizygisk::settings::detail::write_text_atomic(
      late_load::kLaunchPolicyErrorFile,
      yukizygisk::fixed_policy::error_message(status));
}

bool PreparedRules::prepare(const json::Value &settings,
                            const char *install_provider) {
  yz_fixed_policy_config config{};
  if (!yukizygisk::fixed_policy::encode(settings, &config))
    return false;
  rules_.clear();
  identity_ = {};
  ScopedFd dir(open_private_directory(directory_of(kConfig)));
  if (dir.get() < 0 || !config.enabled)
    return dir.get() >= 0;

  std::string provider, daemon;
  for (unsigned attempt = 1;; ++attempt) {
    if (attempt > 1)
      usleep(10000);
    if (!observed_daemon(host_, &provider, &daemon, &identity_)) {
      if (errno == EAGAIN && attempt < kMaxIdentityAttempts)
        continue;
      if (identity_.generation || errno == EAGAIN || errno == ESTALE ||
          errno == EOPNOTSUPP)
        return false;
      break;
    }
    if (install_provider && provider != install_provider) {
      errno = EXDEV;
      return false;
    }
    const bool validated = host_.call(YZ_IOCTL_VALIDATE_FIXED_POLICY, &config) == 0;
    const bool prepared = validated && render_checked(provider, daemon, &rules_);
    const int policy_error = errno;
    // The validator consults the live daemon. If it changed, reread /proc
    // and validate the replacement before using its domain in any rule.
    if (!same_daemon(host_, identity_)) {
      if ((errno == ESTALE || errno == EAGAIN) && attempt < kMaxIdentityAttempts)
        continue;
      return false;
    }
    if (prepared)
      return true;
    errno = policy_error;
    if (validated)
      return false;
    if (errno == ENETUNREACH) {
      fprintf(
          stderr,
          "yzctl: fixed policy rejected: cannot verify host mount isolation "
          "or application-domain access to the cleanup daemon.\n");
      return false;
    }
    if (errno != ENOTTY && errno != EPERM)
      return false;
    break;
  }

  if (!install_provider) {
    fprintf(stderr,
            "yzctl: fixed policy requires a running daemon and a compatible "
            "kernel to verify mount isolation.\n");
    errno = ENETUNREACH;
    return false;
  }
  // An offline installation may retain approved rules or withdraw them.
  std::string saved;
  if (!read_saved(&saved)) {
    // A restored preference without a protected generation needs live
    // validation. A comment is safe for the host to scan in the meantime.
    if (errno != ENOENT)
      return false;
    rules_ = kPendingRules;
    return true;
  }
  if (saved == kPendingRules) {
    rules_ = saved;
    return true;
  }
  std::string saved_provider, saved_daemon;
  if (!published::saved_identity(saved, &saved_provider, &saved_daemon) ||
      (install_provider && saved_provider != install_provider) ||
      (!provider.empty() && saved_provider != provider) ||
      (!daemon.empty() && daemon != saved_daemon)) {
    errno = ESTALE;
    return false;
  }
  return render_checked(saved_provider, saved_daemon, &rules_, &saved);
}

bool PreparedRules::daemon_current() const {
  return !identity_.generation || rules_ == kPendingRules ||
         same_daemon(host_, identity_);
}

bool PreparedRules::save(const std::string &original,
                         const std::string *updated_config) const {
  using namespace yukizygisk::settings::detail;
  std::string current;
  if (!yukizygisk::crash::read_bounded(
          kConfig, yukizygisk::crash::kMaxDocument, &current,
          yukizygisk::crash::FileSource::RootPrivate))
    return false;
  if (current != original) {
    errno = EAGAIN;
    return false;
  }
  const auto save_config = [&] {
    return !updated_config || write_text_atomic(kConfig, *updated_config);
  };
  ScopedFd module(open_private_directory(directory_of(kRules)));
  if (module.get() < 0 && !(rules_.empty() && errno == ENOENT))
    return false;
  struct stat st{};
  if (lstat(kRules, &st) != 0) {
    if (errno != ENOENT)
      return false;
    if (rules_.empty())
      return withdraw_fixed_policy() && save_config();
  } else if (!rules_.empty() && trusted_rule_file(st) &&
             st.st_size == static_cast<off_t>(rules_.size())) {
    std::string saved;
    if (!read_saved(&saved))
      return false;
    if (saved == rules_ && staged_rules_match(rules_))
      return record_rule_withdrawal(rules_) && daemon_current() && save_config();
  }
  return persist_policy_update(updated_config, rules_, original,
                               [this] { return daemon_current(); });
}

bool PreparedRules::install(const char *directory) const {
  return write_module_rules(directory, rules_, false,
                            [this] { return daemon_current(); });
}

int publish(const char *install_provider, const char *install_dir) {
  using namespace yukizygisk::settings::detail;
  if (install_provider && strcmp(install_provider, "ksu") &&
      strcmp(install_provider, "apatch"))
    return 2;
  ScopedFd lock(lock_config(kConfig));
  if (lock.get() < 0)
    return 1;
  const auto installed = directory_of(kRules);
  ScopedFd active(open_private_directory(installed));
  if (active.get() < 0 && errno != ENOENT)
    return 1;
  bool copy_to_installer = install_dir != nullptr;
  if (install_dir) {
    ScopedFd incoming(open_private_directory(install_dir));
    struct stat target{}, current{};
    if (incoming.get() < 0 || fstat(incoming.get(), &target) != 0)
      return 1;
    if (active.get() >= 0) {
      if (fstat(active.get(), &current) != 0 ||
          !retire_unsafe_rule(active.get(), true))
        return 1;
      copy_to_installer = !same_file(target, current);
    }
    if (copy_to_installer && !retire_unsafe_rule(incoming.get(), false))
      return 1;
  }
  json::Value settings;
  std::string original;
  if (!read_locked(kConfig, &settings, &original))
    return 1;
  if (!install_provider) {
    bool pending;
    if (!reconcile_published_rules(&settings, original, &pending))
      return 1;
    if (!pending)
      return 0;
  }
  PreparedRules rules;
  if (!rules.prepare(settings, install_provider)) {
    fprintf(stderr, "yzctl: cannot prepare the requested fixed policy: %s\n",
            strerror(errno));
    return 1;
  }
  if ((!install_dir || active.get() >= 0) && !rules.save(original))
    return 1;
  if (copy_to_installer)
    return rules.install(install_dir) ? 0 : 1;
  return 0;
}

} // namespace yzctl::policy
