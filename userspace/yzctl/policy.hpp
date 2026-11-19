#pragma once

#include "host.hpp"
#include "kernel/uapi/viola_health.h"
#include "userspace/zygisk/settings.hpp"

namespace yzctl::policy {

using yukizygisk::settings::kConfig;

class PreparedRules {
public:
  bool prepare(const json::Value &settings,
               const char *install_provider = nullptr);
  bool save(const std::string &original,
            const std::string *updated_config = nullptr) const;
  bool install(const char *directory) const;

private:
  bool daemon_current() const;
  Host host_;
  yz_viola_daemon_identity_cmd identity_{};
  std::string rules_;
};

bool prepare_boot();
bool record_launch_policy_error();
int publish(const char *install_provider, const char *install_dir = nullptr);

} // namespace yzctl::policy
