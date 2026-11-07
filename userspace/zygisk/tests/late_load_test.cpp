/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Late-load activation and module description regression tests.
 *
 * License: Apache-2.0
 *
 * Author: Rouyashiki Developers
 */

#include "userspace/zygisk/late_load.hpp"
#include "userspace/zygisk/daemon/module_description.hpp"

#include <array>
#include <cassert>
#include <cerrno>
#include <cstdio>

namespace {
bool late_load = false;
bool activation_waiting = false;
mode_t marker_mode = S_IFDIR | 0700;
mode_t pending_mode = S_IFREG | 0600;
}

extern "C" int __real_lstat(const char *, struct stat *);
extern "C" int __wrap_lstat(const char *path, struct stat *result) {
  if (std::strcmp(path, yukizygisk::late_load::kPendingFile) == 0) {
    if (!late_load || !activation_waiting) {
      errno = ENOENT;
      return -1;
    }
    *result = {};
    result->st_mode = pending_mode;
    result->st_nlink = 1;
    return 0;
  }
  if (std::strcmp(path, yukizygisk::late_load::kStateDirectory) != 0)
    return __real_lstat(path, result);
  if (!late_load) {
    errno = ENOENT;
    return -1;
  }
  *result = {};
  result->st_mode = marker_mode;
  result->st_uid = 0;
  return 0;
}

int main() {
  namespace activation = yukizygisk::late_load;
  namespace description = yukizygisk::description;
  yz_viola_status viola{};
  viola.catalog_ready = 1;
  viola.daemon64 = YZ_VIOLA_READY;
  yz_runtime_query_cmd runtime{};
  std::array<yz_runtime_record, 2> records{};
  auto &primary = records[0];
  auto &secondary = records[1];
  const auto pending = [&](const char *configuration) {
    return activation::injection_pending(configuration, records.data(), records.size());
  };
  const auto render = [&] {
    return description::render(viola, runtime, records.data(), records.size());
  };

  // An ordinary boot must never acquire a late-load warning from empty records.
  assert(!activation::query(false, nullptr, 0).active);
  assert(!activation::query(false, nullptr, 0).pending);
  assert(!activation::activation_pending());
  assert(render().find("late-load") == std::string::npos);
  late_load = true;
  activation_waiting = true;
  assert(activation::activation_pending());
  assert(activation::query(false, nullptr, 0).active);
  assert(activation::query(false, nullptr, 0).pending);
  assert(render().find("请软重启完成注入") != std::string::npos);

  primary.kind = YZ_RUNTIME_KIND_ZYGOTE;
  primary.state = YZ_RUNTIME_STATE_INJECTED;
  primary.abi = YZ_RUNTIME_ABI_64;
  std::strcpy(primary.target, "zygote");
  assert(!pending("zygote64"));
  assert(!pending("zygote32"));
  assert(!pending(nullptr));
  assert(pending("zygote64_32"));
  assert(pending("zygote32_64"));

  // A compat daemon or a vendor/WebView Zygote does not complete the primary
  // and secondary service pair selected by ro.zygote.
  secondary = primary;
  secondary.abi = YZ_RUNTIME_ABI_32;
  std::strcpy(secondary.target, "zygote_ocomp");
  assert(pending("zygote64_32"));
  std::strcpy(secondary.target, "zygote_secondary");
  assert(!pending("zygote64_32"));
  assert(!pending("zygote32_64"));
  primary.state = YZ_RUNTIME_STATE_EXITED;
  assert(pending("zygote64_32"));
  primary.state = YZ_RUNTIME_STATE_INJECTED;
  for (const auto state : {YZ_RUNTIME_STATE_FAILED, YZ_RUNTIME_STATE_EXITED,
                          YZ_RUNTIME_STATE_SAFEMODE}) {
    secondary.state = state;
    assert(pending("zygote64_32"));
  }
  secondary.state = YZ_RUNTIME_STATE_INJECTED;
  secondary.kind = YZ_RUNTIME_KIND_NATIVE;
  assert(pending("zygote64_32"));
  secondary.kind = YZ_RUNTIME_KIND_ZYGOTE;
  std::strcpy(secondary.module_id, "module-only-report");
  assert(pending("zygote64_32"));
  secondary.module_id[0] = '\0';
  assert(!pending("zygote64_32"));

  // Initial late-load remains deferred even if a partial launch reported
  // injected Zygotes before its caller could consume the activation marker.
  assert(activation::query(false, records.data(), records.size()).pending);
  pending_mode = S_IFLNK | 0600;
  assert(!activation::activation_pending());
  pending_mode = S_IFREG | 0666;
  assert(!activation::activation_pending());
  pending_mode = S_IFREG | 0600;
  activation_waiting = false;
  assert(!activation::activation_pending());
  // Successful injection clears the action while preserving the mode label.
  assert(!activation::query(false, records.data(), records.size()).pending);
  assert(render().find("late-load | ") != std::string::npos);
  assert(render().find("soft reboot required") == std::string::npos);
  // Safe mode suppresses the action even when neither Zygote is injected.
  // Keep the late-load label, since a soft reboot cannot clear kernel safety.
  runtime.safe_mode = 1;
  activation_waiting = true;
  primary.state = YZ_RUNTIME_STATE_SAFEMODE;
  secondary.state = YZ_RUNTIME_STATE_EXITED;
  assert(activation::query(true, nullptr, 0).active);
  assert(!activation::query(true, nullptr, 0).pending);
  assert(!activation::query(true, records.data(), records.size()).pending);
  assert(render().find("safe mode") != std::string::npos);
  assert(render().find("late-load | ") != std::string::npos);
  assert(render().find("soft reboot required") == std::string::npos);
  assert(render().find("请软重启完成注入") == std::string::npos);
  activation_waiting = false;
  runtime.safe_mode = 0;
  // The renderer also gives a recorded SAFEMODE result precedence.
  assert(render().find("safe mode") != std::string::npos);
  assert(render().find("soft reboot required") == std::string::npos);
  primary.state = YZ_RUNTIME_STATE_EXITED;
  assert(activation::query(false, records.data(), records.size()).pending);
  assert(render().find("soft reboot required") != std::string::npos);

  marker_mode = S_IFLNK | 0700;
  assert(!activation::query(false, nullptr, 0).active);
  marker_mode = S_IFDIR | 0777;
  assert(!activation::query(false, nullptr, 0).active);
  std::puts("PASS: late-load status, Zygote coverage and safe-mode description transitions");
}
