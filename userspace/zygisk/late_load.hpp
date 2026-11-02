/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Late-load activation status shared by the daemon and yzctl.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */
#pragma once

#include "uapi/yukizygisk.h"

#include <cstddef>
#include <cstring>
#include <sys/stat.h>
#if defined(__ANDROID__)
#include <sys/system_properties.h>
#endif

namespace yukizygisk::late_load {

// Created by late-load.sh before startup; survives a userspace soft reboot.
inline constexpr char kStateDirectory[] = "/dev/yukizygisk-late-load";

struct Status {
  bool active = false;
  bool pending = false;
};

inline bool injection_pending(const char *zygote_config,
                              const yz_runtime_record *records, size_t count) {
  const bool dual_zygote = zygote_config != nullptr &&
      (std::strcmp(zygote_config, "zygote64_32") == 0 ||
       std::strcmp(zygote_config, "zygote32_64") == 0);
  bool primary = false;
  bool secondary = false;
  for (size_t i = 0; records != nullptr && i < count; ++i) {
    const auto &record = records[i];
    if (record.kind != YZ_RUNTIME_KIND_ZYGOTE || record.module_id[0] != '\0' ||
        record.state != YZ_RUNTIME_STATE_INJECTED)
      continue;
    primary |= std::strncmp(record.target, "zygote", sizeof(record.target)) == 0;
    secondary |= std::strncmp(record.target, "zygote_secondary",
                              sizeof(record.target)) == 0;
  }
  return !primary || (dual_zygote && !secondary);
}

inline Status query(bool safe_mode, const yz_runtime_record *records,
                    size_t count) {
  struct stat marker{};
  if (lstat(kStateDirectory, &marker) != 0 || !S_ISDIR(marker.st_mode) ||
      marker.st_uid != 0 || (marker.st_mode & (S_IWGRP | S_IWOTH)) != 0)
    return {};

  // Kernel safe mode remains latched across a userspace soft reboot, which
  // cannot complete injection while that protection is active.
  if (safe_mode)
    return {true, false};

#if defined(__ANDROID__)
  char zygote_config[PROP_VALUE_MAX]{};
  __system_property_get("ro.zygote", zygote_config);
#else
  constexpr char zygote_config[] = "";
#endif
  return {true, injection_pending(zygote_config, records, count)};
}

} // namespace yukizygisk::late_load
