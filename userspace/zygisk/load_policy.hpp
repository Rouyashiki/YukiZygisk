/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Independent linker and memory policy.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */

#pragma once

#include "uapi/yukizygisk.h"

#include <cstddef>

namespace yukizygisk::config {

inline constexpr yz_config defaults{1, 0, 0, YZ_MEMORY_ANONYMOUS};

constexpr bool anonymous(const yz_config &config) {
  return config.memory_type != YZ_MEMORY_FILE;
}

constexpr __u16 load_flags(const yz_config &config) {
  return YZ_LOAD_CONFIG_VALID | (config.yukilinker ? YZ_LOAD_YUKILINKER : 0) |
         (anonymous(config) ? YZ_LOAD_ANONYMOUS : 0);
}

constexpr yz_config from_flags(__u16 flags) {
  yz_config config = defaults;
  if (flags & YZ_LOAD_CONFIG_VALID) {
    config.yukilinker = (flags & YZ_LOAD_YUKILINKER) != 0;
    config.memory_type =
        (flags & YZ_LOAD_ANONYMOUS) ? YZ_MEMORY_ANONYMOUS : YZ_MEMORY_FILE;
  }
  return config;
}

static_assert(sizeof(yz_config) == 4);
static_assert(offsetof(yz_config, memory_type) == 3);
static_assert(sizeof(yz_early_native_packet_header) == 16);
static_assert(offsetof(yz_early_native_packet_header, count) == 12);
static_assert(sizeof(yz_early_native_snapshot_header) == 72);
static_assert(offsetof(yz_early_native_snapshot_header, flags) == 12);

} // namespace yukizygisk::config
