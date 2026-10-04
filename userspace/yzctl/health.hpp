/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Live kernel and authenticated daemon health diagnostics.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */

#pragma once
#include "json.hpp"
#include <cstdint>

namespace yzctl {
class Host;
json::Value kernel_health(Host &host, uint32_t capabilities);
json::Value daemon_health(Host &host);
} // namespace yzctl
