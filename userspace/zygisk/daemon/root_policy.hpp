/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Userspace root-policy fallback.
 *
 * License: Apache-2.0
 *
 * Author: Rouyashiki Developers
 */
#pragma once

#include "uapi/yukizygisk.h"

#include <cstdint>

namespace yzpolicy {

bool setup(int control_fd, const yz_root_status_cmd &status,
           bool publish_cache = true);
bool active();
bool refresh(bool force);
bool query_uid(uint32_t uid, bool *should_umount);
// Query the registered KernelSU manager even when policy uses kernel callables.
bool uid_is_manager(uint32_t uid);
void handle_refresh_request(uint32_t uid);
const char *source_name();

} // namespace yzpolicy
