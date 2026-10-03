/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Runtime module description updates.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */

#pragma once

#include "kernel/uapi/viola.h"
#include "uapi/yukizygisk.h"

#include <cstddef>
#include <string>

namespace yukizygisk::description {

std::string render(const yz_viola_status &viola,
                   const yz_runtime_query_cmd &runtime,
                   const yz_runtime_record *records, size_t count);
bool update(const std::string &module_dir, const std::string &state);

} // namespace yukizygisk::description
