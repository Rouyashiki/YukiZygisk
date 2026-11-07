/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Standalone userspace logger.
 *
 * License: Apache-2.0
 *
 * Author: Rouyashiki Developers
 */
#pragma once

#include "zygiskd.hpp"

#include <sys/types.h>

namespace zygiskd::logging {

void set_kernel_mirror(bool enabled);
void write(LogLevel level, LogSource source, pid_t pid, uid_t uid,
           const char *message);
[[gnu::format(printf, 3, 4)]] void writef(LogLevel level, LogSource source,
                                          const char *format, ...);

} // namespace zygiskd::logging
