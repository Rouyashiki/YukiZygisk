/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk logging.
 *
 * License: Apache-2.0
 *
 * Author: Rouyashiki Developers
 */
#pragma once

#if defined(YUKIZYGISK_RUNTIME_LOG)

#include "userspace/zygisk/daemon/zygiskd.hpp"

extern "C" __attribute__((format(printf, 2, 3))) void
yz_log(uint8_t level, const char *format, ...);

#define YZ_LOG(level, ...) yz_log(static_cast<uint8_t>(level), __VA_ARGS__)

#define ZLOGE(...) YZ_LOG(zygiskd::LogLevel::Error, __VA_ARGS__)
#define ZLOGW(...) YZ_LOG(zygiskd::LogLevel::Warning, __VA_ARGS__)
#define ZLOGI(...) YZ_LOG(zygiskd::LogLevel::Info, __VA_ARGS__)
#define ZLOGD(...) YZ_LOG(zygiskd::LogLevel::Debug, __VA_ARGS__)

#else

extern "C" __attribute__((weak, format(printf, 1, 2))) void
yz_klog(const char *fmt, ...);

#define YZ_LOG(...)                                                            \
  do {                                                                         \
    if (yz_klog != nullptr)                                                    \
      yz_klog(__VA_ARGS__);                                                    \
  } while (0)

#define ZLOGE(...) YZ_LOG(__VA_ARGS__)
#define ZLOGW(...) YZ_LOG(__VA_ARGS__)
#define ZLOGI(...) YZ_LOG(__VA_ARGS__)
#define ZLOGD(...) YZ_LOG(__VA_ARGS__)

#endif
