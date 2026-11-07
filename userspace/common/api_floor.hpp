/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk Android API floor.
 *
 * License: Apache-2.0
 *
 * Author: Rouyashiki Developers
 */

#pragma once

#if !defined(__ANDROID__)
#error "YukiZygisk userspace targets Android only"
#elif !defined(__ANDROID_API__)
#error \
    "__ANDROID_API__ is undefined: select a concrete Android API level with the NDK toolchain."

/*
 * Bionic uses 10000 when no concrete API level was selected. Rejecting this
 * sentinel prevents an unversioned target from bypassing the minimum check.
 */
#elif __ANDROID_API__ >= 10000
#error \
    "__ANDROID_API__ is __ANDROID_API_FUTURE__: select a concrete Android API level."
#elif __ANDROID_API__ < 31
#error \
    "YukiZygisk requires Android API 31 (Android 12) or newer. Do not lower this."
#endif
