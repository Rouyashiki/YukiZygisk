/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk shared C++ runtime shim.
 *
 * License: Apache-2.0
 *
 * Author: Rouyashiki Developers
 */

/*
 * Keep this include first so the API check sees the toolchain-provided value
 * before a bionic header can supply its future-version fallback.
 */
#include "api_floor.hpp"

#include <cstddef>

/*
 * Nothing in YukiZygisk demangles symbols. Satisfying this libc++abi reference
 * locally avoids linking the full demangler and unwinder into every target.
 */
// NOLINTBEGIN
extern "C" __attribute__((visibility("hidden"))) char *
__cxa_demangle(const char *mangled_name, char *output_buffer, size_t *length,
               int *status) {
  (void)mangled_name;
  (void)output_buffer;
  (void)length;
  if (status != nullptr)
    *status = -2;
  return nullptr;
}
// NOLINTEND
