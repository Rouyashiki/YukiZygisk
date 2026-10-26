#pragma once

#include <cstddef>
#include <cstdint>

namespace yukizygisk::handoff {

struct Result {
  bool complete = false;
  const char *reason = "not checked";
  uintptr_t slot = 0;
  uintptr_t target = 0;
};

Result verify(uintptr_t core, size_t size, uintptr_t loader,
              const uintptr_t *capabilities = nullptr, size_t count = 0);
Result verify_loaded(uintptr_t core_reference, uintptr_t loader,
                     const uintptr_t *capabilities = nullptr, size_t count = 0);

using TakeDependencies = bool (*)(void *const *, size_t);
using FinishHandoff = bool (*)(bool);
bool retirement_ready();

} // namespace yukizygisk::handoff
