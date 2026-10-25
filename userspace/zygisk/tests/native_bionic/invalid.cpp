#include "check.hpp"
#include "zygisk_next_api.h"

namespace {
__attribute__((constructor)) void constructed() { fixture_event(1); }
__attribute__((destructor)) void destroyed() { fixture_event(2); }
void unexpected(void *, const ZygiskNextAPI *) { std::abort(); }
} // namespace

extern "C" {
#if defined(INVALID_VERSION)
ZygiskNextModule zn_module = {99, unexpected};
#elif defined(NULL_ENTRY)
ZygiskNextModule zn_module = {ZYGISK_NEXT_API_VERSION, nullptr};
#endif
}
