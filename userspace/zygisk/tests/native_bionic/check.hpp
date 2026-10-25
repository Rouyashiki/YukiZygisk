#pragma once

#include <cstdio>
#include <cstdlib>

inline void fixture_check(bool condition, const char *expression,
                          const char *file, int line) {
  if (!condition) {
    (void)std::fprintf(stderr, "FAIL %s:%d: %s\n", file, line, expression);
    std::abort();
  }
}

#define CHECK(condition)                                                       \
  fixture_check(static_cast<bool>(condition), #condition, __FILE__, __LINE__)

extern "C" void fixture_event(int event);
extern "C" int yz_native_private_value();
extern "C" int yz_native_original();
