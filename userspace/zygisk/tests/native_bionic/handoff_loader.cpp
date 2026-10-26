#include "bootstrap_loader_under_test.inc"

#include <cstdarg>
#include <cstdio>

extern "C" void yz_log(uint8_t, const char *format, ...) {
  va_list args;
  va_start(args, format);
  (void)vfprintf(stderr, format, args);
  (void)fputc('\n', stderr);
  va_end(args);
}

extern "C" __attribute__((visibility("default"))) bool
retire_metadata(void *core) {
  auto *handle = static_cast<yukilinker::SoHandle *>(core);
  auto take = reinterpret_cast<yukizygisk::handoff::TakeDependencies>(
      yukilinker::dlsym(handle, "zygisk_bootstrap_take_dependencies"));
  return yukilinker::release_bootstrap_metadata(handle, take);
}
