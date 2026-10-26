// Core statics are process-lived and built with -fno-c++-static-destructors.
// Bind bootstrap no-ops locally; module destructor registries stay unchanged.
extern "C" __attribute__((visibility("hidden"))) int
__cxa_atexit(void (*)(void *), void *, void *) {
  return 0;
}

extern "C" __attribute__((visibility("hidden"))) void __cxa_finalize(void *) {}
