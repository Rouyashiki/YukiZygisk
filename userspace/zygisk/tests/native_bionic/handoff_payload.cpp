#include "loader_handoff.hpp"

#include <cstdio>
#include <link.h>
#include <pthread.h>

extern "C" int handoff_dependency_value();
extern "C" int __cxa_atexit(void (*)(void *), void *, void *);
extern "C" void __cxa_finalize(void *);

extern "C" __attribute__((visibility("default"))) bool
check_system_handoff(uintptr_t loader) {
  return yukizygisk::handoff::verify_loaded(
             reinterpret_cast<uintptr_t>(check_system_handoff), loader)
      .complete;
}

extern "C" __attribute__((visibility("default"))) bool
check_handoff(uintptr_t base, size_t size, uintptr_t loader) {
  const auto result = yukizygisk::handoff::verify(base, size, loader);
  (void)fprintf(stderr, "handoff: %s slot=%p target=%p\n", result.reason,
                reinterpret_cast<void *>(result.slot),
                reinterpret_cast<void *>(result.target));
  return result.complete;
}

extern "C" __attribute__((visibility("default"))) int call_imports() {
  __cxa_finalize(nullptr);
  if (__cxa_atexit(nullptr, nullptr, nullptr) != 0)
    return -1;
  int seen = 0;
  dl_iterate_phdr(
      [](dl_phdr_info *, size_t, void *data) {
        ++*static_cast<int *>(data);
        return 0;
      },
      &seen);
  return seen > 0 ? handoff_dependency_value() : -1;
}

namespace {
pthread_mutex_t callback_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t callback_condition = PTHREAD_COND_INITIALIZER;
pthread_t callback_thread;
bool callback_waiting = false;
bool callback_released = false;
int callback_result = -1;

void *deferred_callback(void *) {
  pthread_mutex_lock(&callback_mutex);
  callback_waiting = true;
  pthread_cond_signal(&callback_condition);
  while (!callback_released)
    pthread_cond_wait(&callback_condition, &callback_mutex);
  pthread_mutex_unlock(&callback_mutex);
  callback_result = call_imports();
  return nullptr;
}
} // namespace

extern "C" __attribute__((visibility("default"))) bool start_callback() {
  if (pthread_create(&callback_thread, nullptr, deferred_callback, nullptr) !=
      0)
    return false;
  pthread_mutex_lock(&callback_mutex);
  while (!callback_waiting)
    pthread_cond_wait(&callback_condition, &callback_mutex);
  pthread_mutex_unlock(&callback_mutex);
  return true;
}

extern "C" __attribute__((visibility("default"))) int finish_callback() {
  pthread_mutex_lock(&callback_mutex);
  callback_released = true;
  pthread_cond_signal(&callback_condition);
  pthread_mutex_unlock(&callback_mutex);
  if (pthread_join(callback_thread, nullptr) != 0)
    return -1;
  return callback_result;
}
