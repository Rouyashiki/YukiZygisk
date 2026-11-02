/* SPDX-License-Identifier: Apache-2.0 */
/* YukiZygisk - Stopped-runtime generations and the kernel activation gate. */
#include "userspace/common/runtime_guard.h"
#include <assert.h>
#include <stdatomic.h>
#include <stdbool.h>

static int dual = 1, running, boot_completed;
static uint32_t serial = 1;

static int property(const char *name, char *value, uint32_t *version) {
  *version = serial;
  strcpy(value, !strcmp(name, "ro.zygote") ? (dual ? "zygote64_32" : "zygote64") :
                !strcmp(name, "sys.boot_completed") ? (boot_completed ? "1" : "0") :
                running ? "running" : "stopped");
  return 0;
}

static bool yz_auth_defer_until_ready, yz_auth_enabled = true;
static void *yz_auth_manifest = &dual;
typedef atomic_int atomic_t;
static atomic_t yz_auth_startup;
#define READ_ONCE(value) (value)
#define smp_load_acquire(pointer) (*(pointer))
#define atomic_read_acquire(pointer) atomic_load(pointer)
static int atomic_cmpxchg(atomic_t *pointer, int old, int value) {
  atomic_compare_exchange_strong(pointer, &old, value);
  return old;
}
#include "startup_gate.h"

int main(void) {
  struct yz_runtime_guard guard = {0};
  assert(yz_runtime_guard_check(&guard, property) == 0);
  for (dual = 0; dual <= 1; ++dual) {
    assert(yz_runtime_guard_capture(&guard, property) == 0);
    char text[YZ_RUNTIME_GUARD_TEXT];
    yz_runtime_guard_format(&guard, text);
    struct yz_runtime_guard inherited;
    assert(yz_runtime_guard_parse(&inherited, text) == 0);
    assert(yz_runtime_guard_check(&inherited, property) == 0);
    running = 1;
    assert(yz_runtime_guard_check(&guard, property) == -EAGAIN);
    running = 0;
    ++serial; /* A complete start/stop cycle must not revive the old attempt. */
    assert(yz_runtime_guard_check(&guard, property) == -EAGAIN);
    assert(yz_runtime_guard_capture(&guard, property) == 0);
    boot_completed = 1;
    assert(yz_runtime_guard_check(&guard, property) == -EAGAIN);
    boot_completed = 0;
  }
  const char *invalid[] = {"", "1,2,3", "1,2,3,4,5", "-1,2,3,4",
                          "4294967296,2,3,4", "1,2,3,x"};
  for (unsigned i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
    assert(yz_runtime_guard_parse(&guard, invalid[i]) == -EINVAL);

  yz_auth_defer_until_ready = true;
  atomic_store(&yz_auth_startup, YZ_AUTH_STARTUP_WAITING);
  assert(!yz_auth_catalog_ready()); /* No early-native or compat injection. */
  yz_auth_runtime_started();
  assert(yz_auth_activate_startup() == -EAGAIN);
  assert(!yz_auth_catalog_ready());
  atomic_store(&yz_auth_startup, YZ_AUTH_STARTUP_WAITING); /* A new attempt. */
  assert(yz_auth_activate_startup() == 0);
  assert(yz_auth_catalog_ready());
  yz_auth_runtime_started(); /* The expected exec after successful startup. */
  assert(yz_auth_catalog_ready());
  yz_auth_defer_until_ready = false;
  atomic_store(&yz_auth_startup, YZ_AUTH_STARTUP_WAITING);
  assert(yz_auth_catalog_ready()); /* Preserve ordinary early-native startup. */
  puts("PASS: stopped-runtime generations, handoff and kernel activation ordering");
  return 0;
}
