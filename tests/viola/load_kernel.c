/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Verify the real kernel loading path before any loading syscall.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */
#define syscall fixture_syscall
#define main viola_program_main
#include "userspace/viola/main.c"
#undef main
#include <stdarg.h>

static int calls;
static int runtime_state;

static int fixture_property(const char *name, char *value, uint32_t *serial) {
  *serial = runtime_state == 2 ? 2 : 1;
  strcpy(value, !strcmp(name, "ro.zygote") ? "zygote64_32" :
                !strcmp(name, "sys.boot_completed") ? "0" :
                runtime_state == 1 ? "running" : "stopped");
  return 0;
}

long fixture_syscall(long number, ...) {
  ++calls;
  if (number != SYS_init_module)
    abort();
  /* The fixture never loads a host kernel module. */
  return 0;
}

int main(int argc, char **argv) {
  if (argc != 2 && argc != 3)
    return 2;
  if (argc == 3) {
    startup_property = fixture_property;
    if (yz_runtime_guard_capture(&startup_guard, startup_property))
      abort();
    runtime_state = atoi(argv[2]);
  }
  struct package package = {.dirfd = -1};
  int result = load_package(&package, argv[1]);
  if (!result)
    result = load_kernel(&package, 7);
  if (package.dirfd >= 0)
    close(package.dirfd);
  printf("%d %d\n", result, calls);
  return 0;
}
