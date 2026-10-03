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

long fixture_syscall(long number, ...) {
  ++calls;
  if (number != SYS_init_module)
    abort();
  /* The fixture never loads a host kernel module. */
  return 0;
}

int main(int argc, char **argv) {
  if (argc != 2)
    return 2;
  struct package package = {.dirfd = -1};
  int result = load_package(&package, argv[1]);
  if (!result)
    result = load_kernel(&package, 7);
  if (package.dirfd >= 0)
    close(package.dirfd);
  printf("%d %d\n", result, calls);
  return 0;
}
