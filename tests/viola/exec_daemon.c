/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Exercise the production frozen-FD daemon handoff.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */
#define ioctl fixture_ioctl
#define syscall fixture_syscall
#define main viola_program_main
#include "userspace/viola/main.c"
#undef main
#include <assert.h>
#include <stdarg.h>

static int pin_calls, arm_calls, exec_calls, fail_stage;
static unsigned expected_abi;
static int pinned_fd = -1;

int fixture_ioctl(int fd, unsigned long request, ...) {
  (void)fd;
  if (request == YZ_IOCTL_VIOLA_PIN_EXEC) {
    va_list args;
    va_start(args, request);
    struct yz_viola_exec_cmd *command = va_arg(args, void *);
    va_end(args);
    pinned_fd = command->image_fd;
    ++pin_calls;
    if (fail_stage == 1) { errno = EACCES; return -1; }
    return 0;
  }
  assert(request == YZ_IOCTL_VIOLA_ARM_EXEC);
  ++arm_calls;
  if (fail_stage == 2) { errno = EACCES; return -1; }
  return 0;
}

long fixture_syscall(long number, ...) {
  assert(number == SYS_execveat);
  va_list args;
  va_start(args, number);
  int fd = va_arg(args, int);
  const char *path = va_arg(args, const char *);
  char **argv = va_arg(args, char **);
  char **env = va_arg(args, char **);
  int flags = va_arg(args, int);
  va_end(args);
  assert(fd == pinned_fd && !*path && flags == AT_EMPTY_PATH && argv[0]);
  assert(arm_calls == 1);
  assert(!!(fcntl(fd, F_GETFD) & FD_CLOEXEC) == (expected_abi == VIOLA_ABI_ARM64));
  int found_image = 0;
  const char prefix[] = "YUKIZYGISK_IMAGE_FD=";
  for (; *env; ++env) {
    if (!strncmp(*env, prefix, sizeof(prefix) - 1)) {
      assert(atoi(*env + sizeof(prefix) - 1) == fd);
      ++found_image;
    }
  }
  assert(found_image == (expected_abi == VIOLA_ABI_ARM32));
  ++exec_calls;
  errno = ECANCELED;
  return -1;
}

int main(int argc, char **argv) {
  if (argc != 4) return 2;
  struct package package = {.dirfd = -1};
  expected_abi = (unsigned)atoi(argv[2]);
  fail_stage = atoi(argv[3]);
  int pipefd[2];
  assert(pipe2(pipefd, O_CLOEXEC) == 0);
  int result = load_package(&package, argv[1]);
  if (!result) result = execute_daemon(&package, pipefd[0], pipefd[1], expected_abi);
  printf("%d %d %d %d\n", result, pin_calls, arm_calls, exec_calls);
  return 0;
}
