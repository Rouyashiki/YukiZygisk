/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Host fixture for explicit compat recovery in the real launcher.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */
#define ioctl fixture_ioctl
#define clock_gettime fixture_clock_gettime
#define poll fixture_poll
#define main viola_program_main
#include "userspace/viola/main.c"
#undef main
#include <stdarg.h>

static int scenario, requests, queries, ticks;

int fixture_clock_gettime(clockid_t clock, struct timespec *now) {
  (void)clock;
  now->tv_sec = ticks++ * 10;
  now->tv_nsec = 0;
  return 0;
}

int fixture_poll(struct pollfd *fds, nfds_t count, int timeout) {
  (void)fds;
  (void)count;
  (void)timeout;
  return 0;
}

int fixture_ioctl(int fd, unsigned long request, ...) {
  (void)fd;
  va_list args;
  va_start(args, request);
  void *arg = va_arg(args, void *);
  va_end(args);
  if (request == YZ_IOCTL_VIOLA_RECOVER_COMPAT) {
    const struct yz_viola_recover_cmd *cmd = arg;
    if (cmd->epoch != 7 || cmd->generation != 9) {
      errno = ESTALE;
      return -1;
    }
    ++requests;
    return 0;
  }
  if (request != YZ_IOCTL_VIOLA_STATUS) {
    errno = ENOTTY;
    return -1;
  }
  struct yz_viola_status *s = arg;
  memset(s, 0, sizeof(*s));
  s->size = sizeof(*s);
  s->version = YZ_VIOLA_VERSION;
  s->profile = VIOLA_PROFILE;
  const unsigned char release[] = VIOLA_RELEASE_ID_BYTES;
  const unsigned char trust[] = VIOLA_TRUST_ID_BYTES;
  memcpy(s->release_id, release, 32);
  memcpy(s->trust_id, trust, 32);
  s->epoch = 7;
  s->generation = 9;
  s->daemon64 = YZ_VIOLA_READY;
  s->compat_required = scenario != 1;
  s->daemon32 = scenario == 2 ? YZ_VIOLA_READY : YZ_VIOLA_LOST;
  if (requests) {
    s->compat_recovering = 1;
    s->daemon32 = YZ_VIOLA_STARTING;
    if (scenario == 0 && queries >= 2) {
      s->daemon32 = YZ_VIOLA_READY;
      s->compat_recovering = 0;
    }
    if (scenario == 3)
      ++s->generation;
    if (scenario == 4) {
      s->compat_recovering = 0;
      s->recovery_error = -ETXTBSY;
    }
    if (scenario == 6)
      s->daemon64 = YZ_VIOLA_LOST;
  }
  ++queries;
  return 0;
}

int main(int argc, char **argv) {
  if (argc != 2)
    return 2;
  scenario = atoi(argv[1]);
  struct yz_viola_status initial = {.epoch = 7, .generation = 9};
  int result = recover_compat(3, &initial);
  printf("%d %d\n", result, requests);
  return 0;
}
