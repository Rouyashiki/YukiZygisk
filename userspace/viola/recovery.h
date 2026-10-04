/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Authenticated daemon health for explicit Viola recovery.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */
#ifndef YUKIZYGISK_VIOLA_RECOVERY_H
#define YUKIZYGISK_VIOLA_RECOVERY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum viola_health_state {
  VIOLA_HEALTH_AVAILABLE,
  VIOLA_HEALTH_MISSING,
  VIOLA_HEALTH_UNRESPONSIVE,
  VIOLA_HEALTH_UNSUPPORTED,
  VIOLA_HEALTH_IDENTITY_ERROR,
  VIOLA_HEALTH_ERROR,
};

struct viola_health {
  enum viola_health_state state;
  int error;
  uint32_t pid;
  int ready;
  int reboot_required;
  int catalog_error;
};

/* The returned descriptors carry CLOEXEC and must be closed by the caller. */
int viola_recovery_lock(void);
int viola_daemon_lock(unsigned abi);
void viola_daemon_health(int control, int timeout_ms,
                         struct viola_health replies[2]);

#ifdef __cplusplus
}
#endif
#endif
