/* SPDX-License-Identifier: Apache-2.0 */
/* YukiZygisk - Bind late-load startup to one stopped Android runtime. */
#ifndef YUKIZYGISK_RUNTIME_GUARD_H
#define YUKIZYGISK_RUNTIME_GUARD_H

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(__ANDROID__)
#include <sys/system_properties.h>
#endif

#define YZ_RUNTIME_GUARD_ENV "YUKIZYGISK_RUNTIME_GUARD"
#define YZ_RUNTIME_GUARD_TEXT 64

struct yz_runtime_guard {
  int enabled;
  uint32_t serial[4];
};

typedef int (*yz_runtime_property_reader)(const char *, char *, uint32_t *);

#if defined(__ANDROID__)
struct yz_runtime_property_value {
  char *value;
  uint32_t *serial;
};

static inline void yz_runtime_property_callback(void *opaque, const char *name,
                                                const char *value,
                                                uint32_t serial) {
  (void)name;
  struct yz_runtime_property_value *output =
      (struct yz_runtime_property_value *)opaque;
  snprintf(output->value, 92, "%s", value);
  *output->serial = serial;
}
#endif

static inline int yz_runtime_property(const char *name, char *value,
                                      uint32_t *serial) {
#if defined(__ANDROID__)
  const prop_info *property = __system_property_find(name);
  if (!property)
    return -EAGAIN;
  struct yz_runtime_property_value output = {value, serial};
  __system_property_read_callback(property, yz_runtime_property_callback, &output);
  return 0;
#else
  (void)name;
  (void)value;
  (void)serial;
  return -ENOTSUP;
#endif
}

static inline int yz_runtime_guard_capture(struct yz_runtime_guard *guard,
                                           yz_runtime_property_reader read) {
  char value[92];
  struct yz_runtime_guard next = {1, {0, 0, 0, 0}};
  if (read("ro.zygote", value, &next.serial[0]))
    return -EAGAIN;
  int dual = !strcmp(value, "zygote64_32") || !strcmp(value, "zygote32_64");
  if (!dual && strcmp(value, "zygote64") && strcmp(value, "zygote32"))
    return -EAGAIN;
  if (read("sys.boot_completed", value, &next.serial[1]) || strcmp(value, "0") ||
      read("init.svc.zygote", value, &next.serial[2]) || strcmp(value, "stopped"))
    return -EAGAIN;
  if (dual && (read("init.svc.zygote_secondary", value, &next.serial[3]) ||
               strcmp(value, "stopped")))
    return -EAGAIN;
  *guard = next;
  return 0;
}

static inline int yz_runtime_guard_check(const struct yz_runtime_guard *guard,
                                         yz_runtime_property_reader read) {
  if (!guard->enabled)
    return 0;
  struct yz_runtime_guard current;
  int result = yz_runtime_guard_capture(&current, read);
  /* Comparing serials also rejects a runtime that started and stopped again. */
  return result ? result : memcmp(guard->serial, current.serial,
                                  sizeof(guard->serial)) ? -EAGAIN : 0;
}

static inline void yz_runtime_guard_format(const struct yz_runtime_guard *guard,
                                           char text[YZ_RUNTIME_GUARD_TEXT]) {
  snprintf(text, YZ_RUNTIME_GUARD_TEXT, "%u,%u,%u,%u", guard->serial[0],
           guard->serial[1], guard->serial[2], guard->serial[3]);
}

static inline int yz_runtime_guard_parse(struct yz_runtime_guard *guard,
                                         const char *text) {
  struct yz_runtime_guard next = {1, {0, 0, 0, 0}};
  if (!text || !*text)
    return -EINVAL;
  for (unsigned i = 0; i < 4; ++i) {
    if (*text < '0' || *text > '9')
      return -EINVAL;
    char *end;
    errno = 0;
    unsigned long number = strtoul(text, &end, 10);
    if (errno || number > UINT32_MAX || *end != (i == 3 ? '\0' : ','))
      return -EINVAL;
    next.serial[i] = (uint32_t)number;
    text = end + (i != 3);
  }
  *guard = next;
  return 0;
}

#endif
