/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - HyperOS Rust Runtime adapter.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */

#include "hyos_runtime.hpp"

#include "log.hpp"

#include "lsplt.hpp"

#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace yukizygisk::hyos {
namespace {

constexpr char kSpawnerPath[] = "/system_ext/bin/hyos_spawner";
constexpr size_t kValueCapacity = 512;

using ForkFn = pid_t (*)();
using SetContextFn = int (*)(uid_t uid, bool is_system_server,
                             const char *se_info, const char *package_name);

static_assert(ZYGISK_NEXT_API_VERSION == 4);
static_assert(ZYGISK_NEXT_HYOS_API_VERSION == 1);
static_assert(ZN_RUNTIME_HYOS == 1);
static_assert(sizeof(ZygiskNextAPI) == 10 * sizeof(void *));
static_assert(offsetof(ZygiskNextAPI, getRuntime) == 9 * sizeof(void *));
static_assert(offsetof(ZygiskNextRuntime, type) == 0);
static_assert(offsetof(ZygiskNextRuntime, api_version) == sizeof(int));
static_assert(offsetof(ZygiskNextRuntime, registerModule) ==
              (((2 * sizeof(int)) + alignof(void *) - 1) &
               ~(alignof(void *) - 1)));
static_assert(sizeof(ZygiskNextRuntime) ==
              offsetof(ZygiskNextRuntime, registerModule) + sizeof(void *));
static_assert(offsetof(ZygiskNextHyosModule, onAppSpecialized) ==
              ((sizeof(int) + alignof(void *) - 1) & ~(alignof(void *) - 1)));
static_assert(sizeof(ZygiskNextHyosModule) ==
              offsetof(ZygiskNextHyosModule, onAppSpecialized) +
                  sizeof(void *));
static_assert(sizeof(ZnHyosAppSpecializeArgs) == 3 * sizeof(void *));
struct RegisteredModule {
  ZygiskNextHyosModule module;
  const uint32_t *module_index;
};

std::vector<RegisteredModule> g_modules;

dev_t g_target_dev = 0;
ino_t g_target_inode = 0;
bool g_available = false;
bool g_registration_open = false;
bool g_hooks_ready = false;

ForkFn g_original_fork = nullptr;
SetContextFn g_original_setcontext = nullptr;
OpenControlSessionFn g_open_control_session = nullptr;
ReportCallbackFn g_report_callback = nullptr;
const uint32_t *g_registering_module_index = nullptr;
int g_child_control_session = -1;
std::atomic_flag g_child_control_lock = ATOMIC_FLAG_INIT;
std::atomic_flag g_fork_lock = ATOMIC_FLAG_INIT;
bool g_in_specialized_child = false;

bool g_child_ready = false;
bool g_child_dispatched = false;
char g_process_name[kValueCapacity]{};
char g_package_name[kValueCapacity]{};
char g_se_info[kValueCapacity]{};

std::string clean_map_path(const std::string &path) {
  constexpr char kDeleted[] = " (deleted)";
  constexpr size_t kDeletedLength = sizeof(kDeleted) - 1;
  if (path.size() >= kDeletedLength &&
      path.compare(path.size() - kDeletedLength, kDeletedLength, kDeleted) == 0)
    return path.substr(0, path.size() - kDeletedLength);
  return path;
}

bool valid_spawner_mapping(const lsplt::MapInfo &mapping) {
  if ((mapping.perms & PROT_READ) == 0 ||
      mapping.end - mapping.start < sizeof(Elf64_Ehdr))
    return false;
  const auto *header = reinterpret_cast<const Elf64_Ehdr *>(mapping.start);
  return memcmp(header->e_ident, ELFMAG, SELFMAG) == 0 &&
         header->e_ident[EI_CLASS] == ELFCLASS64 &&
         header->e_ident[EI_DATA] == ELFDATA2LSB &&
         (header->e_type == ET_DYN || header->e_type == ET_EXEC) &&
         header->e_machine == EM_AARCH64;
}

bool copy_value(char *destination, size_t capacity, const char *source) {
  if (source == nullptr || capacity == 0)
    return false;
  size_t length = 0;
  while (length < capacity && source[length] != '\0')
    ++length;
  if (length == capacity)
    return false;
  memcpy(destination, source, length + 1);
  return true;
}

bool read_process_name() {
  int fd;
  do {
    fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
  } while (fd < 0 && errno == EINTR);
  if (fd < 0)
    return false;

  size_t length = 0;
  bool complete = false;
  while (length + 1 < sizeof(g_process_name)) {
    char value = '\0';
    ssize_t result;
    do {
      result = read(fd, &value, sizeof(value));
    } while (result < 0 && errno == EINTR);
    if (result != sizeof(value))
      break;
    if (value == '\0') {
      complete = length != 0;
      break;
    }
    g_process_name[length++] = value;
  }
  close(fd);
  g_process_name[length] = '\0';
  return complete;
}

void reset_child_state(bool control_session_ready) {
  g_child_control_lock.clear(std::memory_order_release);
  g_in_specialized_child = true;
  g_child_ready = control_session_ready;
  g_child_dispatched = false;
  g_process_name[0] = '\0';
  g_package_name[0] = '\0';
  g_se_info[0] = '\0';
}

void dispatch_specialized(const char *se_info, const char *package_name) {
  if (!g_hooks_ready || !g_child_ready || g_child_dispatched)
    return;
  g_child_dispatched = true;

  if (!copy_value(g_package_name, sizeof(g_package_name), package_name) ||
      !copy_value(g_se_info, sizeof(g_se_info), se_info) ||
      !read_process_name())
    return;

  const ZnHyosAppSpecializeArgs args = {
      .process_name = g_process_name,
      .package_name = g_package_name,
      .se_info = g_se_info,
  };
  for (const auto &entry : g_modules) {
    entry.module.onAppSpecialized(&args);
    if (g_report_callback != nullptr && entry.module_index != nullptr &&
        *entry.module_index != UINT32_MAX)
      (void)g_report_callback(*entry.module_index);
  }
}

pid_t replacement_fork() {
  if (g_original_fork == nullptr)
    return -1;
  while (g_fork_lock.test_and_set(std::memory_order_acquire)) {
  }
  const int control_session =
      g_open_control_session != nullptr ? g_open_control_session() : -1;
  const pid_t result = g_original_fork();
  if (result == 0) {
    g_fork_lock.clear(std::memory_order_release);
    if (g_child_control_session >= 0)
      close(g_child_control_session);
    g_child_control_session = control_session;
    reset_child_state(control_session >= 0);
  } else if (control_session >= 0) {
    close(control_session);
  }
  if (result != 0)
    g_fork_lock.clear(std::memory_order_release);
  return result;
}

int replacement_setcontext(uid_t uid, bool is_system_server,
                           const char *se_info, const char *package_name) {
  if (g_original_setcontext == nullptr)
    return -1;
  const int result =
      g_original_setcontext(uid, is_system_server, se_info, package_name);
  if (result == 0)
    dispatch_specialized(se_info, package_name);
  return result;
}

int register_module(const void *module_pointer) {
  if (!g_registration_open || module_pointer == nullptr)
    return ZN_FAILED;
  const auto *module =
      static_cast<const ZygiskNextHyosModule *>(module_pointer);
  if (module->target_api_version != ZYGISK_NEXT_HYOS_API_VERSION ||
      module->onAppSpecialized == nullptr)
    return ZN_FAILED;

  g_modules.push_back({*module, g_registering_module_index});
  return ZN_SUCCESS;
}

const ZygiskNextRuntime g_runtime = {
    .type = ZN_RUNTIME_HYOS,
    .api_version = ZYGISK_NEXT_HYOS_API_VERSION,
    .registerModule = register_module,
};

bool rollback_partial_hooks() {
  bool pending = false;
  if (g_original_fork != nullptr)
    pending |=
        lsplt::RegisterHook(g_target_dev, g_target_inode, "fork",
                            reinterpret_cast<void *>(g_original_fork), nullptr);
  if (g_original_setcontext != nullptr)
    pending |= lsplt::RegisterHook(
        g_target_dev, g_target_inode, "selinux_android_setcontext",
        reinterpret_cast<void *>(g_original_setcontext), nullptr);
  return !pending || lsplt::CommitHook();
}

} // namespace

bool initialize(OpenControlSessionFn open_control_session,
                ReportCallbackFn report_callback) {
#ifndef __aarch64__
  (void)open_control_session;
  (void)report_callback;
  return false;
#else
  g_available = false;
  g_registration_open = false;
  g_hooks_ready = false;
  g_modules.clear();
  g_open_control_session = open_control_session;
  g_report_callback = report_callback;
  g_registering_module_index = nullptr;

  for (const auto &mapping : lsplt::MapInfo::Scan()) {
    if (mapping.offset != 0 || mapping.dev == 0 || mapping.inode == 0 ||
        clean_map_path(mapping.path) != kSpawnerPath ||
        !valid_spawner_mapping(mapping))
      continue;
    g_target_dev = mapping.dev;
    g_target_inode = mapping.inode;
    g_available = true;
    g_registration_open = true;
    ZLOGI("HyperOS Rust Runtime detected at %p",
          reinterpret_cast<void *>(mapping.start));
    return true;
  }
  return false;
#endif
}

bool available() { return g_available; }

const ZygiskNextRuntime *runtime() {
  return g_available ? &g_runtime : nullptr;
}

size_t registered_module_count() { return g_modules.size(); }

bool install_registered_hooks() {
  g_registration_open = false;
  const size_t count = registered_module_count();
  if (!g_available || count == 0)
    return true;

  g_original_fork = nullptr;
  g_original_setcontext = nullptr;
  const bool registered =
      lsplt::RegisterHook(g_target_dev, g_target_inode, "fork",
                          reinterpret_cast<void *>(replacement_fork),
                          reinterpret_cast<void **>(&g_original_fork)) &&
      lsplt::RegisterHook(g_target_dev, g_target_inode,
                          "selinux_android_setcontext",
                          reinterpret_cast<void *>(replacement_setcontext),
                          reinterpret_cast<void **>(&g_original_setcontext));
  const bool committed = registered && lsplt::CommitHook();
  bool control_ready = false;
  if (committed && g_original_fork != nullptr &&
      g_original_setcontext != nullptr && g_open_control_session != nullptr) {
    const int control_session = g_open_control_session();
    control_ready = control_session >= 0;
    if (control_session >= 0)
      close(control_session);
  }
  if (!control_ready) {
    const bool rolled_back = rollback_partial_hooks();
    if (rolled_back) {
      g_original_fork = nullptr;
      g_original_setcontext = nullptr;
    }
    ZLOGE("failed to install HyperOS Rust Runtime hooks; rollback=%u",
          rolled_back ? 1U : 0U);
    return false;
  }

  g_hooks_ready = true;
  ZLOGI("HyperOS Rust Runtime hooks installed for %zu module(s)", count);
  return true;
}

int child_control_session() { return g_child_control_session; }

bool in_specialized_child() { return g_in_specialized_child; }

void lock_child_control_session() {
  while (g_child_control_lock.test_and_set(std::memory_order_acquire)) {
  }
}

void unlock_child_control_session() {
  g_child_control_lock.clear(std::memory_order_release);
}

void invalidate_child_control_session() {
  if (g_child_control_session >= 0)
    close(g_child_control_session);
  g_child_control_session = -1;
  g_child_ready = false;
}

void begin_module_registration(const uint32_t *module_index) {
  g_registering_module_index = module_index;
}

void end_module_registration() { g_registering_module_index = nullptr; }

} // namespace yukizygisk::hyos
