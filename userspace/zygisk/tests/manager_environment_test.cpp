/* SPDX-License-Identifier: Apache-2.0 */
// Real manager discovery and specialize functions with a fake KernelSU driver.
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <cassert>
#include <cstdarg>
#include <cstdio>

static int driver_ioctl(int, unsigned long, ...);
static int driver_prctl(int, ...);
static long driver_syscall(long, ...);
#define ioctl driver_ioctl
#define prctl driver_prctl
#define syscall driver_syscall
#include "userspace/zygisk/daemon/root_policy.cpp"
#undef ioctl
#undef prctl
#undef syscall
#include "userspace/zygisk/daemon/zygiskd.hpp"

static uint32_t manager_uid = 10420;
static bool driver_failure = false;
static bool legacy_driver = false;

static int driver_ioctl(int, unsigned long request, ...) {
  va_list args;
  va_start(args, request);
  void *output = va_arg(args, void *);
  va_end(args);
  if (request == yzpolicy::kKsuIoctlGetInfo) {
    *static_cast<uint32_t *>(output) = 12345;
    return 0;
  }
  if (request == yzpolicy::kKsuIoctlGetManagerUid && !driver_failure) {
    *static_cast<uint32_t *>(output) = manager_uid;
    return 0;
  }
  return -1;
}

static long driver_syscall(long request, ...) {
  if (request != SYS_reboot || legacy_driver)
    return -1;
  va_list args;
  va_start(args, request);
  (void)va_arg(args, int);
  (void)va_arg(args, int);
  (void)va_arg(args, int);
  *va_arg(args, int *) = open("/dev/null", O_RDONLY | O_CLOEXEC);
  va_end(args);
  return 0;
}

static int driver_prctl(int option, ...) {
  assert(option == yzpolicy::kKsuOption);
  va_list args;
  va_start(args, option);
  const auto command = va_arg(args, unsigned long);
  void *output = va_arg(args, void *);
  (void)va_arg(args, int);
  auto *result = va_arg(args, uint32_t *);
  va_end(args);
  if (command == yzpolicy::kKsuCmdGetVersion) {
    *static_cast<int *>(output) = 12345;
    return 0;
  }
  if (command == yzpolicy::kKsuCmdGetManagerUid && !driver_failure) {
    *static_cast<uint32_t *>(output) = manager_uid;
    *result = static_cast<uint32_t>(yzpolicy::kKsuOption);
    return 0;
  }
  return -1;
}

// Minimal Android/module glue; environment operations and fork are real.
using JNIEnv = void;
namespace zygisk {
struct AppSpecializeArgs {
  int uid;
};
constexpr uint32_t PROCESS_ON_DENYLIST = 2;
} // namespace zygisk
namespace yukizygisk::plt_lifecycle {
struct ExternalScope {
  explicit operator bool() const { return true; }
  int error() const { return 0; }
};
bool dispatch_allowed() { return true; }
} // namespace yukizygisk::plt_lifecycle
namespace yzhost {
bool uid_should_umount(uint32_t) { return true; }
} // namespace yzhost
struct AppSpecializeArgs_v1 {
  explicit AppSpecializeArgs_v1(zygisk::AppSpecializeArgs *) {}
};
struct ModuleAbi {
  void *impl;
  void (*postAppSpecialize)(void *, const zygisk::AppSpecializeArgs *);
};
struct Module {
  ModuleAbi *abi;
};
struct ModuleCallbackScope {
  explicit ModuleCallbackScope(Module &) {}
  explicit operator bool() const { return true; }
};
void *app_args_for(Module &, zygisk::AppSpecializeArgs *args,
                   AppSpecializeArgs_v1 *) {
  return args;
}
void unload_requested_modules(JNIEnv *) {}
void yz_drop_runtime_header_pages() {}
void zd_load_config() {}
static std::vector<Module> g_modules; // No installed Zygisk modules.
static std::atomic<int> g_plt_callback_tid{0};
static Module *g_cur = nullptr;
static int g_app_uid = -1;
static int g_manager_uid = -1;
static yz_config g_yz_config{};
static uid_t specialized_uid = 0;
static uid_t fixture_getuid() { return specialized_uid; }
#define getuid fixture_getuid
#define LOGE(...) ((void)0)
#define LOGI(...) ((void)0)
#include "manager_functions.inc"
#undef getuid

static void specialize(int requested_uid, int final_uid, bool expected) {
  const pid_t child = fork();
  assert(child >= 0);
  if (child == 0) {
    assert(zygisk_inject_decision(requested_uid) == 0);
    assert(getenv("ZYGISK_ENABLED") == nullptr);
    specialized_uid = final_uid;
    zygisk::AppSpecializeArgs args{final_uid};
    run_app_post_impl(nullptr, &args);
    const char *value = getenv("ZYGISK_ENABLED");
    assert(expected ? value && strcmp(value, "1") == 0 : value == nullptr);
    _exit(0);
  }
  int status = 0;
  assert(waitpid(child, &status, 0) == child);
  assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  assert(getenv("ZYGISK_ENABLED") == nullptr); // Parent zygote unchanged.
}

int main() {
  unsetenv("ZYGISK_ENABLED");
  for (bool legacy : {false, true}) {
    legacy_driver = legacy;
    yzpolicy::g = {};
    yz_root_status_cmd status{};
    status.owner = YZ_ROOT_OWNER_UAPI_KERNELSU;
    assert(yzpolicy::setup(-1, status, false));
    assert(!yzpolicy::active()); // Kernel-callable policy is the common path.
    assert(yzpolicy::uid_is_manager(10420));
    assert(yzpolicy::uid_is_manager(110420));
    assert(!yzpolicy::uid_is_manager(10421));
    assert(!yzpolicy::uid_is_manager(0));
    assert(!yzpolicy::uid_is_manager(99000));
    yzpolicy::g.enabled = true;
    assert(yzpolicy::uid_is_manager(10420)); // Fallback policy also works.
    yzpolicy::g.enabled = false;

    specialize(10420, 10420, true);
    specialize(110420, 110420, true);
    specialize(10421, 10421, false);
    specialize(99000, 99000, false);
    specialize(10420, 10421, false); // A module changed the target UID.
    specialize(10420, 0, false);     // Not specialized yet.
    g_app_uid = 10420;
    g_yz_config.denylist_mode = 2;
    assert(query_flags(10420) == (zygiskd::kProcessIsManager | 2));
    assert(api_get_flags(nullptr) == 2); // Private bit never enters the API.
    assert(zygisk_inject_decision(10420) == 1);
    g_yz_config.denylist_mode = 1;
    assert(zygisk_inject_decision(10420) == 2);
    g_yz_config.denylist_mode = 0;

    manager_uid = 10421; // Do not retain a stale registered manager.
    specialize(10420, 10420, false);
    specialize(10421, 10421, true);
    for (uint32_t invalid : {0U, 9999U, 20000U, UINT32_MAX}) {
      manager_uid = invalid;
      assert(!yzpolicy::uid_is_manager(10420));
    }
    manager_uid = 10420;
    driver_failure = true;
    specialize(10420, 10420, false);
    driver_failure = false;
    for (uint32_t owner :
         {YZ_ROOT_OWNER_UAPI_NONE, YZ_ROOT_OWNER_UAPI_KERNELPATCH}) {
      yzpolicy::g.owner = owner;
      specialize(10420, 10420, false);
    }
  }
  puts("PASS: manager discovery, specialize environment isolation and API "
       "flags");
}
