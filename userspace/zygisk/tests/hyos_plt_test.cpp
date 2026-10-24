#include "fixture.hpp"
#include "plt_state.hpp"

#include <fcntl.h>

#define ZLOGE(...) ((void)0)
#define ZLOGI(...) ((void)0)

static bool g_registration_open, g_available, g_hooks_ready;
static dev_t g_target_dev;
static ino_t g_target_inode;
static pid_t (*g_original_fork)();
static int (*g_original_setcontext)(uid_t, bool, const char *, const char *);
static int (*g_open_control_session)();
static size_t registered_module_count() { return 1; }
static pid_t replacement_fork() { return 11; }
static int replacement_setcontext(uid_t, bool, const char *, const char *) {
  return 11;
}
static int control_ok() { return open("/dev/null", O_RDONLY | O_CLOEXEC); }
static int control_failed() { return -1; }

#include "hyos_hook_under_test.inc"

static void setup_bridge(Region &region, size_t second = distant) {
  setup_slots(region, second);
  CHECK(mprotect(reinterpret_cast<void *>(region.base), length,
                 PROT_READ | PROT_WRITE) == 0);
  const char names[] = "\0fork\0selinux_android_setcontext\0";
  std::memcpy(reinterpret_cast<void *>(region.base + 0x500), names,
              sizeof(names));
  auto *sym = reinterpret_cast<ElfW(Sym) *>(region.base + 0x600);
  sym[1].st_name = 1;
  sym[2].st_name = 6;
  const uint32_t hash[] = {1, 3, 1, 0, 2, 0};
  std::memcpy(reinterpret_cast<void *>(region.base + 0x700), hash,
              sizeof(hash));
  auto *rel = reinterpret_cast<ElfW(Rela) *>(region.base + 0x800);
#if __SIZEOF_POINTER__ == 8
  rel[1].r_info = ELF64_R_INFO(2, ELF64_R_TYPE(rel[0].r_info));
#else
  rel[1].r_info = ELF32_R_INFO(2, ELF32_R_TYPE(rel[0].r_info));
#endif
  CHECK(mprotect(reinterpret_cast<void *>(region.base), length, PROT_READ) ==
        0);
  g_available = g_registration_open = true;
  g_hooks_ready = false;
  g_original_fork = nullptr;
  g_original_setcontext = nullptr;
  g_target_dev = region.initial.dev;
  g_target_inode = region.initial.inode;
  g_open_control_session = control_failed;
  yukizygisk::plt_lifetime.retain_core.store(false);
}

static void restore_owned_hooks() {
  CHECK(lsplt::RegisterHook(g_target_dev, g_target_inode, "fork",
                            reinterpret_cast<void *>(g_original_fork),
                            nullptr));
  CHECK(lsplt::RegisterHook(
      g_target_dev, g_target_inode, "selinux_android_setcontext",
      reinterpret_cast<void *>(g_original_setcontext), nullptr));
  CHECK(lsplt::CommitHookDetailed().success);
}

static void normal_and_existing_hooks() {
  clean();
  Region region;
  setup_bridge(region);
  g_open_control_session = control_ok;
  CHECK(install_registered_hooks() && g_hooks_ready);
  CHECK(install_registered_hooks());
  g_open_control_session = control_failed;
  CHECK(!install_registered_hooks());
  expect_values(region, distant, reinterpret_cast<uintptr_t>(replacement_fork),
                reinterpret_cast<uintptr_t>(replacement_setcontext));
  CHECK(!lsplt::ReleaseInactiveCache());
  CHECK(reinterpret_cast<void *>(g_original_fork) ==
        reinterpret_cast<void *>(original_fn));
  restore_owned_hooks();
  region.identity();
  clean();
}

static void conflicts_and_rollbacks() {
  for (const auto second : {adjacent, distant}) {
    clean();
    Region region;
    setup_bridge(region, second);
    conflict_cas = 2;
    conflict_value = reinterpret_cast<uintptr_t>(other_fn);
    CHECK(!install_registered_hooks());
    expect_values(region, second, reinterpret_cast<uintptr_t>(original_fn),
                  reinterpret_cast<uintptr_t>(other_fn));
    CHECK(reinterpret_cast<void *>(g_original_setcontext) ==
          reinterpret_cast<void *>(original_fn));
    CHECK(!pending_rollback);
    region.identity();
    clean();
  }
  for (const auto mask : {8u, 8u | 16u}) {
    clean();
    Region region;
    setup_bridge(region);
    faults(mask);
    CHECK(!install_registered_hooks());
    expect_values(region, distant, reinterpret_cast<uintptr_t>(original_fn),
                  reinterpret_cast<uintptr_t>(original_fn));
    CHECK(!pending_rollback && yukizygisk::plt_lifetime.retain_core);
    CHECK(g_original_fork && g_original_setcontext);
    region.identity();
    clean();
  }
}

static void pending_conflict() {
  clean();
  Region region;
  setup_bridge(region);
  faults(8u | 16u);
  conflict_cas = 3;
  conflict_value = reinterpret_cast<uintptr_t>(other_fn);
  CHECK(!install_registered_hooks());
  CHECK(pending_rollback && !lsplt::ReleaseInactiveCache());
  expect_values(region, distant, reinterpret_cast<uintptr_t>(replacement_fork),
                reinterpret_cast<uintptr_t>(other_fn));
  CHECK(register_info.empty());
  faults();
  CHECK(mprotect(PageStart(region.base + distant), kPageSize,
                 PROT_READ | PROT_WRITE) == 0);
  __atomic_store_n(reinterpret_cast<uintptr_t *>(region.base + distant),
                   reinterpret_cast<uintptr_t>(original_fn), __ATOMIC_RELEASE);
  CHECK(mprotect(PageStart(region.base + distant), kPageSize, PROT_READ) == 0);
  CHECK(lsplt::CommitHookDetailed().success);
  restore_owned_hooks();
  region.identity();
  clean();
}

static void unrelated_registration() {
  clean();
  Region region, unrelated;
  setup_bridge(region);
  void *backup = nullptr;
  register_target(unrelated, &backup);
  CHECK(!install_registered_hooks());
  expect_values(region, distant, reinterpret_cast<uintptr_t>(original_fn),
                reinterpret_cast<uintptr_t>(original_fn));
  CHECK(unrelated.read(target_off) == reinterpret_cast<uintptr_t>(original_fn));
  CHECK(backup == nullptr && register_info.size() == 1);
  CHECK(lsplt::CommitHookDetailed().success);
  CHECK(unrelated.read(target_off) ==
        reinterpret_cast<uintptr_t>(replacement_fn));
  register_target(unrelated, nullptr, backup);
  CHECK(lsplt::CommitHookDetailed().success);
  region.identity();
  unrelated.identity();
  clean();
}

int main() {
  normal_and_existing_hooks();
  conflicts_and_rollbacks();
  pending_conflict();
  unrelated_registration();
  puts(
      "PASS production HyperOS functions: Applied-only cleanup, foreign slots, "
      "existing hooks, pending recovery, original lifetime and unrelated "
      "requests");
}
