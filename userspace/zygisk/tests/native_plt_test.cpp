#include "fixture.hpp"
#include "plt_state.hpp"
#include "zygisk_next_api.h"

namespace yukizygisk::hyos {
static bool cached;
bool in_specialized_child() { return cached; }
} // namespace yukizygisk::hyos

constexpr int kSuccess = ZN_SUCCESS;
constexpr int kFailed = ZN_FAILED;
#undef LOGE
#define LOGE(...) ((void)0)
#undef LOGI
#define LOGI(...) ((void)0)
static bool map_from_base(void *base, lsplt::MapInfo *out) {
  *out = mapping(reinterpret_cast<uintptr_t>(base));
  return true;
}

#include "native_plt_under_test.inc"

static int install(Region &region, void **backup) {
  return api_plt_hook(reinterpret_cast<void *>(region.base), "target",
                      reinterpret_cast<void *>(replacement_fn), backup);
}
static void restore(Region &region) {
  CHECK(yukizygisk::apply_plt(
            false, {yukizygisk::restore_plt(
                       region.initial.dev, region.initial.inode, "target",
                       reinterpret_cast<void *>(original_fn),
                       reinterpret_cast<void *>(replacement_fn))})
            .success);
}

static void repeated_and_unknown_backup() {
  clean();
  Region region;
  void *backup;
  CHECK(install(region, &backup) == kSuccess);
  CHECK(backup == reinterpret_cast<void *>(original_fn));
  for (bool cached : {false, true}) {
    yukizygisk::hyos::cached = cached;
    void *fresh = nullptr;
    CHECK(install(region, &fresh) == kSuccess);
    CHECK(fresh == backup);
  }
  CHECK(lsplt::InvalidateBackup());
  void *fresh = nullptr;
  CHECK(install(region, &fresh) == kFailed && fresh == nullptr);
  restore(region);
  region.identity();
  clean();
  yukizygisk::hyos::cached = false;
}

static void own_result_and_concurrent_commit() {
  for (bool fail_install : {false, true}) {
    clean();
    Region region, queued;
    void *backup = nullptr;
    register_target(queued, nullptr, reinterpret_cast<void *>(other_fn),
                    "missing");
    faults(fail_install ? 1 : 0);
    lsplt::CommitReport legacy;
    int result = -1;
    std::atomic<bool> start{false};
    std::thread a([&] {
      while (!start.load())
        std::this_thread::yield();
      result = install(region, &backup);
    });
    std::thread b([&] {
      while (!start.load())
        std::this_thread::yield();
      legacy = lsplt::CommitHookDetailed();
    });
    start = true;
    a.join();
    b.join();
    CHECK(!legacy.success && legacy.registrations.size() == 1);
    CHECK(legacy.registrations[0].inode == queued.initial.inode);
    CHECK(result == (fail_install ? kFailed : kSuccess));
    CHECK(backup ==
          (fail_install ? nullptr : reinterpret_cast<void *>(original_fn)));
    CHECK(region.read(target_off) ==
          reinterpret_cast<uintptr_t>(fail_install ? original_fn
                                                   : replacement_fn));
    faults();
    if (!fail_install)
      restore(region);
    clean();
  }
}

static std::atomic<bool> entered, leave;
static void *live_original;
static uintptr_t live_callback() {
  CHECK(live_original == reinterpret_cast<void *>(original_fn));
  entered.store(true);
  while (!leave.load())
    std::this_thread::yield();
  return reinterpret_cast<uintptr_t (*)()>(live_original)();
}
static void await_entry(const void *, int prot) {
  if (!(prot & PROT_WRITE))
    while (!entered.load())
      std::this_thread::yield();
}

static void failed_publication_lifetime() {
  clean();
  Region region;
  live_original = nullptr;
  entered = leave = false;
  yukizygisk::plt_lifetime.retain_core.store(false);
  std::thread caller([&] {
    const auto callback = reinterpret_cast<uintptr_t>(live_callback);
    while (region.read(target_off) != callback)
      std::this_thread::yield();
    CHECK(reinterpret_cast<uintptr_t (*)()>(callback)() == 7);
  });
  faults(2);
  protect_observer = await_entry;
  CHECK(api_plt_hook(reinterpret_cast<void *>(region.base), "target",
                     reinterpret_cast<void *>(live_callback),
                     &live_original) == kFailed);
  CHECK(entered.load() && yukizygisk::plt_lifetime.retain_core);
  CHECK(region.read(target_off) == reinterpret_cast<uintptr_t>(original_fn));
  leave = true;
  caller.join();
  faults();
  CHECK(yukizygisk::apply_plt(false, {}).success);
  CHECK(live_original == reinterpret_cast<void *>(original_fn));
  CHECK(yukizygisk::plt_lifetime.retain_core);
  region.identity();
  clean();
}

int main() {
  repeated_and_unknown_backup();
  own_result_and_concurrent_commit();
  failed_publication_lifetime();
  puts("PASS production Native ZN: fresh backup, request isolation, concurrent "
       "commit and callback lifetime");
}
