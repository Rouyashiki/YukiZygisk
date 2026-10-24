#include "plt_state.hpp"

#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <dirent.h>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

static std::vector<std::string> logs;
static void logging(const char *format, ...) {
  char text[1024];
  va_list args;
  va_start(args, format);
  vsnprintf(text, sizeof(text), format, args);
  va_end(args);
  logs.emplace_back(text);
}
#define ZLOGI(...) logging(__VA_ARGS__)
#define ZLOGE(...) logging(__VA_ARGS__)

static bool ends_with(std::string_view text, std::string_view suffix) {
  return text.size() >= suffix.size() &&
         text.substr(text.size() - suffix.size()) == suffix;
}

static bool elf_valid;
static std::vector<uintptr_t> addresses;
struct Elf {
  explicit Elf(uintptr_t) {}
  bool Valid() const { return elf_valid; }
  std::vector<uintptr_t> FindPltAddr(const char *) const { return addresses; }
};

static std::vector<lsplt::MapInfo> maps;
static unsigned calls;
static void *replacement;
static void **original_output;
static lsplt::CommitStatus outcome;
static bool refuse_registration;
static void *tracked_original;
namespace lsplt {
inline namespace v2 {
std::vector<MapInfo> MapInfo::Scan(std::string_view) { return maps; }
bool RegisterHook(dev_t, ino_t, std::string_view, void *callback, void **out) {
  ++calls;
  if (refuse_registration) {
    errno = EINVAL;
    return false;
  }
  replacement = callback;
  original_output = out;
  return true;
}
CommitReport CommitHookDetailed() {
  CommitReport report;
  RegistrationResult entry;
  entry.dev = 1;
  entry.inode = 2;
  entry.symbol = "target";
  entry.callback = replacement;
  entry.status = outcome;
  entry.error =
      (outcome == CommitStatus::Applied || outcome == CommitStatus::NoChange)
          ? HookError::None
          : HookError::ProtectFailed;
  entry.error_number = entry.error == HookError::None ? 0 : EACCES;
  entry.ever_published =
      outcome != CommitStatus::Rejected && outcome != CommitStatus::NoChange;
  if (entry.ever_published && original_output)
    *original_output =
        reinterpret_cast<void *>(*reinterpret_cast<uintptr_t *>(addresses[0]));
  if (original_output && entry.ever_published)
    tracked_original = *original_output;
  if (original_output && outcome == CommitStatus::NoChange)
    *original_output = tracked_original;
  for (auto address : addresses) {
    auto *slot = reinterpret_cast<uintptr_t *>(address);
    const auto before = *slot;
    if (outcome == CommitStatus::Applied ||
        outcome == CommitStatus::RollbackIncomplete)
      *slot = reinterpret_cast<uintptr_t>(replacement);
    entry.slots.push_back({address, before, *slot, true,
                           outcome != CommitStatus::RollbackIncomplete});
  }
  report.success =
      outcome == CommitStatus::Applied || outcome == CommitStatus::NoChange;
  report.rollback_pending = outcome == CommitStatus::RollbackIncomplete;
  report.registrations.push_back(std::move(entry));
  return report;
}
CommitReport CommitHookCachedDetailed() { return CommitHookDetailed(); }
HookBatchReport ApplyHooksDetailed(const std::vector<HookRequest> &requests) {
  HookBatchReport batch;
  for (const auto &request : requests) {
    if (!RegisterHook(request.dev, request.inode, request.symbol,
                      request.callback, request.backup)) {
      RegistrationResult rejected;
      rejected.error = HookError::InvalidRequest;
      rejected.error_number = EINVAL;
      batch.results.push_back(rejected);
      batch.success = false;
      continue;
    }
    auto report = CommitHookDetailed();
    batch.success &= report.success;
    batch.rollback_pending |= report.rollback_pending;
    batch.results.push_back(std::move(report.registrations.front()));
  }
  return batch;
}
HookBatchReport
ApplyHooksCachedDetailed(const std::vector<HookRequest> &requests) {
  return ApplyHooksDetailed(requests);
}
} // namespace v2
} // namespace lsplt

static yukizygisk::ArtHookLifecycle g_art_hook;
static struct {
  dev_t dev;
  ino_t inode;
  bool ready;
} g_art_maps;
static struct {
  void (*original)(void *, bool, bool);
} g_art_post_fork_child;
static constexpr char kArtPostForkChild[] = "target";
static void new_art_post_fork_child(void *, bool, bool) {}
static void original_fn(void *, bool, bool) {}
static void other_fn(void *, bool, bool) {}

#include "art_hook_under_test.inc"

static uintptr_t storage[2];
static void reset() {
  storage[0] = storage[1] = reinterpret_cast<uintptr_t>(original_fn);
  addresses = {reinterpret_cast<uintptr_t>(&storage[0]),
               reinterpret_cast<uintptr_t>(&storage[1])};
  maps = {{addresses[0], addresses[1] + sizeof(uintptr_t), PROT_READ, true, 0,
           1, 2, "/test/libart.so"}};
  g_art_hook = {};
  yukizygisk::plt_lifetime.retain_core.store(false);
  g_art_post_fork_child.original = nullptr;
  calls = 0;
  tracked_original = nullptr;
  outcome = lsplt::CommitStatus::Applied;
  elf_valid = true;
  refuse_registration = false;
  logs.clear();
}

int main() {
  using State = yukizygisk::ArtHookState;
  for (int failure = 0; failure < 7; ++failure) {
    reset();
    auto valid_maps = maps;
    auto valid_addresses = addresses;
    switch (failure) {
    case 0:
      maps.clear();
      break;
    case 1:
      addresses.clear();
      break;
    case 2:
      addresses[0]++;
      break;
    case 3:
      storage[0] = 0;
      break;
    case 4:
      storage[1] = reinterpret_cast<uintptr_t>(other_fn);
      break;
    case 5:
      maps[0].is_private = false;
      break;
    case 6:
      elf_valid = false;
      break;
    }
    hook_art_post_fork_child(true);
    assert(calls == 0 && g_art_hook.state == State::Deferred);
    hook_art_post_fork_child(true);
    assert(calls == 0);
    maps = valid_maps;
    addresses = valid_addresses;
    storage[0] = storage[1] = reinterpret_cast<uintptr_t>(original_fn);
    elf_valid = true;
    hook_art_post_fork_child(false);
    assert(calls == 1 && g_art_hook.state == State::Installed);
    assert(g_art_hook.unhook_required);
    assert(g_art_post_fork_child.original == original_fn);
    hook_art_post_fork_child(false);
    assert(calls == 1);
  }
  reset();
  addresses.clear();
  hook_art_post_fork_child(false);
  assert(g_art_hook.state == State::FailedClean);
  addresses = {reinterpret_cast<uintptr_t>(storage)};
  hook_art_post_fork_child(false);
  assert(calls == 0);

  reset();
  outcome = lsplt::CommitStatus::Rejected;
  hook_art_post_fork_child(true);
  assert(g_art_hook.state == State::Deferred &&
         !yukizygisk::plt_lifetime.retain_core);
  outcome = lsplt::CommitStatus::Applied;
  hook_art_post_fork_child(false);
  assert(g_art_hook.state == State::Installed);

  for (const auto status : {lsplt::CommitStatus::RolledBack,
                            lsplt::CommitStatus::RollbackIncomplete}) {
    reset();
    outcome = status;
    hook_art_post_fork_child(true);
    assert(g_art_hook.state == (status == lsplt::CommitStatus::RolledBack
                                    ? State::FailedClean
                                    : State::NeedsCleanup));
    assert(yukizygisk::plt_lifetime.retain_core);
    assert(!g_art_hook.unhook_required);
    assert(g_art_post_fork_child.original == original_fn);
    hook_art_post_fork_child(false);
    assert(calls == 1);
    yukizygisk::plt_lifetime.observe(lsplt::CommitReport{});
    assert(yukizygisk::plt_lifetime.retain_core);
    const auto child = fork();
    assert(child >= 0);
    if (child == 0)
      _exit(yukizygisk::plt_lifetime.retain_core &&
                    g_art_post_fork_child.original == original_fn
                ? 0
                : 1);
    int child_status = 0;
    assert(waitpid(child, &child_status, 0) == child);
    assert(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
  }
  reset();
  refuse_registration = true;
  hook_art_post_fork_child(true);
  assert(g_art_hook.state == State::Deferred);
  refuse_registration = false;
  hook_art_post_fork_child(false);
  assert(g_art_hook.state == State::Installed);
  reset();
  hook_art_post_fork_child(true);
  g_art_hook = {};
  g_art_post_fork_child.original = nullptr;
  outcome = lsplt::CommitStatus::NoChange;
  hook_art_post_fork_child(false);
  assert(g_art_hook.state == State::Installed && calls == 2);
  assert(g_art_post_fork_child.original == original_fn);
  assert(current_thread_count() >= 1);
  std::atomic<bool> ready{false}, stop{false};
  std::thread worker([&] {
    ready = true;
    while (!stop)
      std::this_thread::yield();
  });
  while (!ready)
    std::this_thread::yield();
  assert(current_thread_count() >= 2);
  stop = true;
  worker.join();
  yukizygisk::PltLifetime concurrent_lifetime;
  lsplt::CommitReport failed_report;
  lsplt::RegistrationResult published;
  published.ever_published = true;
  published.status = lsplt::CommitStatus::RolledBack;
  failed_report.registrations.push_back(published);
  const lsplt::CommitReport clean_report;
  std::atomic<bool> start{false};
  std::thread failed_observer([&] {
    while (!start)
      std::this_thread::yield();
    for (int i = 0; i < 10000; ++i) {
      concurrent_lifetime.observe(failed_report);
      assert(concurrent_lifetime.retain_core);
    }
  });
  std::thread clean_observer([&] {
    while (!start)
      std::this_thread::yield();
    for (int i = 0; i < 10000; ++i)
      concurrent_lifetime.observe(clean_report);
  });
  start = true;
  failed_observer.join();
  clean_observer.join();
  assert(concurrent_lifetime.retain_core);
  puts("PASS production ART function: early/late probes, transaction states, "
       "original, concurrent retention and fork inheritance");
}
