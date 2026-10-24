#include "fixture.hpp"
#include "plt_state.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <string_view>

#define ZLOGE(...) ((void)0)
#define ZLOGI(...) ((void)0)

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
static bool ends_with(std::string_view text, std::string_view suffix) {
  return text.size() >= suffix.size() &&
         text.substr(text.size() - suffix.size()) == suffix;
}

#include "art_hook_under_test.inc"

#include "art_retire_under_test.inc"

using State = yukizygisk::ArtHookState;
static const auto original = reinterpret_cast<uintptr_t>(original_fn);
static const auto callback =
    reinterpret_cast<uintptr_t>(new_art_post_fork_child);
static const auto foreign = reinterpret_cast<uintptr_t>(other_fn);

struct ArtRegion : Region {
  char directory[64] = "/tmp/yukizygisk-art-XXXXXX";
  std::string path;

  explicit ArtRegion(size_t second) {
    setup_slots(*this, second);
    CHECK(mkdtemp(directory));
    path = std::string(directory) + "/libart.so";
    const int file =
        open(path.c_str(), O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    CHECK(file >= 0);
    CHECK(write(file, reinterpret_cast<void *>(base), length) ==
          static_cast<ssize_t>(length));
    CHECK(mmap(reinterpret_cast<void *>(base), length, PROT_READ,
               MAP_PRIVATE | MAP_FIXED, file,
               0) == reinterpret_cast<void *>(base));
    close(fd);
    fd = file;
    initial = mapping(base);
    g_art_hook = {};
    g_art_maps = {};
    g_art_post_fork_child.original = nullptr;
    yukizygisk::plt_lifetime.retain_core.store(false);
  }

  ~ArtRegion() {
    CHECK(unlink(path.c_str()) == 0);
    CHECK(rmdir(directory) == 0);
  }

  void store(size_t offset, uintptr_t value) {
    CHECK(mprotect(PageStart(base + offset), kPageSize,
                   PROT_READ | PROT_WRITE) == 0);
    __atomic_store_n(reinterpret_cast<uintptr_t *>(base + offset), value,
                     __ATOMIC_RELEASE);
    CHECK(mprotect(PageStart(base + offset), kPageSize, PROT_READ) == 0);
  }
};

static void check_original() {
  CHECK(reinterpret_cast<uintptr_t>(g_art_post_fork_child.original) ==
        original);
}

static void install(ArtRegion &region, size_t second) {
  hook_art_post_fork_child(true);
  CHECK(g_art_hook.state == State::Installed && g_art_hook.unhook_required);
  expect_values(region, second, callback, callback);
  check_original();
}

static void failed_install_cleanup() {
  for (const auto second : {adjacent, distant}) {
    for (const bool recovered_elsewhere : {false, true}) {
      clean();
      ArtRegion region(second);
      faults(second == adjacent ? 2u : 4u);
      conflict_cas = 2;
      conflict_value = foreign;
      hook_art_post_fork_child(true);
      CHECK(g_art_hook.state == State::NeedsCleanup);
      CHECK(!g_art_hook.unhook_required && pending_rollback);
      CHECK(yukizygisk::plt_lifetime.retain_core);
      expect_values(region, second, original, foreign);
      check_original();
      CHECK(!lsplt::ReleaseInactiveCache());
      faults(1);
      CHECK(!retire_art_fork_hook());
      CHECK(g_art_hook.state == State::NeedsCleanup);
      CHECK(!g_art_hook.unhook_required && pending_rollback && cas_calls == 0);
      faults();
      if (recovered_elsewhere)
        CHECK(yukizygisk::commit_plt(true).success);
      CHECK(retire_art_fork_hook());
      CHECK(g_art_hook.state == State::Retired && !g_art_hook.unhook_required);
      CHECK(!pending_rollback && cas_calls == 0);
      expect_values(region, second, original, foreign);
      CHECK(yukizygisk::plt_lifetime.retain_core);
      check_original();
      region.identity();
      clean();
    }
  }
}

static void installed_cleanup() {
  for (const auto second : {adjacent, distant}) {
    for (const bool already_restored : {false, true}) {
      clean();
      ArtRegion region(second);
      install(region, second);
      if (already_restored) {
        region.store(target_off, original);
        region.store(second, original);
      }
      CHECK(retire_art_fork_hook());
      CHECK(g_art_hook.state == State::Retired && !g_art_hook.unhook_required);
      expect_values(region, second, original, original);
      check_original();
      region.store(second, foreign);
      CHECK(retire_art_fork_hook());
      expect_values(region, second, original, foreign);
      region.identity();
      clean();
    }
  }
}

static void failed_unhook_retry() {
  for (const auto second : {adjacent, distant}) {
    for (const bool incomplete : {false, true}) {
      clean();
      ArtRegion region(second);
      install(region, second);
      const unsigned restore_failure = second == adjacent ? 2u : 8u;
      faults(restore_failure | (incomplete ? restore_failure << 1 : 0));
      CHECK(!retire_art_fork_hook());
      CHECK(g_art_hook.state == State::NeedsCleanup &&
            g_art_hook.unhook_required);
      CHECK(static_cast<bool>(pending_rollback) == incomplete);
      CHECK(yukizygisk::plt_lifetime.retain_core);
      expect_values(region, second,
                    incomplete && second == distant ? original : callback,
                    callback);
      check_original();
      faults();
      CHECK(retire_art_fork_hook());
      CHECK(g_art_hook.state == State::Retired && !g_art_hook.unhook_required);
      expect_values(region, second, original, original);
      CHECK(yukizygisk::plt_lifetime.retain_core);
      check_original();
      region.identity();
      clean();
    }
  }
}

static void unrelated_batch_failure() {
  clean();
  ArtRegion region(distant);
  install(region, distant);
  register_target(region, nullptr, reinterpret_cast<void *>(foreign),
                  "missing");
  CHECK(retire_art_fork_hook());
  CHECK(g_art_hook.state == State::Retired && !g_art_hook.unhook_required);
  CHECK(register_info.size() == 1);
  expect_values(region, distant, original, original);
  CHECK(!lsplt::CommitHookDetailed().success);
  region.store(distant, foreign);
  CHECK(retire_art_fork_hook());
  expect_values(region, distant, original, foreign);
  check_original();
  region.identity();
  clean();
}

static void unavailable_restore() {
  clean();
  ArtRegion region(distant);
  install(region, distant);
  const auto saved_original = g_art_post_fork_child.original;
  g_art_post_fork_child.original = nullptr;
  CHECK(!retire_art_fork_hook());
  CHECK(g_art_hook.state == State::NeedsCleanup && g_art_hook.unhook_required);
  expect_values(region, distant, callback, callback);
  g_art_post_fork_child.original = saved_original;
  const auto inode = g_art_maps.inode;
  g_art_maps.inode = 0;
  CHECK(!retire_art_fork_hook());
  CHECK(g_art_hook.state == State::NeedsCleanup && g_art_hook.unhook_required);
  expect_values(region, distant, callback, callback);
  g_art_maps.inode = inode;
  CHECK(retire_art_fork_hook());
  CHECK(g_art_hook.state == State::Retired && !g_art_hook.unhook_required);
  expect_values(region, distant, original, original);
  region.identity();
  clean();
}

static void foreign_hook_cleanup() {
  clean();
  ArtRegion region(distant);
  install(region, distant);
  region.store(distant, foreign);
  faults();
  CHECK(!retire_art_fork_hook());
  CHECK(g_art_hook.unhook_required && cas_calls == 0);
  CHECK(yukizygisk::plt_lifetime.retain_core);
  expect_values(region, distant, callback, foreign);
  check_original();
  region.store(distant, original);
  CHECK(retire_art_fork_hook());
  expect_values(region, distant, original, original);
  CHECK(yukizygisk::plt_lifetime.retain_core);
  clean();
}

int main() {
  failed_install_cleanup();
  installed_cleanup();
  failed_unhook_retry();
  unrelated_batch_failure();
  unavailable_restore();
  foreign_hook_cleanup();
  puts("PASS production ART install/retire: recovery-only cleanup, foreign "
       "slots, unhook retry, per-request success, original and retention");
}
