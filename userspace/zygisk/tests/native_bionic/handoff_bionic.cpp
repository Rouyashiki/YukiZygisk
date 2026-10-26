#include "check.hpp"
#include "loader_handoff.hpp"
#include "yukilinker.hpp"

#include <dlfcn.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char **argv) {
  CHECK(argc == 4);
  void *stage = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  CHECK(stage != nullptr);
  auto load = reinterpret_cast<void *(*)(int, const char *)>(
      dlsym(stage, "yuki_dlopen_memfd"));
  auto symbol = reinterpret_cast<void *(*)(void *, const char *)>(
      dlsym(stage, "yuki_dlsym"));
  auto retire =
      reinterpret_cast<bool (*)(void *)>(dlsym(stage, "retire_metadata"));
  CHECK(load != nullptr && symbol != nullptr && retire != nullptr);
  if (argv[3][0] == 's') {
    void *core = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    CHECK(core != nullptr);
    auto check = reinterpret_cast<bool (*)(uintptr_t)>(
        dlsym(core, "check_system_handoff"));
    auto call = reinterpret_cast<int (*)()>(dlsym(core, "call_imports"));
    CHECK(check != nullptr && call != nullptr);
    CHECK(check(reinterpret_cast<uintptr_t>(load)));
    CHECK(dlclose(stage) == 0);
    CHECK(call() == 42);
    CHECK(dlclose(core) == 0);
    puts("Bionic: system-owned core handoff checked and dependency lifetime "
         "retained");
    return 0;
  }
  int fd = open(argv[2], O_RDONLY | O_CLOEXEC);
  CHECK(fd >= 0);
  auto *core = static_cast<yukilinker::SoHandle *>(load(fd, ""));
  close(fd);
  CHECK(core != nullptr);
  if (argv[3][0] == 'p') {
    const auto result = yukizygisk::handoff::verify(
        reinterpret_cast<uintptr_t>(core->load_bias), core->map_size,
        reinterpret_cast<uintptr_t>(load));
    (void)fprintf(stderr, "production core handoff: %s slot=%p target=%p\n",
                  result.reason, reinterpret_cast<void *>(result.slot),
                  reinterpret_cast<void *>(result.target));
    CHECK(result.complete);
    auto completed = reinterpret_cast<bool (*)()>(
        symbol(core, "zygisk_bootstrap_handoff_complete"));
    CHECK(completed != nullptr && !completed());
    CHECK(retire(core));
    CHECK(dlclose(stage) == 0);
    CHECK(!completed());
    puts("Bionic: production Core relocations checked; legacy completion "
         "remains closed without initialization");
    return 0;
  }
  auto check = reinterpret_cast<bool (*)(uintptr_t, size_t, uintptr_t)>(
      symbol(core, "check_handoff"));
  auto call = reinterpret_cast<int (*)()>(symbol(core, "call_imports"));
  CHECK(check != nullptr && call != nullptr && call() == 42);
  const bool expected = argv[3][0] == '1';
  CHECK(check(reinterpret_cast<uintptr_t>(core->load_bias), core->map_size,
              reinterpret_cast<uintptr_t>(load)) == expected);
  if (!expected) {
    // Unrepaired imports require retaining the actual loader.
    CHECK(call() == 42);
    puts("Bionic: borrowed bootstrap callbacks detected; loader retained");
    return 0;
  }
  Dl_info info{};
  CHECK(dladdr(reinterpret_cast<void *>(load), &info) != 0);
  auto start = reinterpret_cast<bool (*)()>(symbol(core, "start_callback"));
  auto finish = reinterpret_cast<int (*)()>(symbol(core, "finish_callback"));
  CHECK(start != nullptr && finish != nullptr && start());
  const uintptr_t old_loader =
      reinterpret_cast<uintptr_t>(load) & ~uintptr_t{1};
  CHECK(retire(core));
  CHECK(dlclose(stage) == 0);
  CHECK(dladdr(reinterpret_cast<void *>(old_loader), &info) == 0);
  unsigned char residency = 0;
  const auto page = static_cast<uintptr_t>(getpagesize());
  CHECK(mincore(reinterpret_cast<void *>(old_loader & ~(page - 1)), page,
                &residency) == -1);
  CHECK(finish() == 42);
  CHECK(call() == 42);
  puts("Bionic: real bootstrap unmapped; deferred core callback, iterator and "
       "dependency still callable");
}
