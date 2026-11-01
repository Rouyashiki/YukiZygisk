#pragma once

#include "native_bionic/check.hpp"
#include "plt_lifecycle.hpp"
#include "process_maps.hpp"
#include <yukiplt.hpp>

#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

struct PltFixture {
  void *library = nullptr;
  yukizygisk::MapInfo map;
  int (*call)() = nullptr;

  explicit PltFixture(const char *path) {
    library = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    CHECK(library != nullptr);
    call = reinterpret_cast<int (*)()>(dlsym(library, "fixture_call"));
    CHECK(call != nullptr && call() == 17);
    const auto address = reinterpret_cast<uintptr_t>(call);
    for (const auto &entry : yukizygisk::MapInfo::Scan()) {
      if (entry.start <= address && address < entry.end)
        map = entry;
    }
    CHECK(map.inode != 0);
  }
  ~PltFixture() { CHECK(dlclose(library) == 0); }
  PltFixture(const PltFixture &) = delete;
  PltFixture &operator=(const PltFixture &) = delete;

  yukiplt::NamedImage image() const {
    auto found = yukiplt::find_image_containing(reinterpret_cast<void *>(call));
    CHECK(found);
    return std::move(found.value());
  }
};
