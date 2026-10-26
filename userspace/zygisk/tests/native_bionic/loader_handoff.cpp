#include "check.hpp"
#include "loader_handoff_under_test.inc"

#include <array>
#include <dlfcn.h>

using namespace yukizygisk::handoff;

namespace {

struct Fixture {
  static constexpr size_t kSize = 8192;
  alignas(ElfW(Ehdr)) std::array<unsigned char, kSize> core{};
  alignas(ElfW(Ehdr)) std::array<unsigned char, kSize> loader{};
  Maps maps;

  static void image(unsigned char *memory) {
    auto *header = reinterpret_cast<ElfW(Ehdr) *>(memory);
    memcpy(header->e_ident, ELFMAG, SELFMAG);
    header->e_ident[EI_CLASS] =
        sizeof(uintptr_t) == 8 ? ELFCLASS64 : ELFCLASS32;
    header->e_ident[EI_DATA] = ELFDATA2LSB;
    header->e_ident[EI_VERSION] = EV_CURRENT;
    header->e_version = EV_CURRENT;
    header->e_type = ET_DYN;
#if defined(__aarch64__)
    header->e_machine = EM_AARCH64;
#elif defined(__arm__)
    header->e_machine = EM_ARM;
#else
    header->e_machine = EM_X86_64;
#endif
    header->e_ehsize = sizeof(*header);
    header->e_phoff = sizeof(*header);
    header->e_phentsize = sizeof(ElfW(Phdr));
    header->e_phnum = 2;
    auto *phdr = reinterpret_cast<ElfW(Phdr) *>(memory + header->e_phoff);
    phdr[0].p_type = PT_LOAD;
    phdr[0].p_flags = PF_R | PF_W;
    phdr[0].p_memsz = kSize;
    phdr[0].p_filesz = kSize / 2;
    phdr[1].p_type = PT_DYNAMIC;
    phdr[1].p_vaddr = 512;
    phdr[1].p_memsz = sizeof(ElfW(Dyn)) * 6;
  }

  Fixture() {
    image(core.data());
    image(loader.data());
    maps.push_back({base(), base() + kSize, 0, 0, 0, 0, true});
    maps.push_back(
        {stage(), stage() + (kSize / 2), 0, uint64_t{1} << 40, 1, 2, true});
    maps.push_back(
        {stage() + (kSize / 2), stage() + kSize, kSize / 2, 0, 0, 0, true});
    std::sort(maps.begin(), maps.end(),
              [](const Map &a, const Map &b) { return a.begin < b.begin; });
    dyn()[0].d_tag = kRel;
    dyn()[0].d_un.d_ptr = 1024;
    dyn()[1].d_tag = kRelSize;
    dyn()[1].d_un.d_val = 2 * sizeof(Relocation);
    dyn()[2].d_tag = kRelEntry;
    dyn()[2].d_un.d_val = sizeof(Relocation);
    rel()[0].r_offset = 2048;
    rel()[1].r_offset = 2048 + sizeof(uintptr_t);
#if defined(__aarch64__)
    rel()[0].r_info = ELF64_R_INFO(0, R_AARCH64_RELATIVE);
#elif defined(__arm__)
    rel()[0].r_info = ELF32_R_INFO(0, R_ARM_RELATIVE);
#else
    rel()[0].r_info = ELF64_R_INFO(0, R_X86_64_RELATIVE);
#endif
    rel()[1].r_info = rel()[0].r_info;
    slots()[0] = base() + 3000;
    slots()[1] = 0;
  }
  [[nodiscard]] uintptr_t base() const {
    return reinterpret_cast<uintptr_t>(core.data());
  }
  [[nodiscard]] uintptr_t stage() const {
    return reinterpret_cast<uintptr_t>(loader.data());
  }
  ElfW(Dyn) * dyn() { return reinterpret_cast<ElfW(Dyn) *>(core.data() + 512); }
  Relocation *rel() {
    return reinterpret_cast<Relocation *>(core.data() + 1024);
  }
  uintptr_t *slots() {
    return reinterpret_cast<uintptr_t *>(core.data() + 2048);
  }
  [[nodiscard]] Result check() const {
    return verify_snapshot(maps, base(), kSize, stage() + 512, nullptr, 0);
  }
};

void reference_tests() {
  Fixture f;
  CHECK(f.check().complete);
  for (uintptr_t offset : {uintptr_t{512}, uintptr_t{6000}}) {
    f.slots()[1] = f.stage() + offset;
    const auto failure = f.check();
    CHECK(!failure.complete &&
          failure.slot == f.base() + 2048 + sizeof(uintptr_t));
    CHECK(failure.target == f.slots()[1]);
  }
  f.slots()[1] = 42;
  CHECK(!f.check().complete);
  f.slots()[1] = 0;
  CHECK(f.check().complete);
  const uintptr_t borrowed[] = {f.stage() + 512};
  CHECK(!verify_snapshot(f.maps, f.base(), Fixture::kSize, f.stage() + 512,
                         borrowed, 1)
             .complete);
  f.dyn()[0].d_tag = DT_JMPREL;
  f.dyn()[1].d_tag = DT_PLTRELSZ;
  CHECK(f.check().complete);
  f.slots()[0] = f.stage() + 512;
  CHECK(!f.check().complete);
}

void relr_tests() {
  for (int tag : {36, 0x6fffe000}) {
    Fixture f;
    f.rel()[1].r_info = 0;
    f.dyn()[3].d_tag = tag;
    f.dyn()[3].d_un.d_ptr = 1536;
    f.dyn()[4].d_tag = tag == 36 ? 35 : 0x6fffe001;
    f.dyn()[4].d_un.d_val = 2 * sizeof(uintptr_t);
    auto *relr = reinterpret_cast<uintptr_t *>(f.core.data() + 1536);
    relr[0] = 2048;
    relr[1] = 3;
    CHECK(f.check().complete);
    f.slots()[1] = f.stage() + 6000;
    CHECK(!f.check().complete);
    f.slots()[1] = 0;
    relr[0] = 3;
    CHECK(!f.check().complete);
    relr[0] = UINTPTR_MAX - 1;
    CHECK(!f.check().complete);
  }
}

void malformed_tests() {
  {
    Fixture f;
    f.dyn()[0].d_un.d_ptr = UINTPTR_MAX;
    CHECK(!f.check().complete);
  }
  {
    Fixture f;
    f.dyn()[1].d_un.d_val++;
    CHECK(!f.check().complete);
  }
  for (auto tag : {36, 0x6fffe000, 0x6000000f, 0x60000011}) {
    Fixture f;
    f.dyn()[3].d_tag = tag;
    CHECK(!f.check().complete);
  }
  {
    Fixture f;
    f.rel()[0].r_offset = Fixture::kSize;
    CHECK(!f.check().complete);
    f.rel()[0].r_offset = 2049;
    CHECK(!f.check().complete);
    f.rel()[0].r_offset = UINTPTR_MAX;
    CHECK(!f.check().complete);
    f.rel()[0].r_offset = 2048;
    f.rel()[0].r_info = 0xffff;
    CHECK(!f.check().complete);
  }
  {
    Fixture f;
    for (size_t i = 3; i < 6; ++i)
      f.dyn()[i].d_tag = DT_DEBUG;
    CHECK(!f.check().complete);
  }
  {
    Fixture f;
    auto *header = reinterpret_cast<ElfW(Ehdr) *>(f.core.data());
    header->e_phoff = UINTPTR_MAX;
    CHECK(!f.check().complete);
  }
  {
    Fixture f;
    auto *header = reinterpret_cast<ElfW(Ehdr) *>(f.core.data());
    auto *phdr =
        reinterpret_cast<ElfW(Phdr) *>(f.core.data() + header->e_phoff);
    phdr[0].p_vaddr = 4096;
    CHECK(!f.check().complete);
  }
  {
    Fixture f;
    f.maps.clear();
    CHECK(!f.check().complete);
  }
  {
    Fixture f;
    for (auto &map : f.maps)
      map.inode = 0;
    CHECK(!f.check().complete);
  }
  {
    Fixture f;
    for (auto &map : f.maps)
      map.readable = false;
    CHECK(!f.check().complete);
  }
}

} // namespace

namespace bootstrap_fixture {
struct Dependency {
  void *system_handle;
  Dependency *next;
};
struct ImageState;
struct SoHandle {
  ImageState *private_state;
};
struct ImageState {
  struct {
    bool active = false;
  } tls;
  Dependency *dependencies = nullptr;
};
ImageState *g_first_image = nullptr, *g_last_image = nullptr;
bool cleanup_success = true;
int unregistered = 0, cleanups = 0;
ImageState *state_of(SoHandle *handle) { return handle->private_state; }
void unregister_image(ImageState *) { ++unregistered; }
bool shutdown() {
  ++cleanups;
  return cleanup_success;
}
#define ZLOGE(...) ((void)0)
#include "bootstrap_retirement_under_test.inc"
#undef ZLOGE
bool ready() { return true; }
bool not_ready() { return false; }
int finished = 0;
bool finish(bool) {
  ++finished;
  return true;
}
bool reject(void *const *, size_t) { return false; }
bool accept(void *const *handles, size_t count) {
  CHECK(count == 2 && handles[0] == reinterpret_cast<void *>(1) &&
        handles[1] == reinterpret_cast<void *>(2));
  return true;
}

void test() {
  Dependency b{reinterpret_cast<void *>(2), nullptr},
      a{reinterpret_cast<void *>(1), &b};
  ImageState image{{false}, &a};
  SoHandle core{&image};
  g_first_image = g_last_image = &image;
  CHECK(!prepare_bootstrap_retirement(&core, true, ready, accept, nullptr));
  CHECK(!prepare_bootstrap_retirement(&core, false, ready, accept, finish));
  CHECK(!prepare_bootstrap_retirement(&core, true, nullptr, accept, finish));
  CHECK(!prepare_bootstrap_retirement(&core, true, not_ready, accept, finish));
  CHECK(!prepare_bootstrap_retirement(&core, true, ready, nullptr, finish));
  CHECK(!prepare_bootstrap_retirement(&core, true, ready, reject, finish));
  image.tls.active = true;
  CHECK(!prepare_bootstrap_retirement(&core, true, ready, accept, finish));
  image.tls.active = false;
  CHECK(unregistered == 0 && cleanups == 0 && a.system_handle != nullptr &&
        b.system_handle != nullptr);
  cleanup_success = false;
  CHECK(!prepare_bootstrap_retirement(&core, true, ready, accept, finish));
  CHECK(unregistered == 1 && cleanups == 1 && a.system_handle == nullptr &&
        b.system_handle == nullptr);
  CHECK(core.private_state == nullptr);
  CHECK(finished == 0);
  a.system_handle = reinterpret_cast<void *>(1);
  b.system_handle = reinterpret_cast<void *>(2);
  core.private_state = &image;
  cleanup_success = true;
  CHECK(prepare_bootstrap_retirement(&core, true, ready, accept, finish));
  CHECK(prepare_bootstrap_retirement(nullptr, true, ready, nullptr, finish));
  CHECK(finished == 2);
}
} // namespace bootstrap_fixture

namespace finalizer_fixture {
bool g_loader_unmap_safe = true;
uintptr_t g_loader_base = 42;
uintptr_t g_self_base = 0;
int drops = 0, preparations = 0;
void zd_load_config() {}
void prepare_system_core_unmap(uintptr_t) { ++preparations; }
namespace yuki::solist {
int drop_lib_containing(uintptr_t base, bool keep) {
  CHECK(base == 42 && !keep);
  ++drops;
  return 1;
}
} // namespace yuki::solist
#define LOGI(...) ((void)0)
#include "core_finalizers_under_test.inc"
#undef LOGI

void test(bool authorized) {
  CHECK(zygisk_bootstrap_handoff_complete() == authorized);
  const int before = drops;
  const int prepared = preparations;
  ordinary_finalize(0, 0);
  native_finalize(0, 0);
  CHECK(drops == before + (authorized ? 2 : 0));
  CHECK(preparations == prepared + (authorized ? 1 : 0));
}
} // namespace finalizer_fixture

int main() {
  reference_tests();
  malformed_tests();
  relr_tests();
  bootstrap_fixture::test();
  finalizer_fixture::test(false);
  CHECK(!retirement_ready());
  CHECK(!zygisk_bootstrap_finish_handoff(true));
  CHECK(!retirement_ready());
  CHECK(!zygisk_bootstrap_take_dependencies(nullptr, 1));
  void *invalid[] = {nullptr};
  CHECK(!zygisk_bootstrap_take_dependencies(invalid, 1));
  void *handles[] = {reinterpret_cast<void *>(1), reinterpret_cast<void *>(2)};
  CHECK(zygisk_bootstrap_take_dependencies(handles, 2));
  CHECK(!retirement_ready());
  CHECK(zygisk_bootstrap_finish_handoff(true));
  CHECK(retirement_ready());
  finalizer_fixture::test(true);
  finalizer_fixture::g_loader_unmap_safe = false;
  finalizer_fixture::test(false);
  CHECK(!zygisk_bootstrap_finish_handoff(true));
  handles[0] = nullptr;
  CHECK(g_bootstrap_dependencies[0] == reinterpret_cast<void *>(1));
  CHECK(!zygisk_bootstrap_take_dependencies(handles, 2));
  free(g_bootstrap_dependencies);
  g_bootstrap_dependencies = nullptr;
  CHECK(!read_maps().empty());
  puts("loader handoff: references, malformed metadata, ownership and "
       "fail-closed gates passed");
}
