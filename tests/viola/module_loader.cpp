/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Embedded loader regression fixture with no kernel mutations.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */
#include "userspace/viola/module_loader.h"

#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>

static int first_error, final_error, calls, compatibility_opens, kmsg_fd;
static bool no_memfd_load, vermagic_retry, forged_kmsg;
static const void *original_image;
static size_t original_size;

extern "C" int __real_open(const char *, int, ...);

// Do not read host symbols or mutate its kptr_restrict. The actual upstream
// parser consumes these controlled files, including module-symbol exclusion.
extern "C" int __wrap_open(const char *path, int flags, ...) {
  if (!std::strcmp(path, "/proc/sys/kernel/kptr_restrict")) {
    ++compatibility_opens;
    errno = EACCES;
    return -1;
  }
  if (!std::strcmp(path, "/proc/kallsyms")) {
    ++compatibility_opens;
    int fd = static_cast<int>(syscall(SYS_memfd_create, "symbols", MFD_CLOEXEC));
    assert(fd >= 0);
    const char symbols[] = "0000000000001234 T viola_fixture_symbol\n"
                           "0000000000005678 T module_only [other]\n";
    assert(write(fd, symbols, sizeof(symbols) - 1) == sizeof(symbols) - 1);
    assert(lseek(fd, 0, SEEK_SET) == 0);
    return fd;
  }
  if (!std::strcmp(path, "/dev/kmsg") || !std::strcmp(path, "/kmsg"))
    return dup(kmsg_fd);
  assert(!(flags & O_CREAT));
  return __real_open(path, flags);
}

static std::vector<uint8_t> image() {
  constexpr size_t sections = 5;
  const char strings[] = "\0viola_fixture_symbol\0module_only\0";
  const char names[] = "\0.symtab\0.strtab\0.shstrtab\0.modinfo\0";
  const char modinfo[] = "vermagic=old SMP\0name=yukizygisk\0";
  const size_t symoff = sizeof(Elf64_Ehdr) + sections * sizeof(Elf64_Shdr);
  const size_t stroff = symoff + 3 * sizeof(Elf64_Sym);
  const size_t nameoff = stroff + sizeof(strings);
  const size_t infooff = nameoff + sizeof(names);
  std::vector<uint8_t> data(infooff + sizeof(modinfo));
  auto *eh = reinterpret_cast<Elf64_Ehdr *>(data.data());
  std::memcpy(eh->e_ident, ELFMAG, SELFMAG);
  eh->e_ident[EI_CLASS] = ELFCLASS64;
  eh->e_ident[EI_DATA] = ELFDATA2LSB;
  eh->e_ident[EI_VERSION] = EV_CURRENT;
  eh->e_type = ET_REL;
  eh->e_machine = EM_AARCH64;
  eh->e_version = EV_CURRENT;
  eh->e_ehsize = sizeof(*eh);
  eh->e_shoff = sizeof(*eh);
  eh->e_shentsize = sizeof(Elf64_Shdr);
  eh->e_shnum = sections;
  eh->e_shstrndx = 3;
  auto *sh = reinterpret_cast<Elf64_Shdr *>(data.data() + eh->e_shoff);
  sh[1].sh_type = SHT_SYMTAB;
  sh[1].sh_name = 1;
  sh[1].sh_offset = symoff;
  sh[1].sh_size = 3 * sizeof(Elf64_Sym);
  sh[1].sh_entsize = sizeof(Elf64_Sym);
  sh[1].sh_link = 2;
  sh[2].sh_type = SHT_STRTAB;
  sh[2].sh_name = 9;
  sh[2].sh_offset = stroff;
  sh[2].sh_size = sizeof(strings);
  sh[3].sh_type = SHT_STRTAB;
  sh[3].sh_name = 17;
  sh[3].sh_offset = nameoff;
  sh[3].sh_size = sizeof(names);
  sh[4].sh_type = SHT_PROGBITS;
  sh[4].sh_name = 27;
  sh[4].sh_offset = infooff;
  sh[4].sh_size = sizeof(modinfo);
  sh[4].sh_addralign = 1;
  auto *sym = reinterpret_cast<Elf64_Sym *>(data.data() + symoff);
  sym[1].st_name = 1;
  sym[2].st_name = 22;
  std::memcpy(data.data() + stroff, strings, sizeof(strings));
  std::memcpy(data.data() + nameoff, names, sizeof(names));
  std::memcpy(data.data() + infooff, modinfo, sizeof(modinfo));
  return data;
}

static long admission(long number, unsigned long a0, unsigned long a1,
                      unsigned long a2) {
  ++calls;
  if (calls == 1) {
    assert(number == SYS_init_module && a0 == (unsigned long)original_image);
    assert(a1 == original_size && !std::strcmp((const char *)a2, "ksu_module_present=0"));
    errno = first_error;
    return first_error ? -1 : 0;
  }
  std::vector<uint8_t> loaded;
  if (number == SYS_finit_module) {
    assert(a2 == 0 && !std::strcmp((const char *)a1, "ksu_module_present=0"));
    int fd = static_cast<int>(a0);
    constexpr int seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    assert(fcntl(fd, F_GET_SEALS) == seals);
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    int writer = __real_open(path, O_RDWR | O_CLOEXEC);
    assert(writer >= 0);
    assert(pwrite(writer, "x", 1, 0) < 0 && errno == EPERM);
    assert(ftruncate(writer, 0) < 0 && errno == EPERM);
    close(writer);
    off_t size = lseek(fd, 0, SEEK_END);
    assert(size > 0);
    loaded.resize(static_cast<size_t>(size));
    assert(pread(fd, loaded.data(), loaded.size(), 0) == size);
    if (no_memfd_load) {
      errno = EOPNOTSUPP;
      return -1;
    }
  } else {
    assert(number == SYS_init_module);
    assert(!std::strcmp((const char *)a2, "ksu_module_present=0"));
    loaded.assign((const uint8_t *)a0, (const uint8_t *)a0 + a1);
  }
  const auto *eh = reinterpret_cast<const Elf64_Ehdr *>(loaded.data());
  const auto *sh = reinterpret_cast<const Elf64_Shdr *>(loaded.data() + eh->e_shoff);
  const auto *sym = reinterpret_cast<const Elf64_Sym *>(loaded.data() + sh[1].sh_offset);
  assert(sym[1].st_shndx == SHN_ABS && sym[1].st_value == 0x1234);
  assert(sym[2].st_shndx == SHN_UNDEF && sym[2].st_value == 0);
  if (vermagic_retry && calls == 2) {
    const char *record = forged_kmsg
      ? "14,1,1,-;yukizygisk: version magic 'old SMP' should be 'new SMP'\n"
      : "6,1,1,-;yukizygisk: version magic 'old SMP' should be 'new SMP'\n";
    assert(pwrite(kmsg_fd, record, std::strlen(record), 0) == (ssize_t)std::strlen(record));
    errno = ENOEXEC;
    return -1;
  }
  if (vermagic_retry)
    assert(!std::strcmp((const char *)loaded.data() + sh[4].sh_offset, "vermagic=new SMP"));
  errno = final_error;
  return final_error ? -1 : 0;
}

int main() {
  auto original = image();
  const auto saved = original;
  original_image = original.data();
  original_size = original.size();
  kmsg_fd = static_cast<int>(syscall(SYS_memfd_create, "kmsg", MFD_CLOEXEC));
  assert(kmsg_fd >= 0);
  for (int scenario = 0; scenario < 10; ++scenario) {
    first_error = scenario == 0 ? 0 : scenario == 1 ? EACCES :
                  scenario == 2 ? EKEYREJECTED : ENOENT;
    final_error = scenario == 5 ? EPERM : scenario == 8 ? ENOEXEC : 0;
    no_memfd_load = scenario == 4;
    vermagic_retry = scenario == 6 || scenario == 7 || scenario == 8;
    forged_kmsg = scenario == 7;
    calls = compatibility_opens = 0;
    assert(!ftruncate(kmsg_fd, 0));
    assert(lseek(kmsg_fd, 0, SEEK_SET) == 0);
    if (scenario == 9)
      original[0] = 0;
    int result = viola_load_verified_kernel(original.data(), original.size(),
                                             "ksu_module_present=0", admission);
    if (scenario == 0 || scenario == 3 || scenario == 4 || scenario == 6)
      assert(result == 0);
    else
      assert(result == -(scenario == 1 ? EACCES : scenario == 2 ? EKEYREJECTED :
                         scenario == 5 ? EPERM : scenario == 9 ? EBADMSG : ENOEXEC));
    if (scenario < 3 || scenario == 9)
      assert(calls == 1 && compatibility_opens == 0);
    else
      assert(calls == (scenario == 4 || scenario == 5 || scenario == 6 || scenario == 8 ? 3 : 2));
    if (scenario == 9)
      original[0] = saved[0];
    assert(original == saved);
  }
  close(kmsg_fd);
  puts("10 embedded loader scenarios passed");
}
