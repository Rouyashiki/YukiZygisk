#pragma once
#include <cstdint>
struct android_dlextinfo {
  uint64_t flags;
  void *reserved_addr;
  size_t reserved_size;
  int relro_fd;
  int library_fd;
  int64_t library_fd_offset;
  void *library_namespace;
};
constexpr uint64_t ANDROID_DLEXT_USE_LIBRARY_FD = 0x10;
extern "C" void *android_dlopen_ext(const char *, int,
                                    const android_dlextinfo *);
