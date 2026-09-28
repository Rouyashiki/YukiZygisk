/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Load configuration transport tests.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */

#include "userspace/zygisk/core/src/load_config.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <initializer_list>
#include <thread>

namespace {

void expect_config(const yz_config &config, bool linker, bool anonymous) {
  assert((config.yukilinker != 0) == linker);
  assert(yukizygisk::config::anonymous(config) == anonymous);
}

int make_packet(__u16 flags) {
  char path[] = "/tmp/yz-load-config-XXXXXX";
  int fd = mkstemp(path);
  assert(fd >= 0);
  assert(unlink(path) == 0);
  yz_early_native_packet_header header{};
  header.magic = YZ_EARLY_NATIVE_PACKET_MAGIC;
  header.version = YZ_EARLY_NATIVE_VERSION;
  header.header_size = sizeof(header);
  header.entry_size = sizeof(yz_early_native_packet_entry);
  header.load_flags = flags;
  header.count = 1;
  assert(write(fd, &header, sizeof(header)) == sizeof(header));
  return fd;
}

void early_packets() {
  expect_config(yukizygisk::config::early_config(-1), true, true);
  int legacy = make_packet(0);
  expect_config(yukizygisk::config::early_config(legacy), true, true);
  close(legacy);
  for (bool linker : {false, true}) {
    for (bool anonymous : {false, true}) {
      yz_config expected{
          static_cast<__u8>(linker), 2, 1,
          static_cast<__u8>(anonymous ? YZ_MEMORY_ANONYMOUS : YZ_MEMORY_FILE)};
      int fd = make_packet(yukizygisk::config::load_flags(expected));
      assert(lseek(fd, 3, SEEK_SET) == 3);
      expect_config(yukizygisk::config::early_config(fd), linker, anonymous);
      assert(lseek(fd, 0, SEEK_CUR) == 3);
      yz_early_native_packet_header header{};
      assert(pread(fd, &header, sizeof(header), 0) == sizeof(header));
      assert(header.count == 1);
      header.version++;
      assert(pwrite(fd, &header, sizeof(header), 0) == sizeof(header));
      expect_config(yukizygisk::config::early_config(fd), true, true);
      assert(ftruncate(fd, 7) == 0);
      expect_config(yukizygisk::config::early_config(fd), true, true);
      close(fd);
    }
  }
}

int listen_for_config() {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  assert(fd >= 0);
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  constexpr size_t name_size = sizeof(zygiskd::kSocketName) - 1;
  memcpy(address.sun_path + 1, zygiskd::kSocketName, name_size);
  auto size =
      static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 + name_size);
  assert(bind(fd, reinterpret_cast<sockaddr *>(&address), size) == 0);
  assert(listen(fd, 1) == 0);
  return fd;
}

void runtime_packets() {
  for (bool linker : {false, true}) {
    for (bool anonymous : {false, true}) {
      yz_config expected{
          static_cast<__u8>(linker), 2, 1,
          static_cast<__u8>(anonymous ? YZ_MEMORY_ANONYMOUS : YZ_MEMORY_FILE)};
      int listener = listen_for_config();
      std::thread server([&] {
        int client = accept(listener, nullptr, nullptr);
        assert(client >= 0);
        uint8_t request = 0;
        assert(read(client, &request, 1) == 1);
        assert(request == static_cast<uint8_t>(zygiskd::Request::GetConfig));
        for (size_t i = 0; i < sizeof(expected); ++i)
          assert(write(client, reinterpret_cast<char *>(&expected) + i, 1) ==
                 1);
        close(client);
      });
      yz_config actual{};
      assert(yukizygisk::config::read_runtime(&actual));
      expect_config(actual, linker, anonymous);
      assert(actual.denylist_mode == 2 && actual.dmesg_log == 1);
      server.join();
      close(listener);
    }
  }
  int listener = listen_for_config();
  std::thread server([&] {
    int client = accept(listener, nullptr, nullptr);
    assert(client >= 0);
    uint8_t request = 0;
    assert(read(client, &request, 1) == 1);
    assert(write(client, "\1\0", 2) == 2);
    close(client);
  });
  yz_config config{0, 2, 1, YZ_MEMORY_FILE};
  assert(!yukizygisk::config::read_runtime(&config));
  expect_config(config, false, false);
  assert(config.denylist_mode == 2 && config.dmesg_log == 1);
  server.join();
  close(listener);
  assert(!yukizygisk::config::read_runtime(&config));
  expect_config(config, false, false);
}

} // namespace

int main() {
  early_packets();
  runtime_packets();
  puts("load configuration: four combinations, legacy packets, malformed "
       "packets, "
       "fragmented replies and unavailable daemon passed");
}
