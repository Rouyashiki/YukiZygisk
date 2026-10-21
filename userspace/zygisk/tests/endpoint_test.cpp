#include "userspace/zygisk/endpoint.hpp"

#include <array>
#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <thread>
#include <unistd.h>

namespace ep = yukizygisk::endpoint;

static int blocked_signal = -1;
static int resume_signal = -1;
static unsigned connect_interruptions;

extern "C" int __real_connect(int, const sockaddr *, socklen_t);
extern "C" int __wrap_connect(int fd, const sockaddr *address,
                              socklen_t length) {
  if (connect_interruptions && !(fcntl(fd, F_GETFL) & O_NONBLOCK)) {
    --connect_interruptions;
    errno = EINTR;
    return -1;
  }
  const int result = __real_connect(fd, address, length);
  const int error = errno;
  if (result < 0 && error == EAGAIN && blocked_signal >= 0) {
    const int signal = blocked_signal;
    blocked_signal = -1;
    assert(write(signal, "B", 1) == 1);
    char ready;
    assert(read(resume_signal, &ready, 1) == 1);
  }
  errno = error;
  return result;
}

static size_t descriptor_count() {
  DIR *directory = opendir("/proc/self/fd");
  assert(directory);
  size_t count = 0;
  while (readdir(directory))
    ++count;
  closedir(directory);
  return count;
}

static int memory_file(size_t size) {
  int fd = static_cast<int>(syscall(SYS_memfd_create, "", MFD_CLOEXEC));
  assert(fd >= 0 && ftruncate(fd, static_cast<off_t>(size)) == 0);
  return fd;
}

struct StatePage {
  int writable = memory_file(static_cast<size_t>(getpagesize()));
  int readonly = -1;
  yz_endpoint_state *page = nullptr;

  explicit StatePage(uint32_t abi = ep::kAbi) {
    assert(fchmod(writable, 0400) == 0);
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", writable);
    readonly = open(path, O_RDONLY | O_CLOEXEC);
    assert(readonly >= 0);
    page = static_cast<yz_endpoint_state *>(mmap(nullptr, getpagesize(),
                                                 PROT_READ | PROT_WRITE,
                                                 MAP_SHARED, writable, 0));
    assert(page != MAP_FAILED);
    page->version = YZ_ENDPOINT_VERSION;
    page->size = sizeof(*page);
    page->abi = abi;
  }

  ~StatePage() {
    munmap(page, getpagesize());
    close(readonly);
    close(writable);
  }

  void publish(int listener, uint64_t generation) {
    yz_endpoint_state next{};
    next.version = YZ_ENDPOINT_VERSION;
    next.size = sizeof(next);
    next.abi = ep::kAbi;
    next.available = listener >= 0;
    next.pid = listener >= 0 ? static_cast<uint32_t>(getpid()) : 0;
    next.start_boottime = listener >= 0 ? generation * 7 : 0;
    next.generation = generation;
    if (listener >= 0) {
      sockaddr_un address{};
      socklen_t length = sizeof(address);
      assert(getsockname(listener, reinterpret_cast<sockaddr *>(&address),
                         &length) == 0);
      assert(length == offsetof(sockaddr_un, sun_path) + 1 + sizeof(next.name));
      assert(address.sun_path[0] == '\0');
      memcpy(next.name, address.sun_path + 1, sizeof(next.name));
      next.name_length = sizeof(next.name);
    }
    const uint32_t sequence =
        __atomic_load_n(&page->sequence, __ATOMIC_RELAXED);
    __atomic_store_n(&page->sequence, sequence + 1, __ATOMIC_RELAXED);
    __atomic_thread_fence(__ATOMIC_RELEASE);
    std::array<uint32_t, sizeof(next) / 4> words{};
    memcpy(words.data(), &next, sizeof(next));
    auto *target = reinterpret_cast<uint32_t *>(page);
    for (size_t i = 1; i < words.size(); ++i)
      __atomic_store_n(target + i, words[i], __ATOMIC_RELAXED);
    __atomic_store_n(&page->sequence, sequence + 2, __ATOMIC_RELEASE);
  }
};

static unsigned random_calls;
static ssize_t zero_random(void *bytes, size_t size, unsigned) {
  ++random_calls;
  memset(bytes, 0, size);
  return static_cast<ssize_t>(size);
}
static ssize_t failed_random(void *, size_t, unsigned) {
  ++random_calls;
  errno = EIO;
  return -1;
}

static void random_names() {
  const auto before = descriptor_count();
  random_calls = 0;
  assert(ep::listen(failed_random) < 0 && errno == EIO && random_calls == 1);
  int occupied = ep::listen(zero_random);
  assert(occupied >= 0);
  random_calls = 0;
  assert(ep::listen(zero_random) < 0 && errno == EADDRINUSE &&
         random_calls == 8);
  close(occupied);
  std::array<char, YZ_ENDPOINT_NAME_LENGTH> previous{};
  for (unsigned i = 0; i < 32; ++i) {
    int fd = ep::listen();
    assert(fd >= 0);
    sockaddr_un address{};
    socklen_t length = sizeof(address);
    assert(getsockname(fd, reinterpret_cast<sockaddr *>(&address), &length) ==
           0);
    assert(length == offsetof(sockaddr_un, sun_path) + 1 + previous.size());
    assert(memcmp(previous.data(), address.sun_path + 1, previous.size()) != 0);
    memcpy(previous.data(), address.sun_path + 1, previous.size());
    close(fd);
  }
  assert(descriptor_count() == before);
}

static void readonly_and_layout() {
  for (uint32_t abi : {YZ_RUNTIME_ABI_32, YZ_RUNTIME_ABI_64}) {
    StatePage page(abi);
    ep::Mapping mapping;
    assert(!mapping.map(page.writable, abi) && errno == EPROTO);
    assert(!mapping.map(page.readonly, 3 - abi) && errno == EPROTO);
    assert(mapping.map(page.readonly, abi));
    yz_endpoint_state snapshot{};
    assert(mapping.read(snapshot) && snapshot.available == 0 &&
           snapshot.abi == abi);
    assert(ep::connect(mapping, ep::Clock::now()) < 0 && errno == ENOENT);
    void *address =
        mmap(nullptr, getpagesize(), PROT_READ, MAP_SHARED, page.readonly, 0);
    assert(address != MAP_FAILED);
    assert(mprotect(address, getpagesize(), PROT_READ | PROT_WRITE) < 0 &&
           errno == EACCES);
    assert(mmap(nullptr, getpagesize(), PROT_WRITE, MAP_SHARED, page.readonly,
                0) == MAP_FAILED);
    assert(pwrite(page.readonly, &snapshot, sizeof(snapshot), 0) < 0 &&
           errno == EBADF);
    munmap(address, getpagesize());
    __atomic_store_n(&page.page->sequence, 1, __ATOMIC_RELEASE);
    assert(!mapping.read(snapshot) && errno == EAGAIN);
    __atomic_store_n(&page.page->sequence, 2, __ATOMIC_RELEASE);
    page.page->version++;
    assert(!mapping.read(snapshot) && errno == EPROTONOSUPPORT);
  }
}

static void restart_and_publication() {
  StatePage page;
  ep::Mapping client;
  assert(client.map(page.readonly, ep::kAbi));
  int first = ep::listen();
  int second = ep::listen();
  assert(first >= 0 && second >= 0);
  page.publish(first, 1);
  yz_endpoint_state stale{};
  int pending = ep::start(client, stale);
  assert(pending >= 0 && ep::validate(pending, client, stale));
  page.publish(second, 2);
  assert(!ep::validate(pending, client, stale) && errno == ESTALE);
  close(pending);
  close(first);
  int connected = ep::connect(client, ep::Clock::now());
  assert(connected >= 0);
  int accepted = accept4(second, nullptr, nullptr, SOCK_CLOEXEC);
  assert(accepted >= 0);
  const char request = 'X';
  assert(send(connected, &request, 1, MSG_NOSIGNAL) == 1);
  char received = 0;
  assert(read(accepted, &received, 1) == 1 && received == request);
  // Revocation after the first byte must never open another session or replay
  // it.
  page.publish(-1, 3);
  close(accepted);
  assert(read(connected, &received, 1) == 0);
  close(connected);
  assert(ep::connect(client, ep::Clock::now()) < 0 && errno == ENOENT);

  page.publish(second, 4);
  page.page->pid++;
  assert(ep::connect(client, ep::Clock::now()) < 0 && errno == EACCES);
  page.publish(second, 5);
  std::atomic<bool> finished{false};
  std::thread writer([&] {
    for (uint64_t generation = uint64_t{UINT32_MAX} - 255;
         generation < uint64_t{UINT32_MAX} + 50000; ++generation)
      page.publish(second, generation);
    finished.store(true, std::memory_order_release);
  });
  size_t reads = 0;
  do {
    yz_endpoint_state current{};
    if (client.read(current)) {
      assert(current.start_boottime == current.generation * 7);
      assert(current.pid == static_cast<uint32_t>(getpid()));
      ++reads;
    } else {
      assert(errno == EAGAIN);
    }
  } while (!finished.load(std::memory_order_acquire));
  writer.join();
  assert(reads > 0);
  close(second);
}

static int packet(int endpoint_fd, int module_fd = -1) {
  yz_bootstrap_packet_header header{YZ_BOOTSTRAP_PACKET_MAGIC,
                                    YZ_BOOTSTRAP_PACKET_VERSION,
                                    sizeof(yz_bootstrap_packet_header),
                                    sizeof(yz_early_native_packet_entry),
                                    0,
                                    module_fd >= 0 ? 1U : 0U,
                                    endpoint_fd,
                                    0};
  int fd = memory_file(sizeof(header) +
                       (header.count * sizeof(yz_early_native_packet_entry)));
  assert(pwrite(fd, &header, sizeof(header), 0) == sizeof(header));
  if (module_fd >= 0) {
    yz_early_native_packet_entry entry{};
    entry.fd = module_fd;
    assert(pwrite(fd, &entry, sizeof(entry), sizeof(header)) == sizeof(entry));
  }
  return fd;
}

static void bootstrap_ownership() {
  StatePage page;
  const size_t before = descriptor_count();
  int endpoint_fd = dup(page.readonly);
  int fd = packet(endpoint_fd);
  ep::Mapping loader;
  assert(loader.map(endpoint_fd, ep::kAbi));
  assert(ep::initialize(fd, true));
  assert(fcntl(endpoint_fd, F_GETFD) < 0 && errno == EBADF);
  ep::close_packet(fd, false);
  assert(descriptor_count() == before);
  int listener = ep::listen();
  page.publish(listener, 1);
  yz_endpoint_state state{};
  assert(loader.read(state) && state.generation == 1);
  int connection = ep::connect(ep::Clock::now());
  assert(connection >= 0);
  close(connection);
  close(listener);
  loader.reset();
  ep::release();
  assert(ep::connect(ep::Clock::now()) < 0 && errno == ENOTCONN);
  endpoint_fd = dup(page.readonly);
  int module_fd = memory_file(1);
  fd = packet(endpoint_fd, module_fd);
  ep::close_packet(fd);
  assert(descriptor_count() == before);
}

static void bootstrap_publication() {
  StatePage page;
  const size_t before = descriptor_count();
  __atomic_store_n(&page.page->sequence, 1, __ATOMIC_RELEASE);
  const int endpoint_fd = dup(page.readonly);
  const int fd = packet(endpoint_fd);
  assert(ep::initialize(fd, false));
  assert(ep::connect(ep::Clock::now()) < 0 && errno == EAGAIN);
  assert(ep::initialize(fd, true));
  ep::close_packet(fd, false);
  assert(descriptor_count() == before);
  __atomic_store_n(&page.page->sequence, 2, __ATOMIC_RELEASE);
  int listener = ep::listen();
  assert(listener >= 0);
  page.publish(listener, 1);
  int connection = ep::connect(ep::Clock::now());
  assert(connection >= 0);
  close(connection);
  close(listener);
  ep::release();
  assert(ep::connect(ep::Clock::now()) < 0 && errno == ENOTCONN);

  ep::Mapping mapping;
  __atomic_store_n(&page.page->sequence, 5, __ATOMIC_RELEASE);
  assert(!mapping.map(page.readonly, 3 - ep::kAbi) && errno == EPROTO);
  page.page->version++;
  assert(!mapping.map(page.readonly, ep::kAbi) && errno == EPROTONOSUPPORT);
  page.page->version--;
  page.page->size++;
  assert(!mapping.map(page.readonly, ep::kAbi) && errno == EPROTONOSUPPORT);
  page.page->size--;
  page.page->reserved = 1;
  assert(!mapping.map(page.readonly, ep::kAbi) && errno == EPROTO);
  assert(descriptor_count() == before);
}

static void congested_connections() {
  StatePage page;
  ep::Mapping mapping;
  assert(mapping.map(page.readonly, ep::kAbi));
  for (bool restart : {false, true}) {
    const int listener = ep::listen();
    const int replacement = restart ? ep::listen() : -1;
    assert(listener >= 0 && (!restart || replacement >= 0));
    assert(listen(listener, 0) == 0);
    page.publish(listener, 1);
    yz_endpoint_state state{};
    const int occupied = ep::start(mapping, state);
    assert(occupied >= 0);
    const size_t before = descriptor_count();
    assert(ep::connect(mapping, ep::Clock::now(), true) < 0 && errno == EAGAIN);
    connect_interruptions = 2;
    const auto deadline = ep::Clock::now() + std::chrono::milliseconds(50);
    assert(ep::connect(mapping, deadline) < 0 && errno == ETIMEDOUT);
    assert(connect_interruptions == 0);
    assert(ep::Clock::now() >= deadline);
    assert(descriptor_count() == before);

    int blocked[2], resume[2];
    assert(pipe(blocked) == 0 && pipe(resume) == 0);
    blocked_signal = blocked[1];
    resume_signal = resume[0];
    std::thread server([&] {
      char ready;
      assert(read(blocked[0], &ready, 1) == 1);
      if (restart) {
        page.publish(replacement, 2);
        close(listener);
      } else {
        const int accepted = accept(listener, nullptr, nullptr);
        assert(accepted >= 0);
        close(accepted);
      }
      assert(write(resume[1], "R", 1) == 1);
    });
    const int connected = ep::connect(
        mapping, ep::Clock::now() + std::chrono::seconds(2), restart);
    assert(connected >= 0);
    server.join();
    assert((fcntl(connected, F_GETFL) & O_NONBLOCK) ==
           (restart ? O_NONBLOCK : 0));
    timeval timeout{};
    socklen_t timeout_size = sizeof(timeout);
    assert(getsockopt(connected, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                      &timeout_size) == 0);
    assert(timeout.tv_sec == 0 && timeout.tv_usec == 0);
    assert(send(connected, "X", 1, MSG_NOSIGNAL) == 1);
    const int accepted =
        accept(restart ? replacement : listener, nullptr, nullptr);
    assert(accepted >= 0);
    char received;
    assert(read(accepted, &received, 1) == 1 && received == 'X');
    close(accepted);
    close(connected);
    close(occupied);
    close(restart ? replacement : listener);
    resume_signal = -1;
    for (unsigned i = 0; i < 2; ++i) {
      close(blocked[i]);
      close(resume[i]);
    }
  }
}

int main() {
  assert(getuid() == 0);
  const auto before = descriptor_count();
  random_names();
  readonly_and_layout();
  restart_and_publication();
  bootstrap_ownership();
  bootstrap_publication();
  congested_connections();
  assert(descriptor_count() == before);
  puts("PASS: random endpoints, readonly pages, dual ABI layout, restart, "
       "publication, bootstrap ownership and connection congestion");
}
