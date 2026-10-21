#include "endpoint.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

namespace yukizygisk::endpoint {
namespace {
Mapping runtime;

bool fail(int error) {
  errno = error;
  return false;
}

bool valid_layout(const yz_endpoint_state &state, uint32_t abi) {
  if (state.version != YZ_ENDPOINT_VERSION || state.size != sizeof(state))
    return fail(EPROTONOSUPPORT);
  if (state.abi != abi || state.reserved)
    return fail(EPROTO);
  return true;
}

bool valid(const yz_endpoint_state &state, uint32_t abi) {
  if (!valid_layout(state, abi))
    return false;
  if (state.available > 1)
    return fail(EPROTO);
  if (!state.available)
    return true;
  if (state.name_length != sizeof(state.name) || !state.pid ||
      !state.generation || !state.start_boottime)
    return fail(EPROTO);
  for (char c : state.name)
    if ((c < '0' || c > '9') && (c < 'a' || c > 'f'))
      return fail(EPROTO);
  return true;
}

bool wait_connect(int fd, const sockaddr *target, socklen_t length,
                  Deadline deadline) {
  if (fcntl(fd, F_SETFL, 0) != 0)
    return false;
  for (;;) {
    const auto remaining =
        std::chrono::ceil<std::chrono::microseconds>(deadline - Clock::now());
    if (remaining.count() <= 0)
      return fail(ETIMEDOUT);
    const timeval timeout{
        static_cast<time_t>(remaining.count() / 1000000),
        static_cast<suseconds_t>(remaining.count() % 1000000)};
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0)
      return false;
    if (::connect(fd, target, length) == 0 || errno == EINPROGRESS)
      break;
    if (errno != EINTR && errno != EAGAIN)
      return false;
  }
  const timeval timeout{};
  return setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) ==
             0 &&
         fcntl(fd, F_SETFL, O_NONBLOCK) == 0;
}
} // namespace

bool Mapping::map(int fd, uint32_t abi) {
  reset();
  if (abi != YZ_RUNTIME_ABI_32 && abi != YZ_RUNTIME_ABI_64)
    return fail(EINVAL);
  struct stat status{};
  const int flags = fcntl(fd, F_GETFL);
  if (flags < 0 || fstat(fd, &status) != 0)
    return false;
  const auto page_size = static_cast<size_t>(getpagesize());
  if ((flags & O_ACCMODE) != O_RDONLY || !S_ISREG(status.st_mode) ||
      status.st_size != static_cast<off_t>(page_size))
    return fail(EPROTO);
  void *page = mmap(nullptr, page_size, PROT_READ, MAP_SHARED, fd, 0);
  if (page == MAP_FAILED)
    return false;
  page_ = static_cast<const yz_endpoint_state *>(page);
  length_ = page_size;
  abi_ = abi;
  yz_endpoint_state state{};
  // These fields are immutable, even while a new endpoint is being published.
  state.version = __atomic_load_n(&page_->version, __ATOMIC_RELAXED);
  state.size = __atomic_load_n(&page_->size, __ATOMIC_RELAXED);
  state.abi = __atomic_load_n(&page_->abi, __ATOMIC_RELAXED);
  state.reserved = __atomic_load_n(&page_->reserved, __ATOMIC_RELAXED);
  if (valid_layout(state, abi_) && (read(state) || errno == EAGAIN))
    return true;
  const int error = errno;
  reset();
  return fail(error);
}

void Mapping::reset() {
  if (page_)
    munmap(const_cast<yz_endpoint_state *>(page_), length_);
  page_ = nullptr;
  length_ = 0;
  abi_ = 0;
}

bool Mapping::read(yz_endpoint_state &state) const {
  if (!page_)
    return fail(ENOTCONN);
  for (unsigned attempt = 0; attempt < 3; ++attempt) {
    const uint32_t sequence =
        __atomic_load_n(&page_->sequence, __ATOMIC_ACQUIRE);
    if (sequence & 1U)
      continue;
    // Word-sized loads keep the same publication protocol on both ABIs.
    const auto *source = reinterpret_cast<const uint32_t *>(page_);
    std::array<uint32_t, sizeof(state) / sizeof(uint32_t)> words{};
    for (size_t i = 1; i < words.size(); ++i)
      words[i] = __atomic_load_n(source + i, __ATOMIC_RELAXED);
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    if (__atomic_load_n(&page_->sequence, __ATOMIC_RELAXED) != sequence)
      continue;
    words[0] = sequence;
    memcpy(&state, words.data(), sizeof(state));
    return valid(state, abi_);
  }
  return fail(EAGAIN);
}

bool read_packet(int fd, yz_bootstrap_packet_header &header) {
  if (fd < 0)
    return fail(EPROTONOSUPPORT);
  ssize_t count;
  do {
    count = pread(fd, &header, sizeof(header), 0);
  } while (count < 0 && errno == EINTR);
  if (count != sizeof(header) || header.magic != YZ_BOOTSTRAP_PACKET_MAGIC ||
      header.version != YZ_BOOTSTRAP_PACKET_VERSION ||
      header.header_size != sizeof(header) ||
      header.entry_size != sizeof(yz_early_native_packet_entry) ||
      header.count > YZ_NATIVE_TARGET_MAX || header.endpoint_fd < 0 ||
      header.reserved)
    return fail(EPROTO);
  return true;
}

bool initialize(int packet_fd, bool consume_endpoint) {
  yz_bootstrap_packet_header header{};
  if (!read_packet(packet_fd, header))
    return false;
  const bool ok = runtime.map(header.endpoint_fd, kAbi);
  const int error = errno;
  if (consume_endpoint)
    close(header.endpoint_fd);
  errno = error;
  return ok;
}

void release() { runtime.reset(); }

void close_packet(int packet_fd, bool close_endpoint) {
  if (packet_fd < 0)
    return;
  yz_bootstrap_packet_header header{};
  if (read_packet(packet_fd, header)) {
    if (close_endpoint)
      close(header.endpoint_fd);
    for (uint32_t i = 0; i < header.count; ++i) {
      yz_early_native_packet_entry entry{};
      const auto offset =
          static_cast<off_t>(sizeof(header)) +
          (static_cast<off_t>(i) * static_cast<off_t>(sizeof(entry)));
      ssize_t count;
      do {
        count = pread(packet_fd, &entry, sizeof(entry), offset);
      } while (count < 0 && errno == EINTR);
      if (count == sizeof(entry) && entry.fd >= 0)
        close(entry.fd);
    }
  }
  close(packet_fd);
}

socklen_t address(const yz_endpoint_state &state, sockaddr_un &out) {
  out = {};
  out.sun_family = AF_UNIX;
  memcpy(out.sun_path + 1, state.name, sizeof(state.name));
  return offsetof(sockaddr_un, sun_path) + 1 + sizeof(state.name);
}

int start(const Mapping &mapping, yz_endpoint_state &state, Deadline deadline) {
  if (!mapping.read(state))
    return -1;
  if (!state.available) {
    errno = ENOENT;
    return -1;
  }
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (fd < 0)
    return -1;
  sockaddr_un target{};
  const auto length = address(state, target);
  const bool can_wait = Clock::now() < deadline;
  if (::connect(fd, reinterpret_cast<sockaddr *>(&target), length) != 0 &&
      errno != EINPROGRESS) {
    // AF_UNIX reports a full accept queue as EAGAIN, without a pending connect.
    if (errno == EAGAIN && can_wait &&
        wait_connect(fd, reinterpret_cast<sockaddr *>(&target), length,
                     deadline))
      return fd;
    const int error = errno;
    close(fd);
    errno = error;
    return -1;
  }
  return fd;
}

bool validate(int fd, const Mapping &mapping, const yz_endpoint_state &state) {
  int error = 0;
  socklen_t length = sizeof(error);
  if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) != 0)
    return false;
  if (error)
    return fail(error);
  struct ucred peer{};
  length = sizeof(peer);
  if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &length) != 0)
    return false;
  if (length != sizeof(peer) || peer.uid != 0 ||
      peer.pid != static_cast<pid_t>(state.pid))
    return fail(EACCES);
  yz_endpoint_state latest{};
  if (!mapping.read(latest))
    return false;
  if (!latest.available || latest.generation != state.generation ||
      latest.pid != state.pid ||
      latest.start_boottime != state.start_boottime ||
      memcmp(latest.name, state.name, sizeof(state.name)) != 0)
    return fail(ESTALE);
  return true;
}

bool rediscoverable(int error) {
  return error == ESTALE || error == ECONNREFUSED || error == ENOENT;
}

int connect(const Mapping &mapping, Deadline deadline, bool nonblocking) {
  for (unsigned attempt = 0; attempt < 2; ++attempt) {
    yz_endpoint_state state{};
    const int fd = start(mapping, state, deadline);
    if (fd < 0) {
      if (rediscoverable(errno))
        continue;
      return -1;
    }
    int result;
    do {
      const auto remaining =
          std::chrono::duration_cast<std::chrono::milliseconds>(deadline -
                                                                Clock::now())
              .count();
      pollfd descriptor{fd, POLLOUT, 0};
      result = poll(&descriptor, 1,
                    static_cast<int>(std::max<int64_t>(0, remaining)));
    } while (result < 0 && errno == EINTR && Clock::now() < deadline);
    if (result > 0 && validate(fd, mapping, state)) {
      if (nonblocking || fcntl(fd, F_SETFL, 0) == 0)
        return fd;
    } else if (result == 0) {
      errno = ETIMEDOUT;
    }
    const int error = errno;
    close(fd);
    errno = error;
    if (!rediscoverable(error) || Clock::now() >= deadline)
      return -1;
  }
  return -1;
}

int connect(Deadline deadline, bool nonblocking) {
  return connect(runtime, deadline, nonblocking);
}

int listen(Random random) {
  for (unsigned attempt = 0; attempt < 8; ++attempt) {
    std::array<unsigned char, 16> bytes{};
    size_t offset = 0;
    while (offset < bytes.size()) {
      const auto count =
          random(bytes.data() + offset, bytes.size() - offset, 0);
      if (count < 0 && errno == EINTR)
        continue;
      if (count <= 0 || static_cast<size_t>(count) > bytes.size() - offset) {
        if (count >= 0)
          errno = EIO;
        return -1;
      }
      offset += static_cast<size_t>(count);
    }
    yz_endpoint_state state{};
    constexpr char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < bytes.size(); ++i) {
      state.name[i * 2] = digits[bytes[i] >> 4];
      state.name[(i * 2) + 1] = digits[bytes[i] & 15];
    }
    const int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
      return -1;
    sockaddr_un target{};
    const auto length = address(state, target);
    if (bind(fd, reinterpret_cast<sockaddr *>(&target), length) == 0) {
      if (::listen(fd, 32) == 0)
        return fd;
      const int error = errno;
      close(fd);
      errno = error;
      return -1;
    }
    const int error = errno;
    close(fd);
    errno = error;
    if (error != EADDRINUSE)
      return -1;
  }
  return -1;
}
} // namespace yukizygisk::endpoint
