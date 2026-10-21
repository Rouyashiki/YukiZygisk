#pragma once

#include "kernel/uapi/yukizygisk.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/un.h>

namespace yukizygisk::endpoint {

inline constexpr uint32_t kAbi =
    sizeof(void *) == 8 ? YZ_RUNTIME_ABI_64 : YZ_RUNTIME_ABI_32;
using Clock = std::chrono::steady_clock;
using Deadline = Clock::time_point;
using Provider = int (*)(uint32_t abi, void *context);
using Random = ssize_t (*)(void *, size_t, unsigned);

static_assert(sizeof(yz_endpoint_state) == 80);
static_assert(offsetof(yz_endpoint_state, generation) == 32);
static_assert(sizeof(yz_bootstrap_packet_header) == 24);

class Mapping {
public:
  constexpr Mapping() = default;
  Mapping(const Mapping &) = delete;
  Mapping &operator=(const Mapping &) = delete;
  Mapping(Mapping &&) = delete;
  Mapping &operator=(Mapping &&) = delete;
  ~Mapping() { reset(); }
  bool map(int fd, uint32_t abi);
  void reset();
  bool read(yz_endpoint_state &state) const;

private:
  const yz_endpoint_state *page_ = nullptr;
  size_t length_ = 0;
  uint32_t abi_ = 0;
};

bool read_packet(int fd, yz_bootstrap_packet_header &header);
bool initialize(int packet_fd, bool consume_endpoint);
void release();
void close_packet(int packet_fd, bool close_endpoint = true);

socklen_t address(const yz_endpoint_state &state, sockaddr_un &out);
int start(const Mapping &mapping, yz_endpoint_state &state,
          Deadline deadline = Clock::now());
bool validate(int fd, const Mapping &mapping, const yz_endpoint_state &state);
bool rediscoverable(int error);
int connect(const Mapping &mapping, Deadline deadline,
            bool nonblocking = false);
int connect(Deadline deadline = Clock::now() + std::chrono::seconds(2),
            bool nonblocking = false);
int listen(Random random = getrandom);

} // namespace yukizygisk::endpoint
