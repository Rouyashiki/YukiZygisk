/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Crash backtrace diagnostics.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */
#pragma once

#include "../crash_evidence.hpp"
#include "../crash_protection.hpp"
#include "uapi/yukizygisk.h"

#include <map>

namespace yukizygisk::crash {

struct Module {
  std::string id;
  std::string path;
  std::string identity;
  bool zygisk = false;
};

class Monitor {
public:
  using Logger = void (*)(const char *);
  explicit Monitor(std::string tombstones = "/data/tombstones",
                   Logger logger = nullptr)
      : tombstones_(std::move(tombstones)), logger_(logger) {}
  ~Monitor();
  Monitor(const Monitor &) = delete;
  Monitor &operator=(const Monitor &) = delete;
  Monitor(Monitor &&) = delete;
  Monitor &operator=(Monitor &&) = delete;
  void set_modules(std::vector<Module> modules);
  void start(std::string directory, uint8_t abi);
  void on_exit(const yz_zygote_exit_event &event);
  void drain();
  void tick();
  void set_protection_enabled(bool enabled) {
    protection_.set_enabled(enabled);
  }
  bool suspended(const std::string &id) { return protection_.blocked(id); }
  [[nodiscard]] int fd() const { return notify_; }
  [[nodiscard]] int timeout_ms() const;

private:
  struct Stamp {
    uint64_t device = 0;
    uint64_t inode = 0;
    int64_t size = 0;
    int64_t seconds = 0;
    int64_t nanos = 0;
    bool operator==(const Stamp &other) const;
  };
  struct Candidate {
    std::string name;
    std::string identity;
    uint64_t completed_ns = 0;
    Tombstone tombstone;
  };
  void watch();
  void scan();
  void consume(const std::string &name, uint64_t inode = 0);
  void consume_closed(const std::string &name);
  void log(const std::string &message) const;
  void correlate(const Exit &event, const Candidate &candidate);
  void save();
  std::string directory_;
  std::string tombstones_;
  Logger logger_ = nullptr;
  std::string boot_;
  uint8_t abi_ = 0;
  int notify_ = -1;
  int watch_ = -1;
  uint64_t retry_ns_ = 0;
  std::map<std::string, Stamp> stamps_;
  std::vector<Module> modules_;
  std::vector<Exit> exits_;
  std::vector<Candidate> candidates_;
  json::Value evidence_ = json::Value::array();
  bool dirty_ = false;
  Protection protection_;
};

} // namespace yukizygisk::crash
