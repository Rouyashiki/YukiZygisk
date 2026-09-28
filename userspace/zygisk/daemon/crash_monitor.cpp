/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Crash backtrace diagnostics.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */
#include "crash_monitor.hpp"

#include <ctime>
#include <dirent.h>
#include <sys/inotify.h>

#include <array>
#include <charconv>
#include <cstring>
#include <utility>

namespace yukizygisk::crash {
namespace {
constexpr uint64_t kRetryNs = 5ULL * 1000000000;
constexpr size_t kMaxTombstone = size_t{4} * 1024 * 1024;

uint64_t now_ns() {
  timespec now{};
  if (clock_gettime(CLOCK_BOOTTIME, &now) != 0)
    return 0;
  return (static_cast<uint64_t>(now.tv_sec) * 1000000000) +
         static_cast<uint64_t>(now.tv_nsec);
}

bool tombstone_name(std::string_view name) {
  constexpr std::string_view prefix = "tombstone_";
  return name.size() > prefix.size() && name.size() < 64 &&
         name.substr(0, prefix.size()) == prefix &&
         std::all_of(
             name.begin() + prefix.size(), name.end(),
             [](char ch) { return ch >= '0' && ch <= '9'; });
}

std::string stamp_identity(const struct stat &status) {
  return std::to_string(status.st_dev) + ":" + std::to_string(status.st_ino) +
         ":" + std::to_string(status.st_size) + ":" +
         std::to_string(status.st_mtim.tv_sec) + ":" +
         std::to_string(status.st_mtim.tv_nsec);
}

bool write_all(int fd, const std::string &text) {
  size_t offset = 0;
  while (offset < text.size()) {
    const ssize_t count = write(fd, text.data() + offset, text.size() - offset);
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0)
      return false;
    offset += static_cast<size_t>(count);
  }
  return true;
}
} // namespace

Monitor::~Monitor() {
  if (notify_ >= 0)
    close(notify_);
}

void Monitor::log(const std::string &message) const {
  if (logger_ != nullptr)
    logger_(message.c_str());
}

bool Monitor::Stamp::operator==(const Stamp &other) const {
  return device == other.device && inode == other.inode && size == other.size &&
         seconds == other.seconds && nanos == other.nanos;
}

void Monitor::set_modules(std::vector<Module> modules) {
  for (auto &module : modules)
    module.identity = image_identity(module.path);
  modules_ = std::move(modules);
}

void Monitor::start(std::string directory, uint8_t abi) {
  directory_ = std::move(directory);
  abi_ = abi;
  boot_ = boot_id();
  protection_.start(directory_, abi_);
  const auto saved = read_evidence(directory_);
  for (const auto &item : saved.as_array()) {
    if (item.at("abi_id").u32_or(0) == abi_ &&
        evidence_.a.size() < kMaxEvidence)
      evidence_.push_back(item);
  }
  watch();
}

void Monitor::watch() {
  retry_ns_ = now_ns() + kRetryNs;
  if (notify_ < 0)
    notify_ = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
  if (notify_ < 0)
    return;
  watch_ = inotify_add_watch(notify_, tombstones_.c_str(),
                             IN_CLOSE_WRITE | IN_MOVED_TO | IN_DELETE_SELF |
                                 IN_MOVE_SELF | IN_ONLYDIR | IN_DONT_FOLLOW);
  if (watch_ < 0)
    return;
  log("watch armed abi=" + std::to_string(abi_));
  // Establish the baseline after arming the watch; existing files are not new
  // evidence.
  stamps_.clear();
  candidates_.clear();
  scan();
}

void Monitor::scan() {
  DIR *directory = opendir(tombstones_.c_str());
  if (directory == nullptr)
    return;
  size_t count = 0;
  while (dirent *entry = readdir(directory)) {
    if (!tombstone_name(entry->d_name))
      continue;
    if (++count > 128)
      break;
    struct stat status{};
    const std::string path = tombstones_ + "/" + entry->d_name;
    if (lstat(path.c_str(), &status) == 0 && S_ISREG(status.st_mode))
      stamps_[entry->d_name] = {status.st_dev, status.st_ino, status.st_size,
                                status.st_mtim.tv_sec, status.st_mtim.tv_nsec};
  }
  closedir(directory);
}

void Monitor::consume_closed(const std::string &name) {
  if (tombstone_name(name)) {
    consume(name);
    return;
  }
  // O_TMPFILE keeps its #inode event name after tombstoned publishes via
  // linkat.
  if (name.size() < 2 || name.front() != '#')
    return;
  uint64_t inode = 0;
  const auto parsed =
      std::from_chars(name.data() + 1, name.data() + name.size(), inode);
  if (parsed.ec != std::errc{} || parsed.ptr != name.data() + name.size() ||
      inode == 0)
    return;
  DIR *directory = opendir(tombstones_.c_str());
  if (directory == nullptr)
    return;
  size_t count = 0;
  while (dirent *entry = readdir(directory)) {
    if (!tombstone_name(entry->d_name))
      continue;
    if (++count > 128)
      break;
    struct stat status{};
    const std::string path = tombstones_ + "/" + entry->d_name;
    if (lstat(path.c_str(), &status) == 0 && S_ISREG(status.st_mode) &&
        status.st_ino == inode)
      consume(entry->d_name, inode);
  }
  closedir(directory);
}

void Monitor::consume(const std::string &name, uint64_t inode) {
  if (!tombstone_name(name))
    return;
  const std::string path = tombstones_ + "/" + name;
  struct stat status{};
  if (lstat(path.c_str(), &status) != 0 || !S_ISREG(status.st_mode) ||
      status.st_size <= 0 || (inode != 0 && status.st_ino != inode) ||
      static_cast<uint64_t>(status.st_size) > kMaxTombstone)
    return;
  const Stamp stamp{status.st_dev, status.st_ino, status.st_size,
                    status.st_mtim.tv_sec, status.st_mtim.tv_nsec};
  const auto found = stamps_.find(name);
  if (found != stamps_.end() && found->second == stamp)
    return;
  if (!recent_mtime(time(nullptr), stamp.seconds)) {
    log("tombstone rejected: mtime " + name);
    return;
  }
  std::string text;
  if (!read_bounded(path, kMaxTombstone, &text, FileSource::Tombstone)) {
    log("tombstone rejected: read/identity " + name);
    return;
  }
  struct stat after{};
  if (lstat(path.c_str(), &after) != 0 ||
      stamp_identity(after) != stamp_identity(status))
    return;
  if (stamps_.size() < 128 || found != stamps_.end())
    stamps_[name] = stamp;
  Candidate candidate{name, stamp_identity(status), now_ns(),
                      parse_tombstone(text)};
  if (candidate.tombstone.abi == abi_)
    log("tombstone received: " + name +
        " pid=" + std::to_string(candidate.tombstone.pid) +
        " ppid=" + std::to_string(candidate.tombstone.ppid) +
        " module_frames=" + std::to_string(candidate.tombstone.frames.size()));
  if (candidate.tombstone.abi != abi_ || candidate.tombstone.frames.empty())
    return;
  for (const auto &event : exits_)
    correlate(event, candidate);
  if (candidates_.size() == kMaxEvidence)
    candidates_.erase(candidates_.begin());
  candidates_.push_back(std::move(candidate));
}

void Monitor::correlate(const Exit &event, const Candidate &candidate) {
  const auto &tombstone = candidate.tombstone;
  if (!matches(event, tombstone, candidate.completed_ns))
    return;
  for (const auto &frame : tombstone.frames) {
    const auto module =
        std::find_if(modules_.begin(), modules_.end(), [&](const Module &item) {
          return item.id == frame.module && item.path == frame.path;
        });
    if (module == modules_.end() || module->identity.empty() ||
        image_identity(module->path) != module->identity) {
      log("module identity rejected: " + frame.module);
      continue;
    }
    const std::string key = candidate.identity + ":" + candidate.name + ":" +
                            frame.module + ":" +
                            std::to_string(event.generation);
    if (std::any_of(evidence_.a.begin(), evidence_.a.end(),
                    [&](const json::Value &item) {
                      return item.at("key").string_or("") == key;
                    }))
      continue;
    const bool direct_fault =
        tombstone.pid == event.pid && tombstone.signal == (event.status & 0x7f);
    const bool server_fault = tombstone.ppid == event.pid &&
                              tombstone.uid == 1000 &&
                              (tombstone.process == "system_server" ||
                               (tombstone.tid == tombstone.pid &&
                                tombstone.thread_name == "system_server"));
    if (module->zygisk && frame.index == 0 && (direct_fault || server_fault) &&
        protection_.suspend(frame.module)) {
      log("injection suspended for this boot: " + frame.module +
          " tombstone=" + candidate.name +
          (protection_.dirty() ? " (persistence pending)" : ""));
    }
    json::Value item = json::Value::object();
    item["key"] = key;
    item["module"] = frame.module;
    item["image"] = module->path;
    item["image_identity"] = module->identity;
    item["process"] = tombstone.process;
    item["pid"] = static_cast<double>(tombstone.pid);
    item["zygote_pid"] = static_cast<double>(event.pid);
    item["generation"] = static_cast<double>(event.generation);
    item["abi_id"] = static_cast<int>(abi_);
    item["abi"] = abi_ == 2 ? "arm64-v8a" : "armeabi-v7a";
    item["timestamp"] = tombstone.timestamp;
    item["observed_at"] = static_cast<double>(time(nullptr));
    item["tombstone"] = candidate.name;
    item["frame"] = frame.text;
    if (evidence_.a.size() == kMaxEvidence)
      evidence_.a.erase(evidence_.a.begin());
    evidence_.push_back(item);
    dirty_ = true;
    log("evidence associated: " + frame.module +
        " tombstone=" + candidate.name);
  }
}

void Monitor::on_exit(const yz_zygote_exit_event &event) {
  const uint64_t now = now_ns();
  if (event.event.type != YZ_EV_ZYGOTE_EXIT || event.abi != abi_ ||
      event.event.pid == 0 || event.generation == 0 ||
      event.start_boottime == 0 ||
      event.observed_boottime < event.start_boottime ||
      now < event.observed_boottime ||
      now - event.observed_boottime > kWindowNs ||
      (event.event.appid & 0x7f) == 0 || (event.event.appid & 0x7f) == 15) {
    if (event.abi == abi_)
      log("exit rejected: pid=" + std::to_string(event.event.pid) +
          " status=" + std::to_string(event.event.appid));
    return;
  }
  log("exit accepted: pid=" + std::to_string(event.event.pid) +
      " generation=" + std::to_string(event.generation) +
      " status=" + std::to_string(event.event.appid));
  tick();
  // The dump can finish before the kernel exit notification reaches userspace.
  drain();
  const Exit exit{event.event.pid,      event.generation,
                  event.event.appid,    event.abi,
                  event.start_boottime, event.observed_boottime};
  if (std::any_of(exits_.begin(), exits_.end(), [&](const Exit &old) {
        return old.pid == exit.pid && old.generation == exit.generation &&
               old.start_ns == exit.start_ns;
      }))
    return;
  for (const auto &candidate : candidates_)
    correlate(exit, candidate);
  if (exits_.size() == 16)
    exits_.erase(exits_.begin());
  exits_.push_back(exit);
  save();
}

void Monitor::drain() {
  if (notify_ < 0)
    return;
  alignas(inotify_event) std::array<char, 8192> buffer{};
  for (unsigned batch = 0; batch < 8; ++batch) {
    const ssize_t size = read(notify_, buffer.data(), buffer.size());
    if (size < 0 && errno == EINTR)
      continue;
    if (size <= 0)
      break;
    size_t offset = 0;
    while (offset + sizeof(inotify_event) <= static_cast<size_t>(size)) {
      const auto *event =
          reinterpret_cast<const inotify_event *>(buffer.data() + offset);
      const size_t remaining =
          static_cast<size_t>(size) - offset - sizeof(*event);
      if (event->len > remaining)
        break;
      if ((event->mask & IN_Q_OVERFLOW) != 0) {
        candidates_.clear();
        exits_.clear();
        scan();
      } else if (event->wd == watch_) {
        if ((event->mask & (IN_IGNORED | IN_MOVE_SELF | IN_DELETE_SELF)) != 0) {
          close(notify_);
          notify_ = -1;
          watch_ = -1;
          exits_.clear();
          candidates_.clear();
          retry_ns_ = now_ns() + kRetryNs;
        } else if ((event->mask & (IN_CLOSE_WRITE | IN_MOVED_TO)) != 0 &&
                   event->len > 0) {
          const size_t length = strnlen(event->name, event->len);
          if (length < event->len) {
            const std::string name(event->name, length);
            if ((event->mask & IN_CLOSE_WRITE) != 0)
              consume_closed(name);
            else
              consume(name);
          }
        }
      }
      offset += sizeof(*event) + event->len;
    }
  }
  save();
}

void Monitor::tick() {
  if (directory_.empty())
    return;
  protection_.tick();
  const uint64_t now = now_ns();
  if (watch_ < 0 && now >= retry_ns_)
    watch();
  exits_.erase(std::remove_if(exits_.begin(), exits_.end(),
                              [&](const Exit &event) {
                                return now < event.observed_ns ||
                                       now - event.observed_ns > kWindowNs;
                              }),
               exits_.end());
  candidates_.erase(std::remove_if(candidates_.begin(), candidates_.end(),
                                   [&](const Candidate &candidate) {
                                     return now < candidate.completed_ns ||
                                            now - candidate.completed_ns >
                                                kWindowNs;
                                   }),
                    candidates_.end());
  if (dirty_ && now >= retry_ns_) {
    retry_ns_ = now + kRetryNs;
    save();
  }
}

int Monitor::timeout_ms() const {
  return watch_ < 0 || dirty_ || protection_.dirty() || !exits_.empty() ||
                 !candidates_.empty()
             ? 5000
             : -1;
}

void Monitor::save() {
  if (!dirty_)
    return;
  if (!current_boot(directory_, boot_)) {
    log("save deferred: boot identity mismatch");
    return;
  }
  json::Value root = json::Value::object();
  root["boot_id"] = boot_;
  root["evidence"] = evidence_;
  const std::string text = json::dump(root);
  if (text.size() > kMaxDocument)
    return;
  const int directory =
      open(directory_.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (directory < 0)
    return;
  const char *name = abi_ == 2 ? "crash64.json" : "crash32.json";
  const std::string temporary =
      std::string(name) + ".tmp." + std::to_string(getpid());
  const int fd = openat(
      directory, temporary.c_str(),
      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600);
  if (fd >= 0) {
    struct stat status{};
    bool ok = fstat(fd, &status) == 0 && S_ISREG(status.st_mode) &&
              status.st_uid == 0 && write_all(fd, text) && fsync(fd) == 0;
    close(fd);
    if (ok)
      ok = renameat(directory, temporary.c_str(), directory, name) == 0;
    if (ok) {
      (void)fsync(directory);
      dirty_ = false;
      log("evidence saved: records=" + std::to_string(evidence_.a.size()));
    } else {
      (void)unlinkat(directory, temporary.c_str(), 0);
    }
  }
  close(directory);
}

} // namespace yukizygisk::crash
