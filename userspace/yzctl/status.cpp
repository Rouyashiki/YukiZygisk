/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Kernel-backed status snapshot for yzctl.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */

#include "status.hpp"
#include "userspace/zygisk/crash_evidence.hpp"
#include "userspace/zygisk/crash_protection.hpp"
#include "userspace/zygisk/settings.hpp"

#include "host.hpp"
#include "native_modules.hpp"

#include "json.hpp"
#include "uapi/yukizygisk.h"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <elf.h>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <string>
#include <tuple>
#include <unistd.h>
#include <utility>
#include <vector>

namespace yzctl {
namespace {

using NativeModule = yukizygisk::native::NativeModule;

struct RuntimeSnapshot {
  uint32_t capabilities = 0;
  uint32_t generation = 0;
  bool safe_mode = false;
  uint32_t zygote_crashes = 0;
  std::string safe_mode_zygote;
  std::vector<yz_runtime_record> records;
};

struct NativeDefinition {
  NativeModule module;
  uint8_t abi = YZ_RUNTIME_ABI_UNKNOWN;
};

struct NativeInjection {
  uint32_t pid = 0;
  std::string process;
  std::string module_id;
  uint8_t target_type = 0;
  std::string target;
  uint8_t abi = YZ_RUNTIME_ABI_UNKNOWN;
  std::string state;
  bool has_companion = false;
};

struct NativeModuleView {
  std::string module_id;
  uint8_t target_type = 0;
  std::string target;
  bool has_companion = false;
  std::string state = "failed";
};

template <size_t Size> std::string bounded_string(const char (&value)[Size]) {
  return std::string(value, strnlen(value, Size));
}

const char *abi_name(uint8_t abi) {
  switch (abi) {
  case YZ_RUNTIME_ABI_32:
    return "armeabi-v7a";
  case YZ_RUNTIME_ABI_64:
    return "arm64-v8a";
  default:
    return "unknown";
  }
}

const char *runtime_state_name(uint8_t state) {
  switch (state) {
  case YZ_RUNTIME_STATE_INJECTED:
    return "injected";
  case YZ_RUNTIME_STATE_SAFEMODE:
    return "crashed";
  case YZ_RUNTIME_STATE_EXITED:
    return nullptr;
  case YZ_RUNTIME_STATE_DETECTED:
  case YZ_RUNTIME_STATE_REDIRECTED:
  case YZ_RUNTIME_STATE_FAILED:
  default:
    return "failed";
  }
}

const char *target_type_name(uint8_t type) {
  return type == YZ_NATIVE_TARGET_PATH ? "path" : "name";
}

void append_escaped(std::string *output, const std::string &value) {
  for (char character : value) {
    switch (character) {
    case '"':
      *output += "\\\"";
      break;
    case '\\':
      *output += "\\\\";
      break;
    case '\b':
      *output += "\\b";
      break;
    case '\f':
      *output += "\\f";
      break;
    case '\n':
      *output += "\\n";
      break;
    case '\r':
      *output += "\\r";
      break;
    case '\t':
      *output += "\\t";
      break;
    default:
      if (static_cast<unsigned char>(character) < 0x20) {
        char escaped[8];
        snprintf(escaped, sizeof(escaped), "\\u%04x",
                 static_cast<unsigned char>(character));
        *output += escaped;
      } else {
        *output += character;
      }
      break;
    }
  }
}

void append_json_string(std::string *output, const std::string &value) {
  *output += '"';
  append_escaped(output, value);
  *output += '"';
}

bool query_runtime(Host &host, RuntimeSnapshot *snapshot, std::string *error) {
  snapshot->records.assign(YZ_RUNTIME_RECORD_MAX, {});
  yz_runtime_query_cmd command{};
  command.capacity = static_cast<uint32_t>(snapshot->records.size());
  command.entries = static_cast<__aligned_u64>(
      reinterpret_cast<uintptr_t>(snapshot->records.data()));
  if (host.call(YZ_IOCTL_GET_RUNTIME, &command) != 0) {
    if (error != nullptr) {
      *error = "cannot query kernel runtime state: ";
      *error += strerror(errno);
    }
    snapshot->records.clear();
    return false;
  }

  snapshot->records.resize(
      std::min<size_t>(command.count, snapshot->records.size()));
  snapshot->generation = command.generation;
  snapshot->safe_mode = command.safe_mode != 0;
  snapshot->capabilities = command.capabilities;
  snapshot->zygote_crashes = command.zygote_crashes;
  snapshot->safe_mode_zygote = bounded_string(command.safe_mode_zygote);
  return true;
}

yz_config read_config(const std::string &path) {
  yz_config config{1, 0, 0, 0};
  std::ifstream stream(path);
  if (!stream.is_open())
    return config;

  std::ostringstream contents;
  contents << stream.rdbuf();
  try {
    const json::Value root = json::parse(contents.str());
    if (root.type != json::Type::Object)
      return config;
    const json::Value &yukilinker = root.at("yukilinker");
    if (yukilinker.type == json::Type::Bool)
      config.yukilinker = yukilinker.as_bool() ? 1 : 0;
    const json::Value &anonymous = root.at("anonymous_memory");
    if (anonymous.type == json::Type::Bool)
      config.memory_type =
          anonymous.as_bool() ? YZ_MEMORY_ANONYMOUS : YZ_MEMORY_FILE;
    const json::Value &denylist_mode = root.at("denylist_mode");
    if (denylist_mode.type == json::Type::Number) {
      const double mode = denylist_mode.as_number();
      if (mode == 0 || mode == 1 || mode == 2)
        config.denylist_mode = static_cast<__u8>(mode);
    }
    const json::Value &dmesg_log = root.at("dmesg_log");
    if (dmesg_log.type == json::Type::Bool)
      config.dmesg_log = dmesg_log.as_bool() ? 1 : 0;
  } catch (...) {
    return yz_config{1, 0, 0, 0};
  }
  return config;
}

std::vector<std::string> scan_zygisk_modules(const std::string &modules_dir) {
  std::vector<std::string> modules;
  DIR *directory = opendir(modules_dir.c_str());
  if (directory == nullptr)
    return modules;

  while (dirent *entry = readdir(directory)) {
    if (entry->d_name[0] == '.')
      continue;
    const std::string base = modules_dir + "/" + entry->d_name;
    if (access((base + "/disable").c_str(), F_OK) == 0 ||
        access((base + "/remove").c_str(), F_OK) == 0)
      continue;
    const std::string zygisk = base + "/zygisk/";
    if (access((zygisk + "arm64-v8a.so").c_str(), F_OK) != 0 &&
        access((zygisk + "armeabi-v7a.so").c_str(), F_OK) != 0)
      continue;
    modules.emplace_back(entry->d_name);
  }
  closedir(directory);
  std::sort(modules.begin(), modules.end());
  modules.erase(std::unique(modules.begin(), modules.end()), modules.end());
  return modules;
}

uint8_t native_module_abi(const std::string &path) {
  unsigned char identity[EI_NIDENT]{};
  const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return YZ_RUNTIME_ABI_UNKNOWN;
  const ssize_t bytes = read(fd, identity, sizeof(identity));
  close(fd);
  if (bytes != static_cast<ssize_t>(sizeof(identity)) ||
      memcmp(identity, ELFMAG, SELFMAG) != 0 ||
      identity[EI_DATA] != ELFDATA2LSB)
    return YZ_RUNTIME_ABI_UNKNOWN;
  if (identity[EI_CLASS] == ELFCLASS32)
    return YZ_RUNTIME_ABI_32;
  if (identity[EI_CLASS] == ELFCLASS64)
    return YZ_RUNTIME_ABI_64;
  return YZ_RUNTIME_ABI_UNKNOWN;
}

bool same_native_definition(const NativeDefinition &left,
                            const NativeDefinition &right) {
  return left.module.module_id == right.module.module_id &&
         left.module.target_type == right.module.target_type &&
         left.module.target == right.module.target && left.abi == right.abi;
}

std::vector<NativeDefinition>
scan_native_modules(const std::string &modules_dir) {
  std::vector<NativeDefinition> modules;
  DIR *directory = opendir(modules_dir.c_str());
  if (directory == nullptr)
    return modules;

  while (dirent *entry = readdir(directory)) {
    if (entry->d_name[0] == '.')
      continue;
    const std::string module_id = entry->d_name;
    const std::string base = modules_dir + "/" + module_id;
    if (access((base + "/disable").c_str(), F_OK) == 0 ||
        access((base + "/remove").c_str(), F_OK) == 0)
      continue;
    std::ifstream manifest(base + "/zn_modules.txt");
    if (!manifest.is_open())
      continue;

    std::string line;
    while (std::getline(manifest, line)) {
      NativeModule module;
      if (!yukizygisk::native::parse_native_module_line(module_id, base, line,
                                                        &module))
        continue;
      const uint8_t abi = native_module_abi(module.lib_path);
      if (abi == YZ_RUNTIME_ABI_UNKNOWN)
        continue;
      NativeDefinition definition{std::move(module), abi};
      const auto duplicate =
          std::find_if(modules.begin(), modules.end(), [&](const auto &item) {
            return same_native_definition(item, definition);
          });
      if (duplicate == modules.end()) {
        modules.push_back(std::move(definition));
      } else {
        duplicate->module.has_companion =
            duplicate->module.has_companion || definition.module.has_companion;
      }
    }
  }
  closedir(directory);
  std::sort(modules.begin(), modules.end(),
            [](const auto &left, const auto &right) {
              return std::tie(left.module.module_id, left.module.target_type,
                              left.module.target, left.abi) <
                     std::tie(right.module.module_id, right.module.target_type,
                              right.module.target, right.abi);
            });
  return modules;
}

const yz_runtime_record *find_ready_record(const RuntimeSnapshot &snapshot,
                                           const yz_runtime_record &base,
                                           const std::string &module_id) {
  for (const auto &record : snapshot.records) {
    if (record.kind == YZ_RUNTIME_KIND_NATIVE && record.pid == base.pid &&
        record.generation == base.generation && record.abi == base.abi &&
        bounded_string(record.module_id) == module_id &&
        record.state != YZ_RUNTIME_STATE_EXITED)
      return &record;
  }
  return nullptr;
}

std::vector<NativeInjection>
build_native_injections(const RuntimeSnapshot &snapshot,
                        const std::vector<NativeDefinition> &modules) {
  std::vector<NativeInjection> injections;
  for (const auto &base : snapshot.records) {
    if (base.kind != YZ_RUNTIME_KIND_NATIVE ||
        base.state == YZ_RUNTIME_STATE_EXITED || base.module_id[0] != '\0')
      continue;
    const std::string target = bounded_string(base.target);
    for (const auto &definition : modules) {
      const NativeModule &module = definition.module;
      if (definition.abi != base.abi ||
          module.target_type != base.target_type || module.target != target)
        continue;
      const yz_runtime_record *ready =
          find_ready_record(snapshot, base, module.module_id);
      const char *state = ready != nullptr ? runtime_state_name(ready->state)
                          : base.state == YZ_RUNTIME_STATE_SAFEMODE ? "crashed"
                                                                    : "failed";
      if (state == nullptr)
        continue;
      injections.push_back(NativeInjection{
          base.pid, bounded_string(base.process), module.module_id,
          base.target_type, target, base.abi, state, module.has_companion});
    }
  }
  std::sort(injections.begin(), injections.end(),
            [](const auto &left, const auto &right) {
              return std::tie(left.pid, left.module_id, left.target_type,
                              left.target, left.abi) <
                     std::tie(right.pid, right.module_id, right.target_type,
                              right.target, right.abi);
            });
  return injections;
}

std::string aggregate_state(const std::string &module_id, uint8_t target_type,
                            const std::string &target,
                            const std::vector<NativeInjection> &injections) {
  bool injected = false;
  bool failed = false;
  for (const auto &injection : injections) {
    if (injection.module_id != module_id ||
        injection.target_type != target_type || injection.target != target)
      continue;
    if (injection.state == "crashed")
      return "crashed";
    if (injection.state == "failed")
      failed = true;
    else if (injection.state == "injected")
      injected = true;
  }
  if (failed)
    return "failed";
  return injected ? "injected" : "failed";
}

std::vector<NativeModuleView>
build_native_module_views(const std::vector<NativeDefinition> &definitions,
                          const std::vector<NativeInjection> &injections) {
  std::vector<NativeModuleView> modules;
  for (const auto &definition : definitions) {
    const NativeModule &source = definition.module;
    auto existing =
        std::find_if(modules.begin(), modules.end(), [&](const auto &module) {
          return module.module_id == source.module_id &&
                 module.target_type == source.target_type &&
                 module.target == source.target;
        });
    if (existing == modules.end()) {
      modules.push_back(
          NativeModuleView{source.module_id, source.target_type, source.target,
                           source.has_companion,
                           aggregate_state(source.module_id, source.target_type,
                                           source.target, injections)});
    } else {
      existing->has_companion = existing->has_companion || source.has_companion;
    }
  }
  return modules;
}

std::string root_impl_name(const yz_root_status_cmd &status) {
  if (status.owner == YZ_ROOT_OWNER_UAPI_KERNELSU) {
    return (status.flags & YZ_ROOT_STATUS_KSU_REDIRECT) != 0
               ? "kernelsu-redirect"
               : "kernelsu";
  }
  if (status.owner == YZ_ROOT_OWNER_UAPI_KERNELPATCH)
    return "kernelpatch";
  return "unsupported";
}

std::string root_policy_name(const yz_root_status_cmd &status) {
  if ((status.flags & YZ_ROOT_STATUS_POLICY_KERNEL) != 0)
    return "kernel";
  if ((status.flags & YZ_ROOT_STATUS_POLICY_FALLBACK) == 0)
    return "unavailable";
  if (status.owner == YZ_ROOT_OWNER_UAPI_KERNELSU)
    return "userspace-ksu-api";
  if (status.owner == YZ_ROOT_OWNER_UAPI_KERNELPATCH)
    return "userspace-apatch-config";
  return "unavailable";
}

std::string snapshot_abi(const RuntimeSnapshot &snapshot) {
  bool abi32 = false;
  bool abi64 = false;
  for (const auto &record : snapshot.records) {
    if (record.state == YZ_RUNTIME_STATE_EXITED)
      continue;
    abi32 = abi32 || record.abi == YZ_RUNTIME_ABI_32;
    abi64 = abi64 || record.abi == YZ_RUNTIME_ABI_64;
  }
  if (abi32 && abi64)
    return "arm64-v8a + armeabi-v7a";
  if (abi32)
    return "armeabi-v7a";
  return "arm64-v8a";
}

size_t injected_base_count(const RuntimeSnapshot &snapshot) {
  std::vector<std::tuple<uint32_t, uint32_t, uint8_t, uint8_t>> injected;
  for (const auto &record : snapshot.records) {
    if (record.state != YZ_RUNTIME_STATE_INJECTED ||
        record.module_id[0] != '\0')
      continue;
    const auto key =
        std::make_tuple(record.pid, record.generation, record.kind, record.abi);
    if (std::find(injected.begin(), injected.end(), key) == injected.end())
      injected.push_back(key);
  }
  return injected.size();
}

void append_zygotes(std::string *json, const RuntimeSnapshot &snapshot,
                    bool monitor) {
  bool first = true;
  for (const auto &record : snapshot.records) {
    if (record.kind != YZ_RUNTIME_KIND_ZYGOTE || record.module_id[0] != '\0')
      continue;
    const char *state = runtime_state_name(record.state);
    if (state == nullptr ||
        (!monitor && record.state != YZ_RUNTIME_STATE_INJECTED))
      continue;
    if (!first)
      *json += ',';
    first = false;
    const std::string target = bounded_string(record.target);
    *json += "{\"pid\":" + std::to_string(record.pid) + ",\"name\":";
    append_json_string(json, target);
    *json += ",\"generation\":" + std::to_string(record.generation);
    *json += ",\"target\":";
    append_json_string(json, target);
    *json += ",\"abi\":";
    append_json_string(json, abi_name(record.abi));
    if (monitor) {
      *json += ",\"state\":";
      append_json_string(json, state);
    }
    *json += '}';
  }
}

} // namespace

bool query_status(Host &host, const StatusOptions &options,
                  StatusDocument *document, std::string *error) {
  if (document == nullptr) {
    if (error != nullptr)
      *error = "status output is null";
    errno = EINVAL;
    return false;
  }

  RuntimeSnapshot runtime;
  if (!query_runtime(host, &runtime, error))
    return false;
  yz_root_status_cmd root_status{};
  if (host.call(YZ_IOCTL_GET_ROOT_STATUS, &root_status) != 0) {
    if (error != nullptr) {
      *error = "cannot query kernel root status: ";
      *error += strerror(errno);
    }
    return false;
  }

  const yz_config config = read_config(options.config_path);
  const std::vector<std::string> zygisk_modules =
      scan_zygisk_modules(options.modules_dir);
  const std::vector<NativeDefinition> native_definitions =
      scan_native_modules(options.modules_dir);
  const std::vector<NativeInjection> native_injections =
      build_native_injections(runtime, native_definitions);
  const std::vector<NativeModuleView> native_modules =
      build_native_module_views(native_definitions, native_injections);

  document->abi = snapshot_abi(runtime);
  document->root_impl = root_impl_name(root_status);
  document->safe_mode = runtime.safe_mode;
  document->injected = injected_base_count(runtime);
  document->zygotes = static_cast<size_t>(std::count_if(
      runtime.records.begin(), runtime.records.end(), [](const auto &record) {
        return record.kind == YZ_RUNTIME_KIND_ZYGOTE &&
               record.module_id[0] == '\0' &&
               record.state != YZ_RUNTIME_STATE_EXITED;
      }));
  document->zygisk_modules = zygisk_modules.size();
  document->native_modules = native_modules.size();

  std::string output = "{\"kernel_alive\":true,\"abi\":";
  append_json_string(&output, document->abi);
  output += ",\"generation\":" + std::to_string(runtime.generation);
  output += ",\"root_impl\":";
  append_json_string(&output, document->root_impl);
  output += ",\"root_mask\":" + std::to_string(root_status.mask);
  output += ",\"ksu_redirect\":";
  output +=
      (root_status.flags & YZ_ROOT_STATUS_KSU_REDIRECT) != 0 ? "true" : "false";
  output += ",\"root_policy_source\":";
  append_json_string(&output, root_policy_name(root_status));
  output += ",\"root_policy_cache_ready\":";
  output += (root_status.flags & YZ_ROOT_STATUS_POLICY_CACHE_READY) != 0
                ? "true"
                : "false";
  output += ",\"count\":" + std::to_string(document->injected);
  output += ",\"safe_mode\":";
  output += runtime.safe_mode ? "true" : "false";
  output += ",\"zygisk_module_monitor\":";
  output += (runtime.capabilities & YZ_RUNTIME_CAP_ZYGOTE_MODULE_REPORT) != 0
                ? "true"
                : "false";
  output += ",\"zygote_crashes\":" + std::to_string(runtime.zygote_crashes);
  output += ",\"safe_mode_zygote\":";
  append_json_string(&output, runtime.safe_mode_zygote.empty()
                                  ? "zygote"
                                  : runtime.safe_mode_zygote);
  output += ",\"yukilinker\":";
  output += config.yukilinker != 0 ? "true" : "false";
  output += ",\"anonymous_memory\":";
  output += config.memory_type != YZ_MEMORY_FILE ? "true" : "false";
  output += ",\"denylist_mode\":" + std::to_string(config.denylist_mode);
  output += ",\"dmesg_log\":";
  output += config.dmesg_log != 0 ? "true" : "false";
  output += ",\"runtime\":[";
  bool first_record = true;
  for (const auto &record : runtime.records) {
    if (!first_record)
      output += ',';
    first_record = false;
    output += "{\"pid\":" + std::to_string(record.pid);
    output += ",\"generation\":" + std::to_string(record.generation);
    output += ",\"kind\":";
    append_json_string(
        &output, record.kind == YZ_RUNTIME_KIND_ZYGOTE ? "zygote" : "native");
    output += ",\"abi\":";
    append_json_string(&output, abi_name(record.abi));
    output += ",\"module\":";
    append_json_string(&output, bounded_string(record.module_id));
    output += ",\"state\":";
    const char *state = runtime_state_name(record.state);
    append_json_string(&output, state ? state : "exited");
    output += '}';
  }
  output += "],\"recent\":[],\"zygotes\":[";
  append_zygotes(&output, runtime, false);
  output += "],\"zygote_monitor\":[";
  append_zygotes(&output, runtime, true);
  output += "],\"modules\":[";
  for (size_t index = 0; index < zygisk_modules.size(); ++index) {
    if (index != 0)
      output += ',';
    append_json_string(&output, zygisk_modules[index]);
  }
  output += "],\"native_modules\":[";
  for (size_t index = 0; index < native_modules.size(); ++index) {
    if (index != 0)
      output += ',';
    const NativeModuleView &module = native_modules[index];
    output += "{\"id\":";
    append_json_string(&output, module.module_id);
    output += ",\"target_type\":";
    append_json_string(&output, target_type_name(module.target_type));
    output += ",\"target\":";
    append_json_string(&output, module.target);
    output += ",\"companion\":";
    output += module.has_companion ? "true" : "false";
    output += ",\"state\":";
    append_json_string(&output, module.state);
    output += '}';
  }
  output += "],\"native_injections\":[";
  for (size_t index = 0; index < native_injections.size(); ++index) {
    if (index != 0)
      output += ',';
    const NativeInjection &injection = native_injections[index];
    output += "{\"pid\":" + std::to_string(injection.pid) + ",\"process\":";
    append_json_string(&output, injection.process);
    output += ",\"module\":";
    append_json_string(&output, injection.module_id);
    output += ",\"target_type\":";
    append_json_string(&output, target_type_name(injection.target_type));
    output += ",\"target\":";
    append_json_string(&output, injection.target);
    output += ",\"abi\":";
    append_json_string(&output, abi_name(injection.abi));
    output += ",\"companion\":";
    output += injection.has_companion ? "true" : "false";
    output += ",\"state\":";
    append_json_string(&output, injection.state);
    output += '}';
  }
  output += "],\"crash_evidence\":" +
            json::dump(yukizygisk::crash::read_evidence(
                "/data/adb/yukizygisk/diagnostics/current"));
  const bool protection =
      yukizygisk::settings::protection_enabled(options.config_path);
  output += ",\"crash_protection\":";
  output += protection ? "true" : "false";
  output += ",\"suspended_modules\":";
  output +=
      json::dump(protection ? yukizygisk::crash::suspended_modules(
                                  "/data/adb/yukizygisk/diagnostics/current")
                            : json::Value::array());
  output += '}';
  document->json = std::move(output);
  return true;
}

} // namespace yzctl
