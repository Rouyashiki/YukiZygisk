/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Standalone control command line client.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */

#include "host.hpp"
#include "status.hpp"
#include "userspace/zygisk/settings.hpp"

#include "uapi/yukizygisk.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>

namespace {

void usage(FILE *stream) {
  fprintf(stream,
          "Usage:\n"
          "  yzctl status [--json] [--modules-dir DIR] [--config FILE]\n"
          "  yzctl reload\n"
          "  yzctl config get\n"
          "  yzctl config set KEY VALUE [KEY VALUE ...]\n");
}

bool option_value(int argc, char **argv, int *index, const char *name,
                  std::string *value) {
  const char *argument = argv[*index];
  const size_t name_length = strlen(name);
  if (strcmp(argument, name) == 0) {
    if (*index + 1 >= argc)
      return false;
    *value = argv[++(*index)];
    return true;
  }
  if (strncmp(argument, name, name_length) == 0 &&
      argument[name_length] == '=') {
    *value = argument + name_length + 1;
    return true;
  }
  return false;
}

int status_command(int argc, char **argv) {
  yzctl::StatusOptions options;
  bool json = false;
  for (int i = 2; i < argc; ++i) {
    std::string value;
    if (strcmp(argv[i], "--json") == 0) {
      json = true;
    } else if (option_value(argc, argv, &i, "--modules-dir", &value)) {
      if (value.empty()) {
        fprintf(stderr, "yzctl: --modules-dir cannot be empty\n");
        return 2;
      }
      options.modules_dir = std::move(value);
    } else if (option_value(argc, argv, &i, "--config", &value)) {
      if (value.empty()) {
        fprintf(stderr, "yzctl: --config cannot be empty\n");
        return 2;
      }
      options.config_path = std::move(value);
    } else {
      fprintf(stderr, "yzctl: unknown status option: %s\n", argv[i]);
      return 2;
    }
  }

  yzctl::Host host;
  std::string error;
  if (!host.open(&error)) {
    fprintf(stderr, "yzctl: %s\n", error.c_str());
    return 1;
  }

  yzctl::StatusDocument status;
  if (!yzctl::query_status(host, options, &status, &error)) {
    fprintf(stderr, "yzctl: %s\n", error.c_str());
    return 1;
  }

  if (json) {
    puts(status.json.c_str());
  } else {
    printf("YukiZygisk status\n"
           "  Kernel control: available\n"
           "  ABI: %s\n"
           "  Root implementation: %s\n"
           "  Safe mode: %s\n"
           "  Injected records: %zu\n"
           "  Zygotes: %zu\n"
           "  Zygisk modules: %zu\n"
           "  Native modules: %zu\n",
           status.abi.c_str(), status.root_impl.c_str(),
           status.safe_mode ? "active" : "inactive", status.injected,
           status.zygotes, status.zygisk_modules, status.native_modules);
  }
  return 0;
}

int reload_command(int argc) {
  if (argc != 2) {
    fprintf(stderr, "yzctl: reload takes no options\n");
    return 2;
  }

  yzctl::Host host;
  std::string error;
  if (!host.open(&error)) {
    fprintf(stderr, "yzctl: %s\n", error.c_str());
    return 1;
  }
  if (host.call(YZ_IOCTL_RELOAD, nullptr) != 0) {
    fprintf(stderr, "yzctl: kernel reload failed: %s\n", strerror(errno));
    return 1;
  }
  puts("YukiZygisk reload signalled");
  return 0;
}

int config_command(int argc, char **argv) {
  constexpr char path[] = "/data/adb/yukizygisk/yzconfig.json";
  if (argc == 3 && strcmp(argv[2], "get") == 0) {
    json::Value root;
    if (!yukizygisk::settings::read(path, &root)) {
      fprintf(stderr, "yzctl: configuration read failed: %s\n",
              strerror(errno));
      return 1;
    }
    puts(json::dump(root).c_str());
    return 0;
  }
  if (argc < 5 || strcmp(argv[2], "set") != 0 || argc % 2 != 1) {
    fprintf(
        stderr,
        "yzctl: expected config get or config set KEY VALUE [KEY VALUE ...]\n");
    return 2;
  }
  const std::vector<std::string> pairs(argv + 3, argv + argc);
  if (!yukizygisk::settings::update(path, pairs)) {
    fprintf(stderr, "yzctl: configuration save failed: %s\n", strerror(errno));
    return 1;
  }
  return reload_command(2);
}

} // namespace

int main(int argc, char **argv) {
  if (argc < 2) {
    usage(stderr);
    return 2;
  }
  if (strcmp(argv[1], "status") == 0)
    return status_command(argc, argv);
  if (strcmp(argv[1], "reload") == 0)
    return reload_command(argc);
  if (strcmp(argv[1], "config") == 0)
    return config_command(argc, argv);
  if (strcmp(argv[1], "help") == 0 || strcmp(argv[1], "--help") == 0 ||
      strcmp(argv[1], "-h") == 0) {
    usage(stdout);
    return 0;
  }
  fprintf(stderr, "yzctl: unknown command: %s\n", argv[1]);
  usage(stderr);
  return 2;
}
