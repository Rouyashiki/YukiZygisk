/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Kernel-backed status snapshot for yzctl.
 *
 * License: Apache-2.0
 *
 * Author: Rouyashiki Developers
 */
#pragma once

#include <cstddef>
#include <string>

namespace yzctl {

class Host;

struct StatusOptions {
  std::string modules_dir = "/data/adb/modules";
  std::string config_path = "/data/adb/yukizygisk/yzconfig.json";
};

struct StatusDocument {
  std::string json;
  std::string abi;
  std::string root_impl;
  bool safe_mode = false;
  bool late_load = false;
  bool late_load_pending = false;
  size_t injected = 0;
  size_t zygotes = 0;
  size_t zygisk_modules = 0;
  size_t native_modules = 0;
};

bool query_status(Host &host, const StatusOptions &options,
                  StatusDocument *document, std::string *error);

} // namespace yzctl
