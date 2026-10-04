/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Reusable standalone kernel control client.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */
#pragma once

#include "kernel/uapi/viola.h"

#include <string>

namespace yzctl {

class Host final {
public:
  Host() = default;
  ~Host();

  Host(const Host &) = delete;
  Host &operator=(const Host &) = delete;

  bool open(std::string *error);
  int call(unsigned long request, void *arg) const;
  bool query_viola(yz_viola_status *status, bool *supported,
                   std::string *error) const;
  bool available() const;
  int native_handle() const { return fd_; }

private:
  int fd_ = -1;
};

} // namespace yzctl
