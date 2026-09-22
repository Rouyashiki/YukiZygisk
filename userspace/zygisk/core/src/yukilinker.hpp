/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - in-memory ELF loader public interface.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <link.h>

namespace yukilinker {

struct SoHandle {
  // Kept public for the bootstrap handoff and the standalone diagnostic.
  uint8_t *load_bias = nullptr;
  size_t map_size = 0;

  // All loader bookkeeping is private to yukilinker.cpp.
  void *private_state = nullptr;
};

// Load an ET_DYN AArch64 image from an already-open descriptor.
SoHandle *dlopen_memfd(int memfd, const char *vma_name,
                       bool file_backed = false);

// Find a defined dynamic symbol in a loaded image.
void *dlsym(SoHandle *h, const char *name);

// Run finalizers and release the image mapping.
void dlclose(SoHandle *h);

// Return whether a loaded image still depends on this loader's TLS resolver.
bool has_active_tls();

// Disable process-wide services before the containing DSO is unmapped.
bool shutdown();

} // namespace yukilinker
