/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Portable host package verification with the production parser.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */
#include "vendor/monocypher-ed25519.h"
#include "viola.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static FILE *package_file(const char *directory, const char *relative) {
  char path[4096];
  int count = snprintf(path, sizeof(path), "%s/%s", directory, relative);
  return count < 0 || (size_t)count >= sizeof(path) ? NULL : fopen(path, "rb");
}

static int read_bounded(const char *directory, const char *relative,
                        void *buffer, size_t capacity, size_t *length) {
  FILE *file = package_file(directory, relative);
  if (!file)
    return 1;
  *length = fread(buffer, 1, capacity, file);
  int failed = ferror(file) || fgetc(file) != EOF || ferror(file);
  if (fclose(file))
    failed = 1;
  return failed;
}

int main(int argc, char **argv) {
  if (argc != 4 || strcmp(argv[1], "verify") ||
      strcmp(argv[2], "--module-dir")) {
    fputs("usage: viola-host verify --module-dir DIRECTORY\n", stderr);
    return 2;
  }
  uint8_t manifest[VIOLA_MANIFEST_MAX], signature[VIOLA_SIGNATURE_MAX];
  size_t manifest_size, signature_size;
  struct viola_manifest_view view;
  if (read_bounded(argv[3], "viola.manifest", manifest, sizeof(manifest),
                   &manifest_size) ||
      read_bounded(argv[3], "viola.sig", signature, sizeof(signature),
                   &signature_size))
    return 1;
  int result = viola_manifest_verify(manifest, manifest_size, signature,
                                     signature_size, &view);
  if (result) {
    fprintf(stderr, "viola-host: %s\n", viola_result_string(result));
    return 1;
  }
  for (unsigned i = 0; i < view.entry_count; ++i) {
    struct viola_entry entry;
    char relative[128];
    uint8_t buffer[16384], digest[64];
    uint64_t count = 0;
    crypto_sha512_ctx hash;
    if (viola_entry_at(&view, i, &entry) ||
        viola_entry_path(&entry, relative, sizeof(relative)))
      return 1;
    FILE *file = package_file(argv[3], relative);
    if (!file)
      return 1;
    crypto_sha512_init(&hash);
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), file))) {
      if (count > entry.size || bytes > entry.size - count) {
        fclose(file);
        return 1;
      }
      count += bytes;
      crypto_sha512_update(&hash, buffer, bytes);
    }
    int failed = ferror(file);
    if (fclose(file))
      failed = 1;
    crypto_sha512_final(&hash, digest);
    if (failed || count != entry.size ||
        crypto_verify64(digest, entry.sha512)) {
      fprintf(stderr, "viola-host: payload rejected: %s\n", relative);
      return 1;
    }
  }
  puts("viola-host: core signature, identity and payloads verified");
  return 0;
}
