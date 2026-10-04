/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Self-contained core verifier and authenticated launcher.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */
#define _GNU_SOURCE
#include "kernel/uapi/viola.h"
#include "kernel/uapi/viola_health.h"
#include "kernel/uapi/yukizygisk.h"
#include "module_loader.h"
#include "recovery.h"
#include "vendor/monocypher-ed25519.h"
#include "viola.h"
#include "viola_build.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

#define VIOLA_BOOT_TIMEOUT_MS 30000
#define VIOLA_ENSURE_TIMEOUT_MS 15000
#define VIOLA_ENSURE_START_TIMEOUT_MS 5000
#define VIOLA_BASE "/data/adb/yukizygisk"

struct package {
  int dirfd;
  char directory[PATH_MAX];
  unsigned char manifest[8192];
  unsigned char signature[4096];
  size_t manifest_size;
  size_t signature_size;
  struct viola_manifest_view catalog;
};

static int64_t monotonic_ms(void);

static int failure(const char *stage, int error) {
  fprintf(stderr, "viola: %s: %s (%d)\n", stage,
          error > 0 ? viola_result_string(error) : strerror(-error), error);
  return error ? error : -EIO;
}

/* Resolve every directory component without following symlinks. */
static int open_directory(const char *path, int create) {
  char copy[PATH_MAX];
  char *part, *save = NULL;
  int fd;
  if (!path || path[0] != '/' || strlen(path) >= sizeof(copy))
    return -EINVAL;
  memcpy(copy, path, strlen(path) + 1);
  fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0)
    return -errno;
  for (part = strtok_r(copy, "/", &save); part;
       part = strtok_r(NULL, "/", &save)) {
    int next;
    if (!strcmp(part, ".") || !strcmp(part, "..")) {
      close(fd);
      return -EINVAL;
    }
    if (create && mkdirat(fd, part, 0755) && errno != EEXIST) {
      int error = errno;
      close(fd);
      return -error;
    }
    next = openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    close(fd);
    if (next < 0)
      return -errno;
    fd = next;
  }
  return fd;
}

static int open_relative(int directory, const char *relative) {
  char path[256], *part, *save = NULL;
  int fd;
  if (!relative || relative[0] == '/' || strlen(relative) >= sizeof(path))
    return -EINVAL;
  strcpy(path, relative);
  fd = fcntl(directory, F_DUPFD_CLOEXEC, 3);
  if (fd < 0)
    return -errno;
  part = strtok_r(path, "/", &save);
  while (part) {
    char *next_part = strtok_r(NULL, "/", &save);
    int next;
    if (!strcmp(part, ".") || !strcmp(part, "..")) {
      close(fd);
      return -EINVAL;
    }
    next = openat(fd, part,
                  O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK |
                      (next_part ? O_DIRECTORY : 0));
    close(fd);
    if (next < 0)
      return -errno;
    fd = next;
    part = next_part;
  }
  struct stat st;
  int result = fstat(fd, &st) ? -errno : !S_ISREG(st.st_mode) ? -EINVAL : 0;
  if (result) {
    close(fd);
    return result;
  }
  return fd;
}

static int read_exact(int fd, void *data, size_t length) {
  unsigned char *cursor = data;
  size_t done = 0;
  while (done < length) {
    ssize_t count = pread(fd, cursor + done, length - done, (off_t)done);
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0)
      return count < 0 ? -errno : -EIO;
    done += (size_t)count;
  }
  unsigned char extra;
  ssize_t count;
  do {
    count = pread(fd, &extra, 1, (off_t)length);
  } while (count < 0 && errno == EINTR);
  return count == 0 ? 0 : count < 0 ? -errno : -EFBIG;
}

static int read_small(int dir, const char *name, void *data, size_t cap,
                      size_t *size) {
  struct stat st;
  int fd = open_relative(dir, name);
  if (fd < 0)
    return fd;
  int result = fstat(fd, &st) ? -errno : 0;
  if (!result &&
      (!S_ISREG(st.st_mode) || st.st_size <= 0 || (uint64_t)st.st_size > cap))
    result = -EFBIG;
  if (!result) {
    *size = (size_t)st.st_size;
    result = read_exact(fd, data, *size);
  }
  close(fd);
  return result;
}

static int load_package(struct package *package, const char *directory) {
  int result;
  if (strlen(directory) >= sizeof(package->directory))
    return -ENAMETOOLONG;
  strcpy(package->directory, directory);
  package->dirfd = open_directory(directory, 0);
  if (package->dirfd < 0)
    return package->dirfd;
  result = read_small(package->dirfd, "viola.manifest", package->manifest,
                      sizeof(package->manifest), &package->manifest_size);
  if (!result)
    result = read_small(package->dirfd, "viola.sig", package->signature,
                        sizeof(package->signature), &package->signature_size);
  if (!result)
    result = viola_manifest_verify(package->manifest, package->manifest_size,
                                   package->signature, package->signature_size,
                                   &package->catalog);
  return result;
}

static int hash_fd_before(int fd, const struct viola_entry *entry,
                          int64_t deadline) {
  unsigned char chunk[16384], digest[64];
  crypto_sha512_ctx hash;
  struct stat st;
  uint64_t offset = 0;
  if (fstat(fd, &st))
    return -errno;
  if (!S_ISREG(st.st_mode) || st.st_size < 0 ||
      (uint64_t)st.st_size != entry->size)
    return -EBADMSG;
  crypto_sha512_init(&hash);
  while (offset < entry->size) {
    if (deadline >= 0) {
      int64_t now = monotonic_ms();
      if (now < 0 || now >= deadline)
        return now < 0 ? -EIO : -ETIMEDOUT;
    }
    size_t amount = entry->size - offset > sizeof(chunk)
                        ? sizeof(chunk)
                        : (size_t)(entry->size - offset);
    ssize_t count = pread(fd, chunk, amount, (off_t)offset);
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0)
      return count < 0 ? -errno : -EIO;
    crypto_sha512_update(&hash, chunk, (size_t)count);
    offset += (size_t)count;
  }
  crypto_sha512_final(&hash, digest);
  if (fstat(fd, &st) || (uint64_t)st.st_size != entry->size)
    return -EBADMSG;
  return crypto_verify64(digest, entry->sha512) ? -EBADMSG : 0;
}

static int hash_fd(int fd, const struct viola_entry *entry) {
  return hash_fd_before(fd, entry, -1);
}

static int open_entry(struct package *package,
                      const struct viola_entry *entry) {
  char path[128];
  int result = viola_entry_path(entry, path, sizeof(path));
  return result ? -EINVAL : open_relative(package->dirfd, path);
}

static int verify_core_directories(struct package *package) {
  static const char *const folders[] = {"bin", "lkm", "lib", "lib64"};
  for (unsigned folder = 0; folder < sizeof(folders) / sizeof(folders[0]);
       ++folder) {
    int fd = openat(package->dirfd, folders[folder],
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
      return -errno;
    DIR *directory = fdopendir(fd);
    if (!directory) {
      int error = errno;
      close(fd);
      return -error;
    }
    int result = 0;
    for (;;) {
      errno = 0;
      struct dirent *item = readdir(directory);
      if (!item) {
        if (errno)
          result = -errno;
        break;
      }
      if (!strcmp(item->d_name, ".") || !strcmp(item->d_name, ".."))
        continue;
      char relative[256];
      int length = snprintf(relative, sizeof(relative), "%s/%s",
                            folders[folder], item->d_name);
      if (length < 0 || (size_t)length >= sizeof(relative)) {
        result = -ENAMETOOLONG;
        break;
      }
      struct stat st;
      if (fstatat(fd, item->d_name, &st, AT_SYMLINK_NOFOLLOW)) {
        result = -errno;
        break;
      }
      /* Package extraction keeps a SHA-256 sidecar beside every file.  It is
       * accepted only when the corresponding path is already in the signed
       * catalog; no unrelated file is admitted into a core directory. */
      size_t relative_size = strlen(relative);
      int sidecar = relative_size > 7 &&
                    !strcmp(relative + relative_size - 7, ".sha256");
      char catalog_relative[256];
      if (sidecar) {
        memcpy(catalog_relative, relative, relative_size - 7);
        catalog_relative[relative_size - 7] = '\0';
      } else {
        memcpy(catalog_relative, relative, relative_size + 1);
      }
      if (!strcmp(relative, "bin/zygiskd") && S_ISLNK(st.st_mode)) {
        char target[64];
        ssize_t n = readlinkat(fd, item->d_name, target, sizeof(target) - 1);
        if (n < 0 || (size_t)n >= sizeof(target) - 1) {
          result = -EINVAL;
          break;
        }
        target[n] = '\0';
        if (!strcmp(target, "zygiskd64") || !strcmp(target, "./zygiskd64"))
          continue;
        result = -EINVAL;
        break;
      }
      int covered = 0;
      for (unsigned i = 0; i < package->catalog.entry_count; ++i) {
        struct viola_entry entry;
        char expected[128];
        if (!viola_entry_at(&package->catalog, i, &entry) &&
            !viola_entry_path(&entry, expected, sizeof(expected)) &&
            !strcmp(catalog_relative, expected)) {
          covered = 1;
          break;
        }
      }
      if (!covered || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "viola: unexpected core entry: %s\n", relative);
        result = -EINVAL;
        break;
      }
    }
    closedir(directory);
    if (result)
      return result;
  }
  return 0;
}

static int verify_package_before(struct package *package, uint32_t selected_kmi,
                                 int64_t deadline) {
  int directory_result = verify_core_directories(package);
  if (directory_result)
    return directory_result;
  if (selected_kmi) {
    struct viola_entry kernel;
    int result = viola_manifest_find(&package->catalog, VIOLA_ROLE_KO,
                                     VIOLA_ABI_ARM64, selected_kmi, &kernel);
    if (result)
      return result;
  }
  for (unsigned i = 0; i < package->catalog.entry_count; ++i) {
    struct viola_entry entry;
    int result = viola_entry_at(&package->catalog, i, &entry);
    if (result)
      return result;
    if (selected_kmi && entry.role == VIOLA_ROLE_KO &&
        entry.kmi != selected_kmi)
      continue;
    int fd = open_entry(package, &entry);
    if (fd < 0)
      return fd;
    result = hash_fd_before(fd, &entry, deadline);
    close(fd);
    if (result) {
      fprintf(stderr, "viola: payload role=%u abi=%u kmi=%u rejected\n",
              entry.role, entry.abi, entry.kmi);
      return result;
    }
  }
  return 0;
}

static int verify_package(struct package *package, uint32_t selected_kmi) {
  return verify_package_before(package, selected_kmi, -1);
}

/* Admission syscalls must originate in Viola's authenticated executable VMA,
 * rather than in the shared libc syscall trampoline. */
static long admission_syscall(long number, unsigned long a0, unsigned long a1,
                              unsigned long a2) {
#if defined(__aarch64__)
  register unsigned long x0 __asm__("x0") = a0;
  register unsigned long x1 __asm__("x1") = a1;
  register unsigned long x2 __asm__("x2") = a2;
  register unsigned long x3 __asm__("x3") = 0;
  register unsigned long x4 __asm__("x4") = 0;
  register long x8 __asm__("x8") = number;
  __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3),
                   "r"(x4), "r"(x8) : "memory", "cc");
  if ((long)x0 < 0 && (long)x0 >= -4095) {
    errno = -(long)x0;
    return -1;
  }
  return (long)x0;
#else
  return syscall(number, a0, a1, a2, 0UL, 0UL);
#endif
}

static int control_open(unsigned option, unsigned magic) {
  int fd = -ENODEV;
  (void)admission_syscall(SYS_prctl, option, magic, (unsigned long)&fd);
  return fd;
}

static int read_status(int fd, struct yz_viola_status *status) {
  memset(status, 0, sizeof(*status));
  status->size = sizeof(*status);
  status->version = YZ_VIOLA_VERSION;
  if (ioctl(fd, YZ_IOCTL_VIOLA_STATUS, status))
    return -errno;
  const uint8_t release[32] = VIOLA_RELEASE_ID_BYTES;
  const uint8_t trust[32] = VIOLA_TRUST_ID_BYTES;
  if (status->version != YZ_VIOLA_VERSION || status->size != sizeof(*status) ||
      status->profile != VIOLA_PROFILE ||
      memcmp(status->release_id, release, sizeof(release)) ||
      memcmp(status->trust_id, trust, sizeof(trust)))
    return -ESTALE;
  return 0;
}

static int module_present(const char *name) {
  char line[512], module[128];
  FILE *file = fopen("/proc/modules", "re");
  if (!file)
    return -errno;
  int found = 0;
  while (fgets(line, sizeof(line), file)) {
    if (sscanf(line, "%127s", module) == 1 && !strcmp(module, name)) {
      found = 1;
      break;
    }
  }
  if (ferror(file))
    found = -EIO;
  fclose(file);
  return found;
}

static uint32_t detect_kmi(struct package *package) {
  struct utsname uts;
  char name[64];
  unsigned major, minor, android;
  if (uname(&uts))
    return 0;
  const char *part = strstr(uts.release, "android");
  if (sscanf(uts.release, "%u.%u", &major, &minor) == 2 && part &&
      sscanf(part, "android%u", &android) == 1) {
    snprintf(name, sizeof(name), "android%u-%u.%u", android, major, minor);
    int kmi = viola_kmi_id(name);
    return kmi > 0 ? (uint32_t)kmi : 0;
  }

  /* An installer choice is valid only for the same unidentifiable release.
   * Catalog lookup and payload hashing still authenticate the selected KO. */
  char selection[sizeof(uts.release) + sizeof(name)];
  size_t size = 0;
  if (read_small(package->dirfd, "kmi", selection, sizeof(selection) - 1,
                 &size) ||
      memchr(selection, '\0', size) || selection[size - 1] != '\n')
    return 0;
  selection[size - 1] = '\0';
  char *release = strchr(selection, '\n');
  if (!release)
    return 0;
  *release++ = '\0';
  if (strcmp(release, uts.release))
    return 0;
  int kmi = viola_kmi_id(selection);
  return kmi > 0 ? (uint32_t)kmi : 0;
}

static int load_kernel(struct package *package, uint32_t kmi) {
  struct viola_entry entry;
  int result = viola_manifest_find(&package->catalog, VIOLA_ROLE_KO,
                                   VIOLA_ABI_ARM64, kmi, &entry);
  if (result)
    return result;
  int fd = open_entry(package, &entry);
  if (fd < 0)
    return fd;
  void *buffer = mmap(NULL, (size_t)entry.size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (buffer == MAP_FAILED) {
    result = -errno;
    close(fd);
    return result;
  }
  result = read_exact(fd, buffer, (size_t)entry.size);
  close(fd);
  if (!result)
    result = viola_check_payload(&entry, buffer, (size_t)entry.size);
  if (!result && mprotect(buffer, (size_t)entry.size, PROT_READ))
    result = -errno;
  if (!result) {
    int ksu = module_present("kernelsu");
    if (ksu < 0)
      result = ksu;
    else
      result = viola_load_verified_kernel(buffer, (size_t)entry.size,
                                          ksu ? "ksu_module_present=1" :
                                                "ksu_module_present=0",
                                          admission_syscall);
  }
  munmap(buffer, (size_t)entry.size);
  return result;
}

static int write_all(int fd, const void *buffer, size_t length) {
  const uint8_t *data = buffer;
  while (length) {
    ssize_t n = write(fd, data, length);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      return n < 0 ? -errno : -EIO;
    data += n;
    length -= (size_t)n;
  }
  return 0;
}

static int deploy_cores(struct package *package) {
  int directory = open_directory(VIOLA_BASE "/lib", 1);
  if (directory < 0)
    return directory;
  int result = 0;
  for (unsigned abi = VIOLA_ABI_ARM64; abi <= VIOLA_ABI_ARM32; ++abi) {
    for (unsigned role = VIOLA_ROLE_LOADER; role <= VIOLA_ROLE_NATIVE; ++role) {
      struct viola_entry entry;
      char target[64], temporary[96];
      const char *base = role == VIOLA_ROLE_LOADER ? "libyukilinker"
                         : role == VIOLA_ROLE_CORE ? "libzygisk"
                                                   : "libyukizncore";
      result = viola_manifest_find(&package->catalog, role, abi, 0, &entry);
      if (result)
        goto out;
      int source = open_entry(package, &entry);
      if (source < 0) {
        result = source;
        goto out;
      }
      uint8_t *data = malloc((size_t)entry.size);
      if (!data) {
        close(source);
        result = -ENOMEM;
        goto out;
      }
      result = read_exact(source, data, (size_t)entry.size);
      close(source);
      if (!result)
        result = viola_check_payload(&entry, data, (size_t)entry.size);
      snprintf(target, sizeof(target), "%s%u.so", base,
               abi == VIOLA_ABI_ARM64 ? 64 : 32);
      snprintf(temporary, sizeof(temporary), ".%s.viola.%ld", target,
               (long)getpid());
      if (!result) {
        int output =
            openat(directory, temporary,
                   O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (output < 0)
          result = -errno;
        else {
          result = write_all(output, data, (size_t)entry.size);
          if (!result)
            result = hash_fd(output, &entry);
          if (!result && (fchmod(output, 0644) || fsync(output)))
            result = -errno;
          close(output);
          if (!result && renameat(directory, temporary, directory, target))
            result = -errno;
          if (result)
            unlinkat(directory, temporary, 0);
        }
      }
      free(data);
      if (result)
        goto out;
    }
  }
  if (fsync(directory))
    result = -errno;
out:
  close(directory);
  return result;
}

static int close_other_fds(int control, int ready, int image) {
  DIR *directory = opendir("/proc/self/fd");
  if (!directory)
    return -errno;
  int iterator_fd = dirfd(directory);
  struct dirent *entry;
  while ((entry = readdir(directory))) {
    char *end;
    long fd = strtol(entry->d_name, &end, 10);
    if (*end || fd < 3 || fd > INT_MAX || fd == control || fd == ready ||
        fd == image || fd == iterator_fd)
      continue;
    close((int)fd);
  }
  closedir(directory);
  return 0;
}

static int execute_daemon(struct package *package, int control, int ready,
                          unsigned abi) {
  struct viola_entry entry;
  char executable[PATH_MAX], control_env[64], ready_env[64], image_env[64];
  char module_env[PATH_MAX + 32];
  int result =
      viola_manifest_find(&package->catalog, VIOLA_ROLE_DAEMON, abi, 0, &entry);
  if (result)
    return result;
  int fd = open_entry(package, &entry);
  if (fd < 0)
    return fd;
  struct yz_viola_exec_cmd command = {sizeof(command), YZ_VIOLA_VERSION, fd, 0};
  if (ioctl(control, YZ_IOCTL_VIOLA_PIN_EXEC, &command))
    result = -errno;
  if (!result)
    result = hash_fd(fd, &entry);
  if (!result && ioctl(control, YZ_IOCTL_VIOLA_ARM_EXEC, 0))
    result = -errno;
  if (result) {
    close(fd);
    return result;
  }
  int count = snprintf(executable, sizeof(executable), "%s/bin/zygiskd%u",
                       package->directory, abi == VIOLA_ABI_ARM64 ? 64 : 32);
  if (count < 0 || (size_t)count >= sizeof(executable)) {
    close(fd);
    return -ENAMETOOLONG;
  }
  snprintf(module_env, sizeof(module_env), "YUKIZYGISK_MODULE_DIR=%s",
           package->directory);
  snprintf(control_env, sizeof(control_env), "YUKIZYGISK_CONTROL_FD=%d",
           control);
  snprintf(ready_env, sizeof(ready_env), "YUKIZYGISK_READY_FD=%d", ready);
  snprintf(image_env, sizeof(image_env), "YUKIZYGISK_IMAGE_FD=%d", fd);
  char *environment[] = {"PATH=/system/bin:/system/xbin",
                         control_env,
                         ready_env,
                         module_env,
                         "YUKIZYGISK_CONFIG=" VIOLA_BASE "/yzconfig.json",
                         "YUKIZYGISK_LOG_DIR=" VIOLA_BASE "/log",
                         "YUKIZYGISK_MODULES_DIR=/data/adb/modules",
                         abi == VIOLA_ABI_ARM32 ? image_env : NULL,
                         NULL};
  char *arguments[] = {executable, NULL};
  if (fcntl(control, F_SETFD, 0) || (ready >= 0 && fcntl(ready, F_SETFD, 0))) {
    close(fd);
    return -errno;
  }
  result = close_other_fds(control, ready, fd);
  /* binfmt_misc must be able to deliver this image to Tango after exec.
   * The daemon closes our inherited FD after claiming its authorized role;
   * the kernel retains the frozen image for the entire control session. */
  if (!result && abi == VIOLA_ABI_ARM32 && fcntl(fd, F_SETFD, 0))
    result = -errno;
  if (!result) {
    syscall(SYS_execveat, fd, "", arguments, environment, AT_EMPTY_PATH);
    result = -errno;
  }
  close(fd);
  return result;
}

static int launch_worker(struct package *package, int ready, int loaded,
                         uint32_t kmi) {
  int result = 0;
  if (!loaded)
    result = load_kernel(package, kmi);
  if (result)
    return failure("kernel image", result);
  int control = control_open(YZ_PRCTL_VIOLA_OPTION, YZ_PRCTL_VIOLA_MAGIC);
  if (control < 0)
    return failure("launcher claim", control);
  struct yz_viola_status status;
  result = read_status(control, &status);
  if (!result && status.role != YZ_VIOLA_LAUNCHER64)
    result = -EPERM;
  /* Reserve the kernel launcher before changing any deployed core. */
  if (!result)
    result = deploy_cores(package);
  struct yz_viola_catalog_cmd catalog = {
      sizeof(catalog),
      YZ_VIOLA_VERSION,
      (uint64_t)(uintptr_t)package->manifest,
      (uint64_t)(uintptr_t)package->signature,
      (uint32_t)package->manifest_size,
      (uint32_t)package->signature_size};
  if (!result && ioctl(control, YZ_IOCTL_VIOLA_CATALOG, &catalog))
    result = -errno;
  if (!result)
    result = execute_daemon(package, control, ready, VIOLA_ABI_ARM64);
  close(control);
  return failure("launch", result);
}

static int restart_worker(struct package *package, int ready) {
  struct viola_entry entry;
  int result = viola_manifest_find(&package->catalog, VIOLA_ROLE_VIOLA,
                                   VIOLA_ABI_ARM64, 0, &entry);
  if (result)
    return result;
  int fd = open_entry(package, &entry);
  if (fd < 0)
    return fd;
  result = hash_fd(fd, &entry);
  char ready_text[16];
  snprintf(ready_text, sizeof(ready_text), "%d", ready);
  char *arguments[] = {"viola", "launch-worker", "--module-dir",
                        package->directory, "--ready-fd", ready_text, NULL};
  char *environment[] = {"PATH=/system/bin:/system/xbin", NULL};
  if (!result && fcntl(ready, F_SETFD, 0))
    result = -errno;
  if (!result)
    result = close_other_fds(-1, ready, fd);
  if (!result) {
    syscall(SYS_execveat, fd, "", arguments, environment, AT_EMPTY_PATH);
    result = -errno;
  }
  close(fd);
  return result;
}

static int64_t monotonic_ms(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now))
    return -1;
  return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int recover_compat_before(int query,
                                 const struct yz_viola_status *initial,
                                 int64_t deadline) {
  struct yz_viola_recover_cmd command = {
      sizeof(command), YZ_VIOLA_VERSION, initial->epoch, initial->generation, 0, 0};
  int requested = 0;
  for (;;) {
    struct yz_viola_status status;
    int result = read_status(query, &status);
    if (result)
      return result;
    if (status.epoch != initial->epoch || status.generation != initial->generation ||
        status.daemon64 != YZ_VIOLA_READY)
      return -ESTALE;
    if (!status.compat_required ||
        (status.daemon32 == YZ_VIOLA_READY && !status.compat_recovering))
      return 0;
    if (requested && !status.compat_recovering && status.recovery_error)
      return status.recovery_error;
    int64_t now = monotonic_ms();
    if (now < 0 || now >= deadline)
      return -ETIMEDOUT;
    if (status.daemon32 != YZ_VIOLA_STARTING &&
        ioctl(query, YZ_IOCTL_VIOLA_RECOVER_COMPAT, &command))
      return -errno;
    requested = 1;
    /* Retry dropped kernel events; the main daemon takes each request once. */
    (void)poll(NULL, 0, (int)(deadline - now < 100 ? deadline - now : 100));
  }
}

static int recover_compat(int query, const struct yz_viola_status *initial) {
  const int64_t start = monotonic_ms();
  return start < 0 ? -EIO
                   : recover_compat_before(query, initial,
                                           start + VIOLA_BOOT_TIMEOUT_MS);
}

static int launch(struct package *package, int64_t deadline) {
  struct yz_viola_status status;
  int query = control_open(YZ_PRCTL_CONTROL_OPTION, YZ_PRCTL_CONTROL_MAGIC);
  int loaded = module_present("yukizygisk");
  int result = 0;
  if (loaded < 0) {
    if (query >= 0)
      close(query);
    return loaded;
  }
  if (query >= 0) {
    result = read_status(query, &status);
    if (result) {
      close(query);
      return result;
    }
    if (status.daemon64 == YZ_VIOLA_READY) {
      uint32_t active_kmi = detect_kmi(package);
      result = active_kmi ? verify_package_before(package, active_kmi, deadline)
                          : -ENOTSUP;
      if (!result)
        result = deadline < 0 ? recover_compat(query, &status)
                              : recover_compat_before(query, &status, deadline);
      close(query);
      return result;
    }
    close(query);
    if (status.daemon64 == YZ_VIOLA_STARTING)
      return -EBUSY;
    loaded = 1;
  } else if (loaded) {
    return -EPROTONOSUPPORT;
  }
  uint32_t kmi = detect_kmi(package);
  if (!kmi)
    return -ENOTSUP;
  result = verify_package_before(package, kmi, deadline);
  if (result)
    return result;
  if (deadline >= 0) {
    int64_t now = monotonic_ms();
    if (now < 0 || now >= deadline)
      return now < 0 ? -EIO : -ETIMEDOUT;
  }
  int pipefd[2];
  struct sigaction child_action;
  memset(&child_action, 0, sizeof(child_action));
  child_action.sa_handler = SIG_DFL;
  sigemptyset(&child_action.sa_mask);
  /* Keep an exited worker waitable, so its PID cannot be reused before cleanup.
   */
  if (sigaction(SIGCHLD, &child_action, NULL))
    return -errno;
  if (pipe2(pipefd, O_CLOEXEC))
    return -errno;
  pid_t child = fork();
  if (child < 0) {
    result = -errno;
    close(pipefd[0]);
    close(pipefd[1]);
    return result;
  }
  if (!child) {
    close(pipefd[0]);
    if (setsid() < 0)
      _exit(1);
    (void)prctl(PR_SET_DUMPABLE, 0);
    /* With an existing KO, make this worker's launcher exec observable by
     * its tracepoint before claiming control. The first loader is checked
     * directly while init_module is executing. */
    result = loaded ? restart_worker(package, pipefd[1]) :
                      launch_worker(package, pipefd[1], 0, kmi);
    ssize_t notified = write(pipefd[1], "0", 1);
    (void)notified;
    _exit(result ? 1 : 0);
  }
  close(pipefd[1]);
  const int64_t start = monotonic_ms();
  if (deadline < 0)
    deadline = start + VIOLA_BOOT_TIMEOUT_MS;
  result = -ETIMEDOUT;
  while (start >= 0) {
    int64_t now = monotonic_ms();
    if (now < 0 || now >= deadline)
      break;
    struct pollfd pollfd = {pipefd[0], POLLIN, 0};
    int polled = poll(&pollfd, 1, (int)(deadline - now));
    if (polled < 0 && errno == EINTR)
      continue;
    if (polled <= 0)
      break;
    char ready = 0;
    if (read(pipefd[0], &ready, 1) != 1 || ready != '1') {
      result = ready == 'R' ? -EUCLEAN : -EIO;
      break;
    }
    query = control_open(YZ_PRCTL_CONTROL_OPTION, YZ_PRCTL_CONTROL_MAGIC);
    result = query < 0 ? query : read_status(query, &status);
    if (query >= 0)
      close(query);
    if (!result && (status.daemon64 != YZ_VIOLA_READY ||
                    status.owner_pid != (uint32_t)child))
      result = -EAGAIN;
    break;
  }
  close(pipefd[0]);
  if (result) {
    /* Only terminate our own child; never a zygote or an injection target. */
    (void)kill(child, SIGKILL);
    while (waitpid(child, NULL, WNOHANG) < 0 && errno == EINTR) {
    }
  }
  return result;
}

static int daemon_missing(int query, unsigned abi) {
  struct yz_viola_daemon_identity_cmd identity;
  memset(&identity, 0, sizeof(identity));
  identity.size = sizeof(identity);
  identity.version = YZ_VIOLA_DAEMON_IDENTITY_VERSION;
  identity.abi = abi;
  if (ioctl(query, YZ_IOCTL_VIOLA_DAEMON_IDENTITY, &identity))
    return -errno;
  if (identity.size != sizeof(identity) ||
      identity.version != YZ_VIOLA_DAEMON_IDENTITY_VERSION ||
      identity.abi != abi || identity.reserved ||
      identity.state > YZ_VIOLA_LOST)
    return -EPROTO;
  if (identity.state == YZ_VIOLA_READY || identity.state == YZ_VIOLA_STARTING)
    return -EBUSY;
  /* A revoked authorization does not prove the old process has exited. */
  if (identity.owner_alive) {
    fprintf(stderr, "viola: daemon%u owner is still alive; requires reboot\n",
            abi == 1 ? 32 : 64);
    return -EUCLEAN;
  }
  int lifetime = viola_daemon_lock(abi);
  if (lifetime < 0)
    return lifetime;
  close(lifetime);
  return 0;
}

static int health_result(const struct viola_health *health, unsigned abi) {
  if (health->state != VIOLA_HEALTH_AVAILABLE) {
    static const char *const states[] = {"available",      "missing",
                                         "unresponsive",   "unsupported",
                                         "identity_error", "error"};
    const unsigned state = (unsigned)health->state;
    fprintf(stderr, "viola: daemon%u %s\n", abi == 1 ? 32 : 64,
            state < sizeof(states) / sizeof(states[0]) ? states[state]
                                                       : "error");
    return -EAGAIN;
  }
  if (health->reboot_required) {
    fprintf(stderr, "viola: daemon%u requires reboot\n", abi == 1 ? 32 : 64);
    return -EUCLEAN;
  }
  if (!health->ready || health->catalog_error)
    return health->catalog_error > 0 ? -health->catalog_error : -EAGAIN;
  printf("daemon%u ready (pid=%u)\n", abi == 1 ? 32 : 64, health->pid);
  return 0;
}

static int health_timeout(int64_t deadline) {
  int64_t now = monotonic_ms();
  if (now < 0 || now >= deadline)
    return 0;
  return deadline - now < 1000 ? (int)(deadline - now) : 1000;
}

static int ensure_allowed(struct package *package, int query) {
  static const char *const markers[] = {"disable", "remove"};
  for (unsigned i = 0; i < sizeof(markers) / sizeof(markers[0]); ++i) {
    struct stat status;
    if (!fstatat(package->dirfd, markers[i], &status, AT_SYMLINK_NOFOLLOW)) {
      fprintf(stderr, "viola: module %s marker blocks recovery\n", markers[i]);
      return -EPERM;
    }
    if (errno != ENOENT)
      return -errno;
  }
  struct yz_safemode_status_cmd safemode;
  memset(&safemode, 0, sizeof(safemode));
  if (ioctl(query, YZ_IOCTL_GET_SAFEMODE, &safemode))
    return -errno;
  if (safemode.active) {
    fputs("viola: kernel safe mode blocks recovery\n", stderr);
    return -EPERM;
  }
  return 0;
}

static int ensure_daemons(struct package *package, unsigned abi) {
  const int64_t start = monotonic_ms();
  if (start < 0)
    return -EIO;
  const int64_t deadline = start + VIOLA_ENSURE_TIMEOUT_MS;
  uint32_t kmi = detect_kmi(package);
  int result = kmi ? verify_package_before(package, kmi, deadline) : -ENOTSUP;
  if (result)
    return result;
  if (!health_timeout(deadline))
    return -ETIMEDOUT;
  int query = control_open(YZ_PRCTL_CONTROL_OPTION, YZ_PRCTL_CONTROL_MAGIC);
  if (query < 0)
    return query;
  struct yz_viola_status initial, status;
  struct viola_health health[2];
  result = read_status(query, &initial);
  if (!result)
    result = ensure_allowed(package, query);
  if (result)
    goto out;
  viola_daemon_health(query, health_timeout(deadline), health);
  if (health[1].state == VIOLA_HEALTH_AVAILABLE) {
    if (initial.daemon64 != YZ_VIOLA_READY ||
        initial.owner_pid != health[1].pid) {
      result = -ESTALE;
      goto out;
    }
    result = health_result(&health[1], 2);
    if (result || abi == 2)
      goto out;
    if (!initial.compat_required) {
      result = abi == 1 ? -ENODEV : 0;
      goto out;
    }
    if (health[0].state == VIOLA_HEALTH_AVAILABLE) {
      result = initial.daemon32 == YZ_VIOLA_READY ? health_result(&health[0], 1)
                                                  : -ESTALE;
      goto out;
    }
    if (health[0].state != VIOLA_HEALTH_MISSING) {
      result = health_result(&health[0], 1);
      goto out;
    }
    result = daemon_missing(query, 1);
    if (!result)
      result = ensure_allowed(package, query);
    if (!result)
      result = recover_compat_before(query, &initial, deadline);
  } else if (health[1].state == VIOLA_HEALTH_MISSING) {
    /* A surviving compat process belongs to the old main generation. It
     * cannot be adopted by a replacement launcher or silently terminated. */
    if (health[0].state != VIOLA_HEALTH_MISSING) {
      fprintf(stderr, "viola: daemon64 missing with surviving or uncertain "
                      "daemon32; requires reboot\n");
      result = -EUCLEAN;
      goto out;
    }
    result = daemon_missing(query, 2);
    if (!result)
      result = daemon_missing(query, 1);
    if (!result)
      result = ensure_allowed(package, query);
    if (!result) {
      int64_t now = monotonic_ms();
      if (now < 0 || now >= deadline)
        result = -ETIMEDOUT;
      else {
        int64_t ready_deadline = now + VIOLA_ENSURE_START_TIMEOUT_MS;
        if (ready_deadline > deadline)
          ready_deadline = deadline;
        puts("viola: starting authenticated daemon64 and required compat "
             "daemon");
        result = launch(package, ready_deadline);
      }
    }
  } else {
    result = health_result(&health[1], 2);
  }
  if (result)
    goto out;
  result = read_status(query, &status);
  if (!result && status.epoch != initial.epoch)
    result = -ESTALE;
  if (result)
    goto out;
  if (!health_timeout(deadline)) {
    result = -ETIMEDOUT;
    goto out;
  }
  viola_daemon_health(query, health_timeout(deadline), health);
  result = status.daemon64 == YZ_VIOLA_READY ? health_result(&health[1], 2)
                                             : -EAGAIN;
  if (!result && abi != 2) {
    if (!status.compat_required)
      result = abi == 1 ? -ENODEV : 0;
    else
      result = status.daemon32 == YZ_VIOLA_READY ? health_result(&health[0], 1)
                                                 : -EAGAIN;
  }
out:
  close(query);
  return result;
}

static int parse_fd(const char *text) {
  char *end;
  errno = 0;
  long value = strtol(text, &end, 10);
  return errno || !*text || *end || value < 3 || value > INT_MAX ? -1
                                                                 : (int)value;
}

int main(int argc, char **argv) {
  /* Supported entry points pass a fresh environment before the linker runs.
   * Refuse direct invocations retaining loader controls as an additional gate. */
  for (char **variable = environ; *variable; ++variable) {
    if (!strncmp(*variable, "LD_", 3)) {
      failure("loader environment", -EPERM);
      return 1;
    }
  }
  const char *directory = NULL;
  int control = -1, ready = -1, abi = -1;
  if (argc < 4) {
    fputs("usage: viola verify|launch|ensure --module-dir ABSOLUTE_DIRECTORY "
          "[--abi all|64|32]\n",
          stderr);
    return 2;
  }
  for (int i = 2; i < argc; i += 2) {
    if (i + 1 == argc)
      return 2;
    if (!strcmp(argv[i], "--module-dir") && !directory)
      directory = argv[i + 1];
    else if (!strcmp(argv[i], "--control-fd") && control < 0) {
      control = parse_fd(argv[i + 1]);
      if (control < 0)
        return 2;
    } else if (!strcmp(argv[i], "--ready-fd") && ready < 0) {
      ready = parse_fd(argv[i + 1]);
      if (ready < 0)
        return 2;
    } else if (!strcmp(argv[i], "--abi") && abi < 0) {
      abi = !strcmp(argv[i + 1], "all")  ? 0
            : !strcmp(argv[i + 1], "32") ? 1
            : !strcmp(argv[i + 1], "64") ? 2
                                         : -1;
      if (abi < 0)
        return 2;
    } else
      return 2;
  }
  int verify = !strcmp(argv[1], "verify");
  int compat = !strcmp(argv[1], "launch-compat");
  int worker = !strcmp(argv[1], "launch-worker");
  int ensure = !strcmp(argv[1], "ensure");
  if (!directory ||
      (!verify && !compat && !worker && !ensure && strcmp(argv[1], "launch")) ||
      (!ensure && abi >= 0) ||
      (compat && (control < 0 || ready < 0 || control == ready)) ||
      (worker && (control >= 0 || ready < 0)) ||
      (!compat && !worker && (control >= 0 || ready >= 0)))
    return 2;
  if (!verify && geteuid() != 0) {
    failure("root required", -EPERM);
    return 1;
  }
  struct package *package = calloc(1, sizeof(*package));
  if (!package)
    return 1;
  package->dirfd = -1;
  int result = load_package(package, directory);
  if (!result && verify)
    result = verify_package(package, 0);
  else if (!result && compat) {
    struct yz_viola_status status;
    if (admission_syscall(SYS_ioctl, control, YZ_IOCTL_VIOLA_CLAIM, 0))
      result = -errno;
    else
      result = read_status(control, &status);
    if (!result && status.role != YZ_VIOLA_LAUNCHER32)
      result = -EPERM;
    if (!result)
      result = execute_daemon(package, control, ready, VIOLA_ABI_ARM32);
  } else if (!result && worker) {
    uint32_t kmi = detect_kmi(package);
    result = kmi ? verify_package(package, kmi) : -ENOTSUP;
    if (!result)
      result = launch_worker(package, ready, 1, kmi);
  } else if (!result) {
    int base = open_directory(VIOLA_BASE, 1);
    result = base < 0 ? base : 0;
    if (base >= 0)
      close(base);
    int operation = result ? result : viola_recovery_lock();
    if (operation < 0)
      result = operation;
    else {
      result = ensure ? ensure_daemons(package, abi < 0 ? 0U : (unsigned)abi)
                      : launch(package, -1);
      close(operation);
    }
  }
  if (package->dirfd >= 0)
    close(package->dirfd);
  free(package);
  if (result)
    failure(argv[1], result);
  else
    printf("viola: %s succeeded\n", argv[1]);
  return result ? (ensure ? (result == -EUCLEAN ? 3 : 2) : 1) : 0;
}
