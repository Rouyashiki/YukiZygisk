#define open fixture_open
#define main viola_program_main
#include "userspace/viola/main.c"
#undef main
#undef open

static const char *fixture_root;

int fixture_open(const char *path, int flags, ...) {
  if (fixture_root && !strcmp(path, "/"))
    path = fixture_root;
  return openat(AT_FDCWD, path, flags);
}

int main(int argc, char **argv) {
  if (argc != 3)
    return 2;
  struct package package = {.dirfd = -1};
  int result = load_package(&package, argv[1]);
  if (!result) {
    fixture_root = argv[2];
    result = deploy_cores(&package);
  }
  if (package.dirfd >= 0)
    close(package.dirfd);
  printf("%d\n", result);
  return 0;
}
