# YukiLinker integration

The standalone runtime ports the SDK integration from
[`Rouyashiki/YukiSU@55bda3ee`](https://github.com/Rouyashiki/YukiSU/commit/55bda3eee71ed46ab70f24c785712b8285915527).
The SDK submodule is pinned to `a479258e5eaa4574187c5e99d86974c9ecc366ce`.
Each ordinary and native Core compiles its own SDK runtime through
`yukilinker_add_runtime_sources`; the temporary first stage is
`libyloader64.so` or `libyloader32.so`.

## Module ownership

Ordinary Zygisk modules use PRIVATE when the existing `yukilinker` setting is
enabled. The `anonymous_memory` setting selects anonymous or file-backed
PRIVATE mappings. Module-local dependencies resolve through a duplicated
`zygisk` directory fd, closed after pre-specialize callbacks and before fd
sanitization. SYSTEM fallback is allowed only for supported compatibility
failures before execution, with complete cleanup.

Native ZN modules use SYSTEM with the verified resident-libc caller. The
generated AT_ENTRY resolver opens the temporary Bionic-registered loader and
binds its native loading service to the process and bootstrap generation.
Core drains and revokes that service before handoff; module-originated Bionic
libdl calls remain available after the loader is released.

Library records retain failed or incomplete operations. Callback execution
and private-image Hook leases prevent premature unloading. SDK and YukiPLT
fork coordination remains part of the Core dispatcher. Core retirement drains
hooks, modules and thread state, runs ELF finalizers, releases dependencies
and returns through an external continuation before unmapping.

## Standalone package boundaries

- Viola role 5 identifies the SDK bootstrap. Package paths are
  `lib64/libyloader.so` and `lib/libyloader.so`; Viola deploys the verified
  images as `/data/adb/yukizygisk/lib/libyloader64.so` and `libyloader32.so`.
  Both Cores retain their existing Viola roles and filenames.
- The kernel advertises `YZ_RUNTIME_CAP_NATIVE_LIBC_BOOTSTRAP_V1`; the daemon
  requires it together with endpoint handoff support. Rebuild the LKM,
  Viola, daemon and payloads as one signed module package.
- The on-disk early snapshot version is 3; its layout is unchanged. Bootstrap
  packet v3, SDK ABI1, HostServices1 and module ABIs remain unchanged.
- The native redirect rechecks the standalone Viola authorization ticket.
  Bootstrap failure reporting is bound to the creating process and generation
  and restores the standalone temporary load policy.
- The standalone endpoint transport and KernelSU late-load activation path
  remain in place. Activation still follows a user-initiated soft reboot.

## Validation

The generated kernel injection images use NDK `30.0.16248370`. Verify them with
`python3 userspace/zygisk/inject/generate.py --ndk /path/to/ndk`; `--write`
regenerates the checked-in headers after source changes. The LKM workflow gates
builds on this check. The regular userspace workflow keeps its pinned NDK 29.

See [the Native Bionic suite](tests/native_bionic/README.md) for ARM64/ARM32
bootstrap, ownership, TLS, hook, fork and retirement fixtures. The host/PLT,
bootstrap, Viola and module-integrity runners cover the standalone boundaries.
These checks do not establish kernel-triggered device startup, OEM namespaces,
HyOS services or long-running resident-module behavior.
