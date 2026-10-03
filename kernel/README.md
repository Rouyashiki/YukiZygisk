# YukiZygisk Kernel LKM

This directory is the first standalone extraction point for the kernel-side
YukiZygisk code currently implemented inside YukiSU.

Current state:

- `feature/zygote_*.c` and matching headers are imported from YukiSU commit
  `754182ed55923beba83484fa6624250a8c78cf39`.
- `core/module.c` provides an independent module entry/exit path.
- `core/bootstrap.c` queues `prctl` control-session requests into process
  context. It performs no image reads or hashing in the kprobe callback.
- `core/auth.c` authenticates the compiled Viola image before business hooks,
  checks the signed core catalog, and owns process/mm/generation-bound roles.
  A frozen approved file is required for each daemon exec transition. The main
  daemon delegates a separate limited session for the existing 32-bit path.
- `core/control.c` exposes the YukiZygisk `YZ_IOCTL_*` UAPI through anonymous
  FDs. Root query/reload access cannot initialize a daemon or mutate runtime
  targets. Queued mutations carry the original authorization generation and
  target mm; owner exit/exec revokes authority independently of FD lifetime.
- Self-owned loader/core/native payloads are checked from their actual staging
  buffer, then sealed before FD delivery. Third-party module images retain the
  generic staging path. Early-native admission uses the authenticated catalog;
  ordinary and Tango paths also require the corresponding daemon readiness.
- `host/host.h` and `host/adapter.c` are the temporary host adapter. They
  preserve source-level build boundaries while the remaining SELinux,
  root-backend, and daemon integrations are extracted.
- `host/runtime.c` and `host/root_impl.c` reuse Kasumi's runtime symbol
  resolver and root implementation detector under YukiZygisk naming. Host init
  accepts one KernelSU or KernelPatch/APatch owner with a readable denylist and
  rejects Magisk-only, multi-root, and no-root environments.
- `YZ_IOCTL_GET_ROOT_STATUS` exposes the accepted owner and KernelSU redirect
  state; `YZ_IOCTL_UID_SHOULD_UMOUNT` routes full-UID policy queries through the
  YukiZygisk host boundary.
- `host/lsm.c` provides the versioned LSM hook backend for the AT_ENTRY
  interception point. It patches `static_calls_table` on 6.12+ and
  `security_hook_heads` on older kernels.
- `host/patch_text.c` provides the arm64 patch primitive used by the LSM
  backend.
- `feature/zygote_orch.c` monitors successful `setresuid` through syscall
  tracepoints and defers specialize notifications through a workqueue. Do not
  add a direct syscall-table fallback here; use a host backend if a target lacks
  usable syscall tracepoints.
- `host/mount.c` owns standalone `YZ_IOCTL_UMOUNT_PID` cleanup. It schedules
  target-context task work, scans the app's mount namespace, and detaches
  KSU/Magisk/APatch/YukiZygisk and `/data/adb` module mounts itself instead of
  depending on KSU `kernel_umount`.

This is not yet a complete replacement for the YukiSU-integrated module.
KernelSU and KernelPatch/APatch are modeled as host backends rather than core
owners; other root states are currently unsupported. The remaining hard
dependencies are documented in `docs/source-inventory.md`.

The standalone ioctl ABI uses only `YZ_IOCTL_*` with magic `'Y'`, but the ioctl
file is delivered through authenticated startup instead of a public device node. Do not
add `KSU_IOCTL_YZ_*` or magic `'K'` here; that ABI remains with the integrated
YukiSU/YukiZygisk module.

The standalone package delegates startup to `bin/viola`. Viola chooses the
matching KMI, verifies the signed manifest and exact KO buffer, and calls
`init_module` itself. Cookie module parameters and the old cookie bootstrap
are no longer accepted. An invalid catalog or core image fails closed without
killing a target process. Existing metadata-based early-native images must
match the same authenticated core catalog.

Build shape:

```bash
./build.sh kernel -k android15-6.6
./build.sh kernel --all-kmis
```

The default single target is pinned by `.ddk-version`; KMI-tagged outputs are
written under `build/out/lkm/`.

The build first prepares `build/viola` and the final stripped Viola digest.
Direct kernel builds must provide `VIOLA_KMI_ID` (1 through 7 in the build
script's target order); `VIOLA_BUILD_DIR` defaults to the sibling
`build/viola`. Both the image identity and expected loader digest are preserved
as ELF notes and checked by the package signer. See the top-level README for
public-only official builds and independent development signing.
