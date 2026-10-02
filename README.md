# YukiZygisk

A new kernel-level Zygisk implementation designed to explore better, cleaner, and more flexible ways of injecting.

## Kernel LKM Skeleton

The standalone kernel sources live in [kernel](kernel). A single test KMI can
be built through DDK:

```bash
./build.sh kernel -k android15-6.6
```

The output is KMI-tagged as
`build/out/lkm/android15-6.6_yukizygisk.ko`. Use `--all-kmis` to build all
supported GKI targets locally. CI builds the seven supported targets as a
matrix and assembles one release module package containing every KO.

This is a buildable extraction checkpoint, not a complete runtime replacement
for the YukiSU-integrated module yet. See the source inventory for the
remaining daemon mediation, payload staging, and host-backend runtime
validation work. The kernel-side setresuid tracepoint monitor, SELinux policy
adapter, and mount cleanup adapter are present in the standalone LKM, but still
need device-side validation before they can be treated as runtime parity.

The standalone control path no longer creates `/dev/yukizygisk`. The LKM arms a
one-shot `prctl` bootstrap when loaded with a per-boot cookie; `zygiskd` claims
an anonymous control fd immediately after startup and then reuses the
`YZ_IOCTL_*` command surface on that fd. Root control clients use the separate
`yzctl` binary, which requests an independently authenticated anonymous control
fd and talks to the same kernel ioctl surface without going through zygiskd.

If zygiskd never claims the bootstrap fd, the kernel guard checks for zygote
service sockets after a short delay. Once service startup is visible, the guard
clears the bootstrap cookie, disables new control sessions, and fails closed.
The later `boot-completed` health check performs the external module unload.

The standalone design remains root-implementation agnostic at its internal
boundaries, but its current admission policy is deliberately narrow. Module
initialization accepts exactly one KernelSU/YukiSU backend (redirect or
non-redirect) or one KernelPatch/APatch backend with a readable denylist.
Magisk-only, multi-root, and no-root environments fail closed. Kernel code
outside the host adapter calls YukiZygisk-owned `yz_*` and `yz_host_*`
interfaces; detection and denylist routing reuse the Kasumi implementation.

The LSM interception point is now extracted into the standalone host layer:
`selinux_bprm_committed_creds` is patched through a versioned adapter that uses
the 6.12+ `static_calls_table` path or the older `security_hook_heads` path.

Standalone mount cleanup is also owned by YukiZygisk now. `YZ_IOCTL_UMOUNT_PID`
schedules target-context task work, scans that app's `/proc/self/mountinfo`,
and detaches KSU/Magisk/APatch/YukiZygisk tagged mounts plus `/data/adb` module
mounts itself. It must not depend on KSU's `kernel_umount` feature being
enabled.

The standalone control ABI is `YZ_IOCTL_*` with ioctl magic `'Y'` only. It does
not accept the integrated YukiSU/YukiZygisk `KSU_IOCTL_YZ_*`/`'K'` ABI.

The default package is a normal module using the conventional Zygisk layout:
`bin/zygiskd64`, `bin/zygiskd32`, and the arm64 `bin/yzctl` control client;
the matching 64-bit payloads are under `lib64/`, and the 32-bit payloads are
under `lib/`. The installed module also provides `bin/zygiskd` as a symlink to
the active 64-bit daemon. A KMI-specific LKM directory is included, and a
local test package may contain one `lkm/<kmi>_yukizygisk.ko`:

```bash
./build.sh package -k android15-6.6
```

A release package contains all supported KMIs and is produced with
`./build.sh package --all-kmis` (or by CI's parallel matrix). During install
and `post-fs-data`, the module derives the exact GKI KMI from `uname -r` and
loads only the matching KO. Unknown releases and missing matches fail closed.
The script then starts the daemon with the same bootstrap cookie. This gives
up early-native injection by default; that capability can remain a future
optional host backend rather than the baseline standalone path.

The packaged Material 3 Expressive WebUI has four pages: device/injection status, Zygisk
and Native modules, settings, and about/credits. Settings save immediately
through `yzctl`, with serialized updates and visible failure feedback. The
interface supports light/dark appearance and the host's dynamic Material
palette, connected setting groups, press ripples, and navigation transitions.
Its controls and icons are bundled locally. It reads kernel-owned
runtime state and requests reloads through `yzctl`; zygiskd is not a manager
or user control interface. The WebUI
does not own a separately configured denylist. The
preferred path asks the accepted KernelSU or KernelPatch backend through a
CFI-safe kernel callable. If that callable cannot be resolved, the kernel asks
zygiskd for a refresh over netlink: zygiskd uses KernelSU's userspace
ioctl/prctl policy API or parses APatch's `package_config`, then atomically
hands a bounded snapshot back through a sealed memfd on the authenticated
anonymous control fd. The WebUI only selects whether matching processes skip
injection or keep injection before mount cleanup.

## WebUI Development

The packaged frontend is static; normal module builds copy `webui/` without
requiring Node.js. To rebuild its pinned Material and Lucide assets:

```bash
npm ci --prefix tools/webui
npm run build --prefix tools/webui
```

For interactive preview, run `python -m http.server 4173` from the
repository and open `http://127.0.0.1:4173/webui/?mock=1`. Browser preview data
does not establish Android runtime behavior.
