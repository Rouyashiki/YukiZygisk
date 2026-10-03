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

The standalone control path uses process-bound anonymous control FDs. Viola
verifies the signed core manifest, loads the verified KO buffer, and executes
the verified daemon from a kernel-frozen file descriptor. The official KO
checks its compiled Viola identity and independently verifies its own runtime
payloads before handing them to a target process. Cookie-based startup is no
longer accepted. Root management sessions can query status and request a reload;
daemon initialization and runtime mutations require their assigned role.

Main and existing 32-bit/Tango daemon sessions are authorized separately.
Forking, transferring a control FD, or executing another program does not
transfer its authority. A failed or expired daemon session prevents new
injection that depends on that daemon; independently verified early-native
payloads retain their separate admission path.

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
`bin/viola`, `bin/zygiskd64`, `bin/zygiskd32`, and the arm64 `bin/yzctl` control client;
the matching 64-bit payloads are under `lib64/`, and the 32-bit payloads are
under `lib/`. The installed module also provides `bin/zygiskd` as a symlink to
the active 64-bit daemon. A KMI-specific LKM directory is included, and a
local test package may contain one `lkm/<kmi>_yukizygisk.ko`:

```bash
./build.sh package -k android15-6.6
```

Package versions use the base version in `module/module.prop`, followed by
`10000 + git rev-list --count HEAD`, for example `v0.2.0-10075`.

A release package contains all supported KMIs and is produced with
`./build.sh package --all-kmis` (or by CI's parallel matrix). During install
and `post-fs-data`, the module derives the exact GKI KMI from `uname -r` and
loads only the matching KO. Unknown releases and missing matches fail closed.
The script delegates startup to Viola and waits for authenticated daemon
readiness with a bounded timeout. Existing early-native sources are checked
against the same signed core manifest; third-party Zygisk/ZN modules are not
required to carry the project's signature.

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

## Viola builds and verification

Installation uses controlled extraction to check `files.list` and each packaged
file against its SHA-256 sidecar, including Viola before its first execution.
These checks detect incomplete or corrupted packages. Viola then authenticates
the signed core payloads using its compiled OpenPGP trust anchors.

Viola embeds [lkmloader](https://github.com/Rouyashiki/lkmloader) as a pinned
source submodule; initialize it with `git submodule update --init --recursive`.
It first loads the verified, read-only KO buffer normally. Only `ENOENT` or
`ENOEXEC` enters compatibility loading: a sealed copy of those authenticated
bytes is passed to the embedded loader, which resolves built-in kernel symbols
and may retry once with an exact kernel-reported vermagic. The package on disk
is unchanged. Both loading syscalls execute inside Viola's authenticated image.
This compatibility path loads a transformed authenticated image, rather than
claiming byte identity with the signed KO. It cannot repair incompatible kernel
APIs, layouts or CFI types. No separate loader executable or shared C++ runtime
is required.

Build hosts need Python 3.10+ with `tools/requirements-viola.txt`, GnuPG, and a
native C compiler in addition to the existing Android NDK/CMake/DDK tools.
Windows uses `clang` for the host verifier (with the Visual C++ SDK), or the
compiler selected by `VIOLA_HOST_CC`. `VIOLA_PYTHON` selects a Python environment;
`VIOLA_GPG` selects a GnuPG executable. For example:

```bash
python3 -m venv build/viola-tools
build/viola-tools/bin/python -m pip install -r tools/requirements-viola.txt
export VIOLA_PYTHON="$PWD/build/viola-tools/bin/python"
./build.sh viola
./build.sh kernel -k android15-6.6
```

Public-only official builds do not need a private key. Creating an installable
package does: official packages pin primary fingerprint
`71B2B58C2A543472BE0DA0D8F580A2CEEF67DC98` and release subkey
`C01D42FA249B2E23C28F4B0347E533340DE325A5`. Only that exact approved signing key
is used. CI requires `GPG_PRIVATE_KEY` and, when necessary, `GPG_PASSPHRASE` in
the independent repository. Store the ASCII-armored secret-subkey export
directly in `GPG_PRIVATE_KEY` (not Base64); the primary private key is not needed.
Missing signing material fails packaging; there is
no unsigned or development fallback. PR builds produce compilation/test
artifacts, not installable ZIPs.

For local changes, create a separate Ed25519 OpenPGP development identity with
an Ed25519 signing subkey, and select its **full subkey fingerprint**:

```bash
./build.sh package -k android15-6.6 --viola-profile dev \
  --viola-key DEVELOPMENT_SIGNING_SUBKEY_FINGERPRINT
```

The corresponding PowerShell flags are the same. `--viola-public-key FILE`
can supply its public certificate; signing uses the selected GnuPG home
(`GNUPGHOME`). A passphrase can be supplied through the GnuPG agent or
`VIOLA_GPG_PASSPHRASE`, never as a command-line argument. Do not commit private
keys. Development packages still enforce every check and are not accepted by
an official kernel/verifier. Switching a loaded release or trust profile
requires rebooting into the matching complete package.

The public build context is under `build/viola`. All components carry its
release identity. The KO also embeds the final Viola digest, so a stale KO is
rejected during packaging even if an old file was reused with `--skip-*`.
The package contains a binary `viola.manifest`, standard GPG detached
`viola.sig`, and public-only `viola.pgp`. Runtime trust comes from the compiled
approved keys; replacing the bundled certificate cannot authorize another key.

The installed verifier supports:

```sh
bin/viola verify --module-dir /absolute/path/to/module
bin/viola launch --module-dir /absolute/path/to/module
```

`verify` does not load anything. `launch` is the sole supported startup path;
repeating it can recover a lost daemon of the same loaded release. It does not
restart zygotes. `yzctl status --json` includes the kernel's Viola catalog,
release, daemon-session states, and last authorization error.

This authenticates this project's core payloads without manager certificates
or an online key service. It does not authenticate the whole installation
script tree, provide online revocation/rollback protection, or establish trust
against replacement of the verifier and its embedded keys together. Android
execution policy, kernel integration, and boot timing still require target
runtime validation; a successful host test or cross-build does not prove them.

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
