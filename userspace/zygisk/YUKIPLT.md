# YukiPLT integration

Both the Zygote and native Core use the pinned YukiPLT submodule directly.
Each Core owns a private static library and registry, built with the same NDK
and static libc++. C++ objects and handles stay within their owning Core.
The supported injection topology selects one Core per process.

## Hook ownership

Bootstrap, ART, native modules and HyperOS retain their image identities,
original storage and recovery handles. HyperOS installs its two slots in one
transaction. Zygisk registration queues belong to the invoking module; commit
prepares all groups before installing one transaction per image. Different
images can partially succeed. Pending recovery blocks further installation.

Unhook preserves foreign slot values and retains incomplete recovery handles.
Published original storage is never reused, including after rollback. An
unhooked slot does not prove callback quiescence: modules with published
replacements remain resident without an explicit quiescence contract.

Zygisk and ZygiskNext API layouts are unchanged. The ZN pltHook boundary can
reuse an identical live binding after checking its handle and slot. Competing
replacements fail. Use `zygisk::loadPltOriginal` or `zn_plt_load_original` to
read published originals. Targets must expose unique, publicly enumerable
JUMP_SLOT imports; their image, replacement and original storage must remain
alive through recovery and callback completion.

## Fork and cache lifetime

Core operations use a common admission gate. Module callbacks and loader
boundaries drain active operations and invalidate cached map permissions.
Contention, recursive boundaries and timeouts reject unsafe dispatch.

Managed Zygote and HyperOS forks use YukiPLT's HostDispatcher protocol, which
drains library operations and coordinates the Core's private pthread keys.
The child adopts its own process and thread identity, then captures permissions
after Bionic's child callbacks. Only the resulting bounded window may use
cached restoration; external callbacks close it. Ordinary restoration uses
live maps. Uncoordinated fork children cannot use inherited Core state.
No anonymous Core callback is permanently registered with libc's atfork list.

## Anonymous Core retirement

The kernel always stages YukiLinker before Core, including the ARM32 Tango
entry. Viola verifies the loader and Core using their respective image roles.
The module linker setting still controls module loading policy.

Retirement restores hooks, checks quiescence, consumes recovery handles,
unsubscribes the fork dispatcher, releases registry and loader ownership,
and drains private runtime state before the existing assembly self-unmap tail.
The Core remains resident if a required condition cannot be proved. The final
ELF must retain the expected two NDK CRT finalizers, private runtime bindings,
and only libc, libdl and libm dependencies. Exceptions stay within the Core.

Standalone endpoint authentication, module paths, logging and mount cleanup
remain owned by this repository. Native companion index and availability are
published together so concurrent IPC uses a consistent binding.

## Build and verification

Initialize dependencies with `git submodule update --init --recursive`.
Runtime builds require CMake 3.24 or newer for YukiPLT's default Full LTO.
The submodule gitlink identifies the exact library source; attribution is in
the root NOTICE and the dependency's LICENSE.

The existing PLT, bootstrap and native Bionic runners cover ownership,
recovery, managed fork, anonymous loading and retirement. See
`tests/native_bionic/README.md` for offline commands. Host sanitizers, QEMU and
cross-builds do not establish Android/OEM runtime compatibility. Deploy the
LKM and payloads from the same build; older Tango stubs use a different entry
contract.
