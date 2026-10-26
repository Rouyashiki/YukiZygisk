"""Exercise production handoff and actual Bionic bootstrap retirement offline."""

import argparse
import os
from pathlib import Path

from run_native_bionic_tests import function, run


def build_one(root, build, compiler, flags, runner=None):
    build.mkdir(parents=True, exist_ok=True)
    core = root / 'userspace/zygisk/core/src'
    fixture = root / 'userspace/zygisk/tests/native_bionic'
    source = (core / 'yukilinker.cpp').read_text()
    (build / 'bootstrap_loader_under_test.inc').write_text(source)
    (build / 'loader_handoff_under_test.inc').write_text((core / 'loader_handoff.cpp').read_text())
    (build / 'bootstrap_retirement_under_test.inc').write_text('\n'.join(
        function(source, signature) for signature in (
            'bool release_bootstrap_metadata(', 'bool prepare_bootstrap_retirement(')))
    ordinary = (core / 'core.cpp').read_text()
    native = (core / 'yukizncore.cpp').read_text()
    signature = 'extern "C" [[gnu::visibility("default")]] void zygisk_finalize_loader('
    (build / 'core_finalizers_under_test.inc').write_text(
        function(ordinary, 'extern "C" [[gnu::visibility("default")]] bool\nzygisk_bootstrap_handoff_complete(') + '\n' +
        function(ordinary, signature).replace('zygisk_finalize_loader', 'ordinary_finalize') + '\n' +
        function(native, signature).replace('zygisk_finalize_loader', 'native_finalize'))
    command = [str(compiler), '-std=c++17', '-O1', '-g', '-fno-exceptions', '-fno-rtti',
               *flags, '-I' + str(build), '-I' + str(core), '-I' + str(root)]
    run([*command, fixture / 'loader_handoff.cpp', '-ldl', '-o', build / 'handoff_test'])
    if runner is not None:
        run([*runner, build / 'handoff_test'])
    if not any('--target=' in flag for flag in flags):
        return
    shared = [*command, '-shared', '-fPIC', '-fvisibility=hidden',
              '-fno-c++-static-destructors', '-ffunction-sections', '-fdata-sections',
              '-Wl,--gc-sections', '-Wl,-z,now', '-ldl']
    run([*shared, '-fvisibility=default', fixture / 'handoff_dependency.cpp',
         '-Wl,-soname,libhandoff_dependency.so', '-o', build / 'libhandoff_dependency.so'])
    for fixed in (False, True):
        bindings = [core / 'core_bindings.cpp'] if fixed else []
        run([*shared, fixture / 'handoff_payload.cpp', core / 'loader_handoff.cpp', *bindings,
             root / 'userspace/common/cxx_slim.cpp',
             '-L' + str(build), '-lhandoff_dependency',
             '-Wl,-soname,libhandoff_core.so', '-o', build / ('fixed.so' if fixed else 'borrowed.so')])
    run([*shared, '-DYUKILINKER_BOOTSTRAP=1', fixture / 'handoff_loader.cpp',
         root / 'userspace/zygisk/endpoint.cpp', root / 'userspace/common/cxx_slim.cpp',
         '-o', build / 'loader.so'])
    run([*command, fixture / 'handoff_bionic.cpp', core / 'loader_handoff.cpp',
         '-ldl', '-o', build / 'handoff_bionic'])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', required=True, type=Path)
    parser.add_argument('--qemu', action='store_true')
    parser.add_argument('--ndk', type=Path)
    parser.add_argument('--android-sysroot', type=Path)
    parser.add_argument('--production-prefix', type=Path,
                        help='External CMake build directory prefix, followed by -<abi>')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    out = args.build_dir.resolve()
    if out.is_relative_to(root):
        parser.error('Build outputs must be outside the checkout')
    if args.android_sysroot:
        for abi, emulator, lib in [('arm64-v8a', 'qemu-aarch64', 'lib64'),
                                  ('armeabi-v7a', 'qemu-arm', 'lib')]:
            directory = out / abi
            libraries = str(directory) + ':' + str(args.android_sysroot / ('apex/com.android.runtime/' + lib + '/bionic'))
            prefix = [emulator, '-L', args.android_sysroot, '-E', 'LD_LIBRARY_PATH=' + libraries]
            run([*prefix, directory / 'handoff_test'])
            for name, expected in [('borrowed.so', '0'), ('fixed.so', '1'), ('fixed.so', 'system')]:
                run([*prefix, directory / 'handoff_bionic', directory / 'loader.so', directory / name, expected])
            if args.production_prefix:
                production = Path(str(args.production_prefix) + '-' + abi)
                for library in ('libyukizncore', 'libzygisk'):
                    filename = library + ('64.so' if abi == 'arm64-v8a' else '32.so')
                    run([*prefix, directory / 'handoff_bionic', directory / 'loader.so', production / filename, 'production'])
    elif args.ndk:
        tag = 'windows-x86_64' if os.name == 'nt' else 'linux-x86_64'
        compiler = args.ndk / 'toolchains/llvm/prebuilt' / tag / 'bin' / ('clang++.exe' if os.name == 'nt' else 'clang++')
        for abi, target in [('arm64-v8a', 'aarch64-linux-android31'),
                            ('armeabi-v7a', 'armv7a-linux-androideabi31')]:
            build_one(root, out / abi, compiler, ['--target=' + target, '-static-libstdc++'])
    else:
        build_one(root, out / 'host', os.environ.get('CXX', 'clang++'),
                  ['-fsanitize=address,undefined', '-fno-omit-frame-pointer'], [])
        if args.qemu:
            for arch, target in [('aarch64', 'aarch64-linux-gnu'), ('arm', 'arm-linux-gnueabihf')]:
                build_one(root, out / arch, target + '-g++', [], ['qemu-' + arch, '-L', '/usr/' + target])


if __name__ == '__main__':
    main()
