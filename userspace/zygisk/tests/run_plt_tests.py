import argparse
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[3]
core = root / 'userspace/zygisk/core/src'
lsplt_root = root / 'userspace/zygisk/third_party/lsplt'
lsplt = lsplt_root / 'lsplt/src/main/jni'
source = (core / 'hook.cpp').read_text()
begin = source.index('int current_thread_count() {')
end = source.index('struct ZygiskContext {', begin)

parser = argparse.ArgumentParser()
parser.add_argument('--qemu', action='store_true')
args = parser.parse_args()


def extract_function(text, name):
    start = text.index('bool ' + name + '(')
    first = text.index('{', start)
    depth, finish = 1, first + 1
    while depth:
        depth += (text[finish] == '{') - (text[finish] == '}')
        finish += 1
    return text[start:finish]


with tempfile.TemporaryDirectory(prefix='yz-plt-state-') as temporary:
    build = Path(temporary)
    (build / 'art_hook_under_test.inc').write_text(source[begin:end])
    (build / 'art_retire_under_test.inc').write_text(
        extract_function(source, 'retire_art_fork_hook'))
    hyos = (core / 'hyos_runtime.cpp').read_text()
    (build / 'hyos_hook_under_test.inc').write_text('\n'.join(
        extract_function(hyos, name)
        for name in ('rollback_partial_hooks', 'install_registered_hooks')
    ))
    native = (core / 'yukizncore.cpp').read_text()
    native_begin = native.index('int api_plt_hook(')
    native_end = native.index('\nint api_inline_hook(', native_begin)
    (build / 'native_plt_under_test.inc').write_text(native[native_begin:native_end])
    flags = [
        '-std=c++17', '-O1', '-g', '-pthread', '-D_GNU_SOURCE', '-DLOG_DISABLED',
        '-DDT_ANDROID_REL=0x6000000f', '-DDT_ANDROID_RELSZ=0x60000010',
        '-DDT_ANDROID_RELA=0x60000011', '-DDT_ANDROID_RELASZ=0x60000012',
        '-I' + str(core), '-I' + str(lsplt / 'include'), '-I' + str(lsplt),
        '-I' + str(lsplt_root / 'test/host'), '-I' + str(build)
    ]
    flags.append('-I' + str(core.parents[1] / 'include'))
    builds = [(os.environ.get('CXX', 'clang++'), 'host',
               ['-fsanitize=address,undefined', '-fno-omit-frame-pointer'], [])]
    if args.qemu:
        builds.extend([
            ('aarch64-linux-gnu-g++', 'arm64', ['-static'], ['qemu-aarch64']),
            ('arm-linux-gnueabihf-g++', 'arm32', ['-static'], ['qemu-arm'])
        ])
    for compiler, arch, extra_flags, runner in builds:
        for name in ('plt_state_test', 'hyos_plt_test', 'art_retire_test', 'native_plt_test'):
            binary = build / (name + '-' + arch)
            sources = [str(Path(__file__).with_name(name + '.cpp'))]
            if name != 'plt_state_test':
                sources.append(str(lsplt / 'elf_util.cc'))
            subprocess.run([compiler, *flags, *extra_flags, *sources,
                            '-o', str(binary)], check=True)
            subprocess.run([*runner, str(binary)], check=True)
