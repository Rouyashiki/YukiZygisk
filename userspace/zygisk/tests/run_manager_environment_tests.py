#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise manager discovery and the real specialize/flag functions on Linux."""

import os
from pathlib import Path
import subprocess
import tempfile


root = Path(__file__).resolve().parents[3]
core = (root / 'userspace/zygisk/core/src/core.cpp').read_text()
daemon = (root / 'userspace/zygisk/daemon/zygiskd.cpp').read_text()


def function(source, signature):
    start = source.index(signature)
    return source[start:source.index('\n}', start) + 2]


with tempfile.TemporaryDirectory(prefix='yz-manager-env-') as temporary:
    build = Path(temporary)
    # Keep the production control flow, including post-specialize with zero
    # modules. Only Android hooks and the root driver's syscalls are stubbed.
    (build / 'manager_functions.inc').write_text('\n'.join([
        function(daemon, 'uint32_t query_flags(uint32_t uid)'),
        'uint32_t zd_get_flags(int uid) { return query_flags(uid); }',
        function(core, 'uint32_t api_get_flags(void *'),
        function(core, 'int zygisk_inject_decision(int uid)'),
        function(core, 'void run_app_post_impl(JNIEnv *env,'),
    ]))
    binary = build / 'manager_environment_test'
    subprocess.run([
        os.environ.get('CXX', 'clang++'), '-std=c++17', '-Wall', '-Wextra', '-Werror',
        '-I' + str(root), '-I' + str(root / 'kernel'), '-I' + str(build),
        str(Path(__file__).with_name('manager_environment_test.cpp')),
        '-o', str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=30)
