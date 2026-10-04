#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# YukiZygisk - Compile actual kernel execution predicates with boundary mocks.
# License: Apache-2.0
# Author: Anatdx
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class AuthExecTests(unittest.TestCase):
    def test_actual_exec_identity_predicates(self):
        source = (ROOT / "kernel/core/auth.c").read_text()
        functions = []
        for name in ("yz_auth_same_image", "yz_auth_tango_image", "yz_auth_record_exec", "yz_auth_claim_image"):
            start = source.index("static bool " + name + "(")
            body = source.index("\n{", start) + 1
            depth = 0
            for end in range(body, len(source)):
                depth += (source[end] == "{") - (source[end] == "}")
                if not depth:
                    functions.append(source[start:end + 1])
                    break
            else:
                self.fail("Unterminated production function: " + name)
        with tempfile.TemporaryDirectory(prefix="viola-auth-exec-") as temporary:
            directory = Path(temporary)
            (directory / "viola_auth_functions.h").write_text("\n\n".join(functions))
            executable = directory / "auth-exec"
            flags = []
            if os.environ.get("VIOLA_TEST_SANITIZERS"):
                flags += ["-fsanitize=" + os.environ["VIOLA_TEST_SANITIZERS"], "-fno-omit-frame-pointer"]
            subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                *flags, "-I" + str(ROOT), "-I" + str(directory),
                str(ROOT / "tests/viola/auth_exec.c"), "-o", str(executable)], check=True)
            subprocess.run([str(executable)], check=True, timeout=5)
