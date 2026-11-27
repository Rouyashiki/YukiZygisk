# SPDX-License-Identifier: GPL-2.0-only
"""Exercise KernelSU callback binding, policy publication and temporary leases."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


def definition(source, name):
    match = re.search(r'^[\w \t*]+[\s*]+\b' + name + r'\([^;{}]*\)\n\{', source, re.M)
    if not match:
        raise ValueError(f'function definition missing: {name}')
    return source[match.start():source.index('\n}', match.end()) + 2]


def run_fixture(test_file, definitions):
    with tempfile.TemporaryDirectory() as temp:
        (Path(temp) / 'production.inc').write_text('\n\n'.join(definitions))
        binary = Path(temp) / test_file.stem
        subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-O1', '-g',
                        '-Wall', '-Werror', '-fsanitize=address,undefined',
                        '-fno-sanitize-recover=undefined', '-pthread',
                        '-I', temp, str(test_file), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True)


class PolicyPublishTest(unittest.TestCase):
    def test_callback_binding(self):
        tests = Path(__file__).resolve().parent
        ksu = (tests.parent / 'host/policy_ksu.c').read_text()
        run_fixture(tests / 'policy_ksu_bind_test.c', [
            re.search(r'^#define KSU_ADVANCE_TYPES .+$', ksu, re.M).group(),
            definition(ksu, 'advance_address'),
            definition(ksu, 'pin_advance_owner'),
            definition(ksu, 'yz_ksu_policy_bind'),
            definition(ksu, 'yz_ksu_policy_unbind'),
        ])

    def test_publication(self):
        tests = Path(__file__).resolve().parent
        host = tests.parent / 'host'
        policy = (host / 'policy.c').read_text()
        leases = (host / 'policy_temp.c').read_text()
        fixed = (tests.parent / 'feature/fixed_policy.c').read_text()
        source = [
            definition(fixed, 'yz_fixed_policy_latch'),
            definition((host / 'policy_ksu.c').read_text(), 'yz_ksu_policy_advance'),
            definition(policy, 'yz_policy_commit_edit_locked'),
            definition(policy, 'yz_policy_base_commit_allow_locked'),
            definition(policy, 'yz_policy_base_commit_restore_locked'),
            definition(policy, 'yz_policy_base_lock'),
            definition(policy, 'yz_policy_base_unlock'),
            leases[leases.index('#define YZ_POLICY_TEMP_RULE_MAX'):leases.index('void yz_policy_temp_reset')],
            leases[leases.index('static bool yz_policy_temp_key_eq'):leases.index('static int yz_policy_temp_validate_batch_locked')],
        ]
        run_fixture(tests / 'policy_publish_test.c', source)


if __name__ == '__main__':
    unittest.main()
