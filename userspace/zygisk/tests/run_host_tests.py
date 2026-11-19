# SPDX-License-Identifier: Apache-2.0
#
# YukiZygisk - Host regression test runner.
#
# License: Apache-2.0
#
# Author: Rouyashiki Developers

import errno
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile


def run(*args):
    subprocess.run(args, check=True)


if os.geteuid() != 0:
    raise SystemExit('Run these filesystem tests as root in a disposable Linux container.')

root = Path(__file__).resolve().parents[3]
compiler = os.environ.get('CXX', 'g++')
flags = ['-std=c++17', '-O1', '-g', '-fsanitize=address,undefined',
         '-fno-omit-frame-pointer', '-I' + str(root), '-I' + str(root / 'kernel')]
daemon = (root / 'userspace/zygisk/daemon/zygiskd.cpp').read_text()
begin = daemon.index('bool nl_receive_one(int fd) {')
end = daemon.index('uint64_t resolve_linker_sym(', begin)
netlink = r'''
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <deque>
#include <iostream>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <vector>
#include "uapi/yukizygisk.h"
#include "kernel/uapi/viola.h"
#include <unistd.h>

struct Packet { std::vector<char> data; uint32_t sender = 0; int error = 0; };
static std::deque<Packet> packets;
static std::vector<uint32_t> generations;
static ssize_t fake_recvfrom(int, void *buffer, size_t capacity, int flags,
                             sockaddr *address, socklen_t *length) {
    assert((flags & MSG_DONTWAIT) != 0);
    if (packets.empty()) { errno = EAGAIN; return -1; }
    const auto packet = packets.front();
    packets.pop_front();
    if (packet.error) { errno = packet.error; return -1; }
    assert(packet.data.size() <= capacity && *length >= sizeof(sockaddr_nl));
    auto *sender = reinterpret_cast<sockaddr_nl *>(address);
    sender->nl_family = AF_NETLINK;
    sender->nl_pid = packet.sender;
    *length = sizeof(*sender);
    memcpy(buffer, packet.data.data(), packet.data.size());
    return static_cast<ssize_t>(packet.data.size());
}
static void enqueue(uint32_t type, uint32_t generation, uint32_t sender = 0) {
    Packet packet;
    packet.sender = sender;
    packet.data.resize(NLMSG_SPACE(sizeof(yz_zygote_exit_event)));
    nlmsghdr header{};
    header.nlmsg_type = YZ_NL_MSG_EVENT;
    header.nlmsg_len = NLMSG_LENGTH(sizeof(yz_zygote_exit_event));
    yz_zygote_exit_event event{};
    event.event.type = type;
    event.generation = generation;
    memcpy(packet.data.data(), &header, sizeof(header));
    memcpy(packet.data.data() + NLMSG_HDRLEN, &event, sizeof(event));
    packets.push_back(packet);
}
struct Monitor {
    void on_exit(const yz_zygote_exit_event &event) { generations.push_back(event.generation); }
} g_crash_monitor;
struct History { bool enabled() const { return false; } } g_exit_history;
static std::vector<yz_target_exit_event> g_legacy_native_exits;
static void flush_legacy_native_exits() { g_legacy_native_exits.clear(); }
static void read_yzconfig() {}
static bool rescan_modules_for_reload() { return true; }
namespace yzpolicy {
static bool refresh(bool) { return true; }
static void handle_refresh_request(uint32_t) {}
}
namespace yzhost { static int ctl(unsigned long, void *) { errno = EAGAIN; return -1; } }
static bool reap_compat_for_recovery() { return false; }
static int spawn_compat_daemon() { return -1; }
static pid_t g_compat_pid = -1;
#define DLOGE(...) ((void)0)
#define DLOGI(...) ((void)0)
#define recvfrom fake_recvfrom
''' + daemon[begin:end] + r'''
int main() {
    enqueue(YZ_EV_SPECIALIZE, 0);
    enqueue(YZ_EV_ZYGOTE_EXIT, 99, 1234);
    enqueue(YZ_EV_ZYGOTE_EXIT, 7);
    packets.push_back({{}, 0, EINTR});
    enqueue(YZ_EV_ZYGOTE_EXIT, 8);
    nl_drain(1);
    assert(packets.empty());
    assert((generations == std::vector<uint32_t>{7, 8}));
    nl_drain(1);
    std::cout << "PASS: kernel event backlog, sender validation and interrupted receive\n";
}
'''
# The module description writer rejects group- or world-writable ancestors.
with tempfile.TemporaryDirectory(prefix='yz-host-tests-', dir=Path.home()) as temporary:
    build = Path(temporary)
    binary = build / 'late_load_test'
    run(compiler, *flags, str(root / 'userspace/zygisk/tests/late_load_test.cpp'),
        str(root / 'userspace/zygisk/daemon/module_description.cpp'),
        '-Wl,--wrap=lstat', '-o', str(binary))
    run(str(binary))
    # Run the actual CLI against redirected paths and real or simulated kernel
    # control. Keep all fixtures in this temp tree, including the /dev markers.
    include = build / 'include'
    guard_header = include / 'userspace/zygisk/late_load.hpp'
    guard_header.parent.mkdir(parents=True)
    activation = build / 'late-load-state'
    guard_header.write_text((root / 'userspace/zygisk/late_load.hpp').read_text().replace(
        '/dev/yukizygisk-late-load', str(activation)))
    config = build / 'config/yzconfig.json'
    module = build / 'modules/yukizygisk'
    module.mkdir(parents=True)
    incoming = build / 'modules_update/yukizygisk'
    settings = root / 'userspace/zygisk/settings.hpp'
    (guard_header.parent / settings.name).write_text(
        settings.read_text().replace('/data/adb/yukizygisk', str(config.parent))
        .replace('/data/adb/modules/yukizygisk', str(module))
        .replace('/data/adb/modules_update/yukizygisk', str(incoming)))
    dev = build / 'dev'
    dev.mkdir()
    boot = dev / 'policy.boot'
    reboot_required = dev / 'policy.reboot-required'
    fixed_policy = settings.with_name('fixed_policy.hpp')
    (guard_header.parent / fixed_policy.name).write_text(fixed_policy.read_text().replace(
        '/dev/yukizygisk-policy.', str(dev / 'policy.')))
    cli_sources = build / 'yzctl-src'
    shutil.copytree(root / 'userspace/yzctl', cli_sources)
    for source in (*cli_sources.glob('*.cpp'), *cli_sources.glob('*.hpp')):
        source.write_text(source.read_text().replace('/data/adb/yukizygisk', str(config.parent)))
    attr = build / 'proc/42/attr/current'
    attr.parent.mkdir(parents=True)
    attr.write_text('u:r:test_daemon:s0')
    context_node = build / 'selinux/context'
    context_node.parent.mkdir()
    context_node.touch()
    policy_cpp = cli_sources / 'policy.cpp'
    policy_cpp.write_text(policy_cpp.read_text().replace('"/proc/', f'"{build}/proc/').replace(
        '"/sys/fs/selinux/', f'"{context_node.parent}/'))
    policy = root / 'kernel/feature/policy'
    run(sys.executable, str(policy / 'generate.py'), str(policy / 'sepolicy.rule'),
        str(build / 'module_rules.inc'), '--native')
    cli = build / 'yzctl'
    run(compiler, '-I' + str(include), *flags, '-pthread',
        '-I' + str(build), '-I' + str(root / 'userspace/zygisk'), '-I' + str(root / 'userspace/common'),
        '-I' + str(root / 'userspace/zygisk/daemon'),
        *[str(cli_sources / name) for name in ('main.cpp', 'policy.cpp', 'status.cpp', 'host.cpp', 'health.cpp')],
        str(root / 'userspace/zygisk/tests/config_reload_control.cpp'),
        *[str(root / name) for name in (
            'userspace/zygisk/endpoint.cpp',
            'userspace/zygisk/daemon/module_description.cpp')],
        '-Wl,--wrap=syscall', '-Wl,--wrap=ioctl', '-Wl,--wrap=write', '-Wl,--wrap=renameat',
        '-Wl,--wrap=unlinkat', '-Wl,--wrap=fstatat',
        '-o', str(cli))

    reload_trace = build / 'reload-events.jsonl'

    def cli_run(*args, code=0, control=None, stop_before_publish=False, restore_after_publish=None,
                stop_before_retire=False, rule_lookup=None, reject_context=None):
        reload_trace.unlink(missing_ok=True)
        environment = os.environ.copy()
        environment.pop('YZ_TEST_CONTROL', None)
        environment.pop('YZ_TEST_STOP_BEFORE_PUBLISH', None)
        environment.pop('YZ_TEST_STOP_BEFORE_RETIRE', None)
        environment.pop('YZ_TEST_STALE_RULE_STAT', None)
        environment.pop('YZ_TEST_PROMOTE_MODULE', None)
        environment.pop('YZ_TEST_RESTORE_AFTER_PUBLISH', None)
        if restore_after_publish is not None:
            environment['YZ_TEST_RESTORE_AFTER_PUBLISH'] = restore_after_publish
        if stop_before_publish:
            environment['YZ_TEST_STOP_BEFORE_PUBLISH'] = '1'
        if stop_before_retire:
            environment['YZ_TEST_STOP_BEFORE_RETIRE'] = '1'
        if rule_lookup == 'before-link':
            environment['YZ_TEST_STALE_RULE_STAT'] = '1'
        elif rule_lookup == 'before-upgrade':
            environment['YZ_TEST_PROMOTE_MODULE'] = str(module)
        if control:
            environment.update(YZ_TEST_CONTROL=control, YZ_TEST_CONFIG=str(config),
                               YZ_TEST_RELOAD_TRACE=str(reload_trace))
        environment['YZ_TEST_SELINUX_CONTEXT'] = str(context_node)
        if reject_context:
            environment['YZ_TEST_REJECT_CONTEXT'] = f'u:r:{reject_context}:s0'
        result = subprocess.run([str(cli), *args], text=True, capture_output=True,
                                timeout=10, env=environment)
        assert result.returncode == code, (args, result.returncode, result.stdout, result.stderr)
        return result

    def full_reboot():
        for marker in dev.iterdir():
            marker.unlink()

    for extra in ('--help', 'unexpected'):
        cli_run('policy-boot', extra, code=2)
        assert not list(dev.iterdir()) and not config.parent.exists()
    os.mkfifo(boot, 0o600)
    cli_run('policy-boot', code=1)
    boot.unlink()
    cli_run('policy-boot')
    original = boot.read_bytes()
    config.parent.mkdir(exist_ok=True)
    rules = module / 'sepolicy.rule'
    # An unreadable configuration cannot authorize an unsafe staged rule, even
    # when the installed generation is missing or its rule is still trusted.
    incoming.mkdir(parents=True)
    staged = incoming / rules.name
    config.chmod(0o664)
    for installed in (False, True):
        if installed:
            rules.write_text('# trusted installed rule\\n')
        staged.write_text('# restored staged rule\\n')
        staged.chmod(0o664)
        cli_run('policy-boot', code=1)
        assert not staged.exists() and rules.exists() == installed
    rules.unlink()
    incoming.rmdir()
    config.chmod(0o600)

    opaque = '{"id":9007199254740993,"list":[-9007199254740995,0.1250]}'
    config.write_text('{"fixed_sepolicy":true,"custom":' + opaque + '}')
    full_reboot()
    cli_run('policy-boot')
    assert opaque in config.read_text()
    repaired = json.loads(cli_run('config', 'get').stdout)
    assert not repaired['fixed_sepolicy'] and repaired['custom'] == json.loads(opaque)
    config.write_text('{"custom":' + opaque + ',"denylist_mode":1.0000000000000001}')
    cli_run('config', 'set', 'fixed_sepolicy', 'false', 'denylist_mode', '1', control='policy-ready')
    assert opaque in config.read_text() and '1.0000000000000001' not in config.read_text()

    # Recovery must discard untrusted transaction files without reading them.
    baseline = '{"fixed_sepolicy":false,"custom":' + opaque + '}'
    for suffix in ('previous', 'next', 'commit.v2'):
        config.write_text(baseline)
        cli_run('config', 'set', 'fixed_sepolicy', 'true', control='policy-ready',
                stop_before_publish=True, code=75)
        rules.with_suffix('.rule.switch').replace(rules)
        unsafe = config.with_name('yzconfig.json.' + suffix)
        unsafe.unlink()
        unsafe.write_text('{"fixed_sepolicy":true}')
        unsafe.chmod(0o664)
        recovered = json.loads(cli_run('config', 'get').stdout)
        assert not recovered['fixed_sepolicy'] and config.read_text() == baseline
        assert not rules.exists() and not unsafe.exists()
        assert set(config.parent.iterdir()) == {config, config.with_suffix('.json.lock')}
        cli_run('config', 'set', 'fixed_sepolicy', 'false')
        full_reboot()
        cli_run('policy-boot')
    restored = '{"custom":2,"fixed_sepolicy":false}'
    failed = cli_run('config', 'set', 'fixed_sepolicy', 'true', control='policy-ready',
                     restore_after_publish=restored, code=1)
    assert os.strerror(errno.ESTALE) in failed.stderr and 'saved' not in failed.stdout
    assert config.read_text() == restored and not rules.exists()
    assert not list(config.parent.glob('yzconfig.json.commit*'))
    full_reboot()
    cli_run('policy-boot')
    cli_run('config', 'set', 'fixed_sepolicy', 'true', control='policy-ready')
    approved_rules = rules.read_text()
    incoming.mkdir()
    staged.write_text('# untrusted staged restore\n')
    staged.chmod(0o664)
    backup = build / 'rule-backup'
    os.link(staged, backup)
    cli_run('policy-boot')
    assert staged.read_text() == rules.read_text() == approved_rules
    assert not staged.samefile(rules) and staged.stat().st_mode & 0o022 == 0
    assert backup.read_text() == '# untrusted staged restore\n' and backup.stat().st_nlink == 1
    staged.unlink()
    backup.unlink()
    incoming.rmdir()
    os.link(rules, backup)
    cli_run('policy-boot', rule_lookup='before-link', code=1)
    assert backup.read_text() == approved_rules and boot.read_bytes() == original
    backup.unlink()
    upgrade = module.with_suffix('.upgrade')
    upgrade.mkdir()
    (upgrade / rules.name).write_text(approved_rules)
    cli_run('policy-boot', rule_lookup='before-upgrade', code=1)
    old_module = module.with_suffix('.old')
    assert not rules.samefile(old_module / rules.name) and boot.read_bytes() == original
    cli_run('policy-boot')
    shutil.rmtree(old_module)
    # The host scans the module directory before any boot hook. Restoring the
    # old data path must never change what either installed generation grants.
    incoming.mkdir(parents=True)
    staged_rules = incoming / rules.name
    legacy_rules = config.parent / rules.name
    legacy_rules.write_text('restored rule\n')
    legacy_rules.chmod(0o664)
    cli_run('policy-install', 'ksu', str(incoming))
    for published in (rules, staged_rules):
        assert not published.is_symlink() and published.stat().st_nlink == 1
        assert published.stat().st_uid == 0 and not published.stat().st_mode & 0o022
        assert published.read_text() == approved_rules and not published.samefile(legacy_rules)
    assert not rules.samefile(staged_rules)
    legacy_rules.write_text('changed after installation\n')
    assert rules.read_text() == staged_rules.read_text() == approved_rules
    legacy_rules.unlink()
    legacy_rules.symlink_to(config)
    assert rules.read_text() == staged_rules.read_text() == approved_rules
    assert 'allow domain domain process execmem' in approved_rules
    assert 'allow domain yukizygisk_file file { open read getattr map execute }' in approved_rules
    assert '$target' not in approved_rules and ' self ' not in approved_rules
    # Legacy fixed_zn_domains entries are retired on read and rejected on set.
    config.write_text('{"fixed_sepolicy":true,"fixed_zn_domains":["first"],"custom":5}')
    migrated = json.loads(cli_run('config', 'get').stdout)
    assert migrated['fixed_sepolicy'] and migrated['custom'] == 5 and 'fixed_zn_domains' not in migrated
    assert 'fixed_zn_domains' not in config.read_text()
    cli_run('config', 'set', 'fixed_zn_domains', '["first"]', control='policy-ready', code=1)
    # A missing upgrade copy still needs a transaction before a fixed-mode update can commit.
    staged_rules.unlink()
    incoming.chmod(0o777)
    initial_config = config.read_bytes()
    cli_run('config', 'set', 'fixed_sepolicy', 'true', 'denylist_mode', '1',
            control='policy-ready', code=1)
    assert config.read_bytes() == initial_config and config.with_suffix('.json.commit.v2').exists()
    incoming.chmod(0o755)
    assert json.loads(cli_run('config', 'get').stdout)['denylist_mode'] == 0
    assert staged_rules.read_bytes() == rules.read_bytes() and not staged_rules.samefile(rules)
    assert not config.with_suffix('.json.commit.v2').exists()
    staged_rules.write_text('# stale staged rules\n')
    cli_run('config', 'set', 'fixed_sepolicy', 'true', 'denylist_mode', '1',
            control='policy-ready', stop_before_publish=True, code=75)
    assert staged_rules.read_text() == '# YukiZygisk fixed policy pending revalidation\n'
    assert json.loads(cli_run('config', 'get').stdout)['denylist_mode'] == 0
    assert staged_rules.read_bytes() == rules.read_bytes()
    cli_run('config', 'set', 'fixed_sepolicy', 'true', 'denylist_mode', '1', control='policy-ready')
    assert json.loads(config.read_text())['denylist_mode'] == 1
    cli_run('config', 'set', 'fixed_sepolicy', 'true', 'denylist_mode', '0', control='policy-ready')

    # A backup may restore a staged rule file that disagrees with the installed rules.
    stale_staged = approved_rules.replace('test_daemon', 'old_daemon')
    preference = config.read_bytes()
    for command in ('policy-boot', 'policy-refresh'):
        staged_rules.write_text(stale_staged)
        cli_run(command)
        assert staged_rules.read_text() == rules.read_text() == approved_rules
        assert not staged_rules.samefile(rules) and config.read_bytes() == preference
        inode = staged_rules.stat().st_ino
        cli_run(command)
        assert staged_rules.stat().st_ino == inode
        module.rename(old_module)
        incoming.rename(module)
        full_reboot()
        cli_run('policy-boot')
        assert struct.unpack_from('=II', boot.read_bytes())[1] == 1 and not reboot_required.exists()
        assert config.read_bytes() == preference and rules.read_text() == approved_rules
        old_module.rename(incoming)

    cli_run('config', 'set', 'fixed_sepolicy', 'false')
    disabled = config.read_bytes()
    for restore_installed in (False, True):
        staged_rules.write_text(approved_rules)
        if restore_installed:
            rules.write_text(approved_rules)
        cli_run('policy-refresh')
        assert not rules.exists() and not staged_rules.exists()
        assert config.read_bytes() == disabled
    cli_run('config', 'set', 'fixed_sepolicy', 'true', control='policy-ready')

    # A restored legacy journal must not replay after the v2 pins retire.
    for retired in (('commit',), ('publish',), ('commit', 'publish')):
        cli_run('config', 'set', 'fixed_sepolicy', 'false')
        cli_run('config', 'set', 'fixed_sepolicy', 'true', 'denylist_mode', '2',
                control='policy-ready', stop_before_retire=True, code=75)
        journals = [config.with_suffix('.json.' + suffix) for suffix in retired]
        for journal in journals:
            journal.write_text('{"fixed_sepolicy": false}')
        full_reboot()
        if len(journals) == 2:
            cli_run('policy-boot', stop_before_retire=True, code=75)
            assert config.with_suffix('.json.commit.v2').exists() and not boot.exists()
        cli_run('policy-boot')
        assert struct.unpack_from('=II', boot.read_bytes())[1] == 1
        assert not any(journal.exists() for journal in journals)
        assert json.loads(cli_run('config', 'get').stdout)['denylist_mode'] == 2
        assert rules.read_text() == approved_rules and staged_rules.read_bytes() == rules.read_bytes()
        cli_run('config', 'set', 'denylist_mode', '0', control='available')

    # The intent follows the candidate inode across the JSON rename.
    for json_published, keep, mirror_failure in (
            (False, False, False), (False, True, False),
            (True, False, False), (True, False, True), (True, True, False)):
        cli_run('config', 'set', 'fixed_sepolicy', 'false')
        original_config = json.loads(config.read_text())
        cli_run('config', 'set', 'fixed_sepolicy', 'true', 'denylist_mode', '1',
                control='policy-ready', stop_before_publish=True, code=75)
        rules.with_suffix('.rule.switch').replace(rules)
        candidate = config.with_suffix('.json.next')
        if json_published:
            candidate = candidate.replace(config)
        assert candidate.samefile(config.with_suffix('.json.commit.v2'))
        full_reboot()
        restored = {**json.loads(candidate.read_text()), 'fixed_sepolicy': keep, 'custom': 7}
        candidate.write_text(json.dumps(restored))
        if mirror_failure:
            incoming.chmod(0o777)
            cli_run('config', 'get', code=1)
            assert not rules.exists() and config.with_suffix('.json.commit.v2').exists()
            incoming.chmod(0o755)
        recovered = json.loads(cli_run('config', 'get').stdout)
        expected = restored if keep or json_published else original_config
        assert recovered == {**expected, 'fixed_sepolicy': keep}
        if keep:
            assert staged_rules.read_bytes() == rules.read_bytes() and not staged_rules.samefile(rules)
        else:
            assert not rules.exists() and not staged_rules.exists()
        assert reboot_required.exists() != keep
        assert not config.with_suffix('.json.commit.v2').exists()
        cli_run('config', 'set', 'fixed_sepolicy', 'true', 'denylist_mode', '0',
                control='policy-ready')
    # KernelSU promotes the staged directory before boot scripts can retire the journal.
    for generation in ('matching', 'rules-only', 'restored', 'aliased', 'pending'):
        if generation == 'rules-only':
            staged_rules.unlink()
            cli_run('policy-install', 'ksu', str(incoming), control='policy-ready',
                    stop_before_retire=True, code=75)
        else:
            cli_run('config', 'set', 'fixed_sepolicy', 'false')
            cli_run('config', 'set', 'fixed_sepolicy', 'true', 'denylist_mode', '1',
                    control='policy-ready', stop_before_retire=True, code=75)
        intent = config.with_suffix('.json.commit.v2')
        assert config.samefile(intent)
        next_config = config.with_suffix('.json.next')
        if generation == 'rules-only':
            assert next_config.samefile(config)
        else:
            assert not next_config.exists()
        assert rules.read_bytes() == staged_rules.read_bytes() and not rules.samefile(staged_rules)
        if generation == 'restored':
            saved = json.loads(config.read_text())
            saved['fixed_sepolicy'] = False
            config.write_text(json.dumps(saved))
        elif generation == 'aliased':
            os.link(staged_rules, build / 'backup-of-promoted-rules')
        elif generation == 'pending':
            staged_rules.write_text('# YukiZygisk fixed policy pending revalidation\n')
        saved = json.loads(config.read_text())
        shutil.rmtree(module)
        incoming.replace(module)
        full_reboot()
        cli_run('policy-boot')
        keep = generation in ('matching', 'rules-only', 'pending')
        assert json.loads(cli_run('config', 'get').stdout) == {**saved, 'fixed_sepolicy': keep}
        assert rules.exists() == keep and not intent.exists() and not next_config.exists()
        assert struct.unpack_from('=II', boot.read_bytes())[1] == (keep and generation != 'pending')
        incoming.mkdir()
        cli_run('config', 'set', 'fixed_sepolicy', 'true', 'denylist_mode', '0',
                control='policy-ready')
    for switched in (False, True):
        staged_rules.write_text('# stale staged rules\n')
        cli_run('config', 'set', 'fixed_sepolicy', 'true', 'denylist_mode', '2',
                control='policy-ready', code=75, stop_before_publish=True)
        if switched:
            rules.with_suffix('.rule.switch').replace(rules)
        incoming.chmod(0o777)  # A failed mirror must leave the intent available for retry.
        cli_run('config', 'get', code=1)
        assert config.with_suffix('.json.commit.v2').exists()
        assert staged_rules.read_text() == '# YukiZygisk fixed policy pending revalidation\n'
        incoming.chmod(0o755)
        assert json.loads(cli_run('config', 'get').stdout)['denylist_mode'] == (2 if switched else 0)
        assert rules.read_text() == approved_rules
        assert staged_rules.read_bytes() == rules.read_bytes() and not staged_rules.samefile(rules)
        assert not config.with_suffix('.json.commit.v2').exists()
        cli_run('config', 'set', 'denylist_mode', '0', control='available')
    cli_run('config', 'set', 'fixed_sepolicy', 'false', code=75, stop_before_publish=True)
    assert staged_rules.read_text() == '# YukiZygisk fixed policy pending revalidation\n'
    assert json.loads(cli_run('config', 'get').stdout)['fixed_sepolicy']
    assert staged_rules.read_bytes() == rules.read_bytes()
    cli_run('config', 'set', 'fixed_sepolicy', 'false', stop_before_retire=True, code=75)
    assert not rules.exists() and not staged_rules.exists()
    # Model a crash just after the journal unlink reached disk.
    config.with_suffix('.json.commit.v2').unlink()
    previous = config.with_suffix('.json.previous')
    previous_rule = rules.with_suffix('.rule.previous')
    assert previous.is_file() and previous_rule.is_file()
    assert not json.loads(cli_run('config', 'get').stdout)['fixed_sepolicy']
    assert not previous.exists() and not list(module.glob('sepolicy.rule.*'))
    # Upgrade from an old installer link with only restored data available.
    config.write_text('{"fixed_sepolicy":true}')
    rules.symlink_to(legacy_rules)
    staged_rules.symlink_to(legacy_rules)
    cli_run('policy-install', 'ksu', str(incoming))
    assert not rules.is_symlink() and not staged_rules.is_symlink()
    assert rules.read_text() == staged_rules.read_text() == '# YukiZygisk fixed policy pending revalidation\n'
    # Even a failed reinstall must retire legacy links before the next scan.
    for published in (rules, staged_rules):
        published.unlink()
        published.symlink_to(legacy_rules)
    config.chmod(0o664)
    cli_run('policy-install', 'ksu', str(incoming), code=1)
    assert not os.path.lexists(rules) and not os.path.lexists(staged_rules)
    assert legacy_rules.is_symlink() and config.read_text() == '{"fixed_sepolicy":true}'
    config.chmod(0o600)
    legacy_rules.unlink()
    legacy_rules.write_text(approved_rules)
    os.link(legacy_rules, rules)
    os.link(legacy_rules, staged_rules)
    cli_run('policy-install', 'ksu', str(incoming))
    assert rules.read_text() == staged_rules.read_text() == '# YukiZygisk fixed policy pending revalidation\n'
    assert legacy_rules.stat().st_nlink == 1 and legacy_rules.read_text() == approved_rules
    legacy_rules.unlink()
    cli_run('policy-refresh', control='policy-ready')
    assert rules.read_text() == staged_rules.read_text() == approved_rules
    # A first installation can also prepare a staging directory before the
    # active module exists, including when a preference backup requests fixed mode.
    rules.unlink()
    module.rmdir()
    previous.symlink_to(config)
    cli_run('policy-install', 'ksu', str(incoming))
    assert not os.path.lexists(previous) and json.loads(config.read_text())['fixed_sepolicy']
    assert staged_rules.read_text() == '# YukiZygisk fixed policy pending revalidation\n'
    module.mkdir()
    cli_run('policy-install', 'ksu', str(incoming), control='policy-ready')
    assert rules.read_text() == staged_rules.read_text() == approved_rules
    os.link(rules, rules.with_suffix('.rule.next'))  # Crash after retiring the intent.
    cli_run('policy-boot')
    assert rules.stat().st_nlink == 1 and rules.read_text() == approved_rules
    # Restoring the old single-directory journal cannot install its candidate.
    next_config = config.with_suffix('.json.next')
    next_config.write_text(config.read_text())
    os.link(next_config, config.with_suffix('.json.commit.v2'))
    legacy_candidate = legacy_rules.with_suffix('.rule.next')
    legacy_candidate.write_text('unverified restored rule\n')
    os.link(legacy_candidate, legacy_rules)
    assert rules.read_text() == staged_rules.read_text() == approved_rules
    assert not json.loads(cli_run('config', 'get').stdout)['fixed_sepolicy']
    assert not rules.exists() and not staged_rules.exists()
    assert legacy_rules.read_text() == 'unverified restored rule\n'
    legacy_rules.unlink()
    legacy_candidate.unlink()
    incoming.rmdir()
    cli_run('config', 'set', 'fixed_sepolicy', 'false')
    full_reboot()
    cli_run('policy-boot')
    cli_run('config', 'set', 'fixed_sepolicy', 'true', control='policy-ready')
    config.write_text('{"fixed_sepolicy":true}')
    cli_run('policy-boot')
    assert boot.read_bytes() == original
    config.chmod(0o664)
    rules.write_text('old fixed grant\n')
    before = (config.read_bytes(), rules.read_bytes())
    failed = cli_run('config', 'set', 'fixed_sepolicy', 'false', code=1)
    assert os.strerror(errno.EPERM) in failed.stderr
    assert before == (config.read_bytes(), rules.read_bytes())
    assert not list(config.parent.glob('yzconfig.json.commit*'))
    full_reboot()
    for contents in ('{"fixed_sepolicy":true}', '{"fixed_sepolicy":false}', '{'):
        config.write_text(contents)
        for command in (('policy-boot',), ('policy-install', 'ksu'), ('config', 'get')):
            cli_run(*command, code=1)
            assert config.read_text() == contents and rules.read_bytes() == before[1]
            assert not boot.exists()
    restore_source = build / 'restored-rule-source'
    restore_source.write_bytes(before[1])
    untrusted_config = config.read_bytes()
    for kind in ('writable', 'symlink', 'hardlink'):
        full_reboot()
        rules.unlink(missing_ok=True)
        if kind == 'symlink':
            rules.symlink_to(restore_source)
        elif kind == 'hardlink':
            restore_source.chmod(0o600)
            os.link(restore_source, rules)
        else:
            rules.write_bytes(before[1])
            rules.chmod(0o664)
        cli_run('policy-boot', code=1)
        assert config.read_bytes() == untrusted_config and config.stat().st_mode & 0o022
        assert not os.path.lexists(rules) and restore_source.read_bytes() == before[1]
        assert reboot_required.exists() and not boot.exists()
        full_reboot()
        cli_run('policy-boot', code=1)
        assert not reboot_required.exists()
    rules.write_bytes(before[1])
    rules.chmod(0o600)
    config.write_bytes(before[0])
    config.chmod(0o600)
    # Preserve internal rollback pins when JSON cannot be read. An additional
    # external link to that same inode must still withdraw both host copies.
    incoming.mkdir()
    cli_run('config', 'set', 'fixed_sepolicy', 'false', code=75, stop_before_publish=True)
    config.chmod(0o664)
    cli_run('policy-boot', code=1)
    assert rules.samefile(rules.with_suffix('.rule.previous'))
    backup_pin = build / 'external-rule-pin'
    os.link(rules, backup_pin)
    cli_run('policy-boot', code=1)
    assert not rules.exists() and not staged_rules.exists() and reboot_required.exists()
    assert backup_pin.read_bytes() == before[1] and config.read_bytes() == before[0]
    config.chmod(0o600)
    assert not json.loads(cli_run('config', 'get').stdout)['fixed_sepolicy']
    assert not staged_rules.exists() and backup_pin.read_bytes() == before[1]
    incoming.rmdir()
    rules.write_bytes(before[1])
    config.write_bytes(before[0])
    cli_run('config', 'set', 'fixed_sepolicy', 'false', code=75, stop_before_publish=True)
    config.with_suffix('.json.commit.v2').rename(config.with_suffix('.json.commit'))
    rules.with_suffix('.rule.switch').replace(rules)
    config.chmod(0o664)  # Simulate an old writer that already published the withdrawal.
    config.write_text('{"fixed_sepolicy":true,"untrusted":9}')
    recovered = json.loads(cli_run('config', 'get').stdout)
    assert not recovered['fixed_sepolicy'] and 'untrusted' not in recovered
    assert config.stat().st_mode & 0o022 == 0
    assert not rules.exists() and not list(config.parent.glob('yzconfig.json.commit*'))
    full_reboot()
    config.write_text('{"fixed_sepolicy":true}')
    config.chmod(0o664)  # Stop after recording the host scan, before repair.
    for byte in (b'a', b'b'):
        rules.write_bytes(byte * (128 * 1024 + 1))
        cli_run('policy-boot', code=1)
        assert reboot_required.exists() == (byte == b'b')
    config.chmod(0o600)
    for cold_boot in (False, True):
        full_reboot()
        config.write_text('{"fixed_sepolicy":true}')
        rules.write_text('old fixed grant\n')
        cli_run('config', 'set', 'fixed_sepolicy', 'false', code=75, stop_before_publish=True)
        rules.with_suffix('.rule.switch').replace(rules)
        if cold_boot:
            full_reboot()
        cli_run('policy-boot')
        assert not json.loads(cli_run('config', 'get').stdout)['fixed_sepolicy']
        assert not rules.exists() and reboot_required.exists() == (not cold_boot)
    for damaged, command in [(None, ('policy-boot',)), ('{', ('config', 'get')),
                             ('{"fixed_sepolicy":"invalid","custom":9}', ('policy-boot',))]:
        full_reboot()
        config.write_text('{}')
        cli_run('policy-boot')
        rules.write_text('# previously staged policy\n')
        if damaged is None:
            config.unlink()
        else:
            config.write_text(damaged)
        cli_run(*command)
        recovered = json.loads(config.read_text())
        assert not recovered['fixed_sepolicy'] and not rules.exists() and boot.read_bytes() == original
        assert not reboot_required.exists()  # A comment grants no permissions.
        if damaged and 'custom' in damaged:
            assert recovered['custom'] == 9
    for size in (0, 23, 128 * 1024 + 1):
        full_reboot()
        cli_run('policy-boot')
        config.write_text('{"fixed_sepolicy":true,"custom":9}')
        rules.write_bytes(b'x' * size)
        cli_run('config', 'set', 'fixed_sepolicy', 'false')
        recovered = json.loads(config.read_text())
        assert not rules.exists() and not recovered['fixed_sepolicy'] and recovered['custom'] == 9
        assert reboot_required.exists() == (size != 0)

    # If recovery loses config identity after publishing a withdrawal, the old
    # rule pin may be the last evidence of a host scan that missed its callback.
    full_reboot()
    cli_run('policy-boot')
    config.write_text('{"fixed_sepolicy":true}')
    rules.write_text('previous fixed grant\n')
    cli_run('config', 'set', 'fixed_sepolicy', 'false', code=75, stop_before_publish=True)
    rules.with_suffix('.rule.switch').replace(rules)
    restored = config.with_name('restored-config')
    restored.write_text('{"fixed_sepolicy":false,"custom":9}')
    restored.replace(config)
    assert json.loads(cli_run('config', 'get').stdout)['custom'] == 9
    assert reboot_required.exists() and not rules.exists()

    # A soft reboot can add fixed grants while the kernel stays in temporary mode.
    for remove_before_disable in (False, True):
        full_reboot()
        config.write_text('{}')
        cli_run('policy-boot')
        rules.write_text(approved_rules)
        config.write_text('{"fixed_sepolicy":true}')
        cli_run('policy-boot')
        assert boot.read_bytes() == original and not reboot_required.exists()
        if remove_before_disable:
            rules.unlink()
            cli_run('policy-boot')  # An empty rescan cannot undo the earlier grants.
        cli_run('config', 'set', 'fixed_sepolicy', 'false')
        assert reboot_required.is_file() and not rules.exists()
        cli_run('policy-boot')
        assert reboot_required.is_file() and boot.read_bytes() == original

    # The host scans the live rule before policy-boot or an earlier config repair.
    for damaged, first_command in ((None, ('policy-boot',)), ('{', ('config', 'get')),
                                   ('{"fixed_sepolicy":false}', ('policy-boot',))):
        full_reboot()
        if damaged is None:
            config.unlink()
        else:
            config.write_text(damaged)
        rules.write_text('previously loaded rules\n')
        if first_command == ('config', 'get'):
            dev.rmdir()
            cli_run(*first_command, code=1)
            assert rules.read_text() == 'previously loaded rules\n' and config.read_text() == damaged
            dev.mkdir()
        cli_run(*first_command)
        assert reboot_required.is_file() and not rules.exists()
        cli_run('policy-boot')
        cli_run('policy-boot')  # Soft reboot retains the notice and the selected mode.
        assert boot.read_bytes() == original and reboot_required.is_file()
        assert not json.loads(config.read_text())['fixed_sepolicy']
        full_reboot()
        rules.touch()  # A published empty withdrawal grants nothing.
        cli_run('policy-boot')
        assert boot.read_bytes() == original and not reboot_required.exists()

    # Stop the actual writer with a durable intent but before its rules rename.
    for replaced in (False, True):
        full_reboot()
        config.write_text('{"fixed_sepolicy":true,"custom":9}')
        rules.write_text('approved old rules\n')
        cli_run('config', 'set', 'fixed_sepolicy', 'false', code=75, stop_before_publish=True)
        previous_rules = rules.with_suffix('.rule.previous')
        assert previous_rules.samefile(rules)
        if replaced:
            backup = rules.with_name('restored.rule')
            backup.write_text('different rules\n')
            backup.replace(rules)
        recovered = json.loads(cli_run('config', 'get').stdout)
        assert recovered['fixed_sepolicy'] == (not replaced) and recovered['custom'] == 9
        assert rules.exists() == (not replaced) and not previous_rules.exists()
        if not replaced:
            assert rules.read_text() == 'approved old rules\n'

    # A withdrawal can be interrupted with an untrusted old file still live,
    # or with the staged inode made writable after its publication.
    for entry in ('writable', 'symlink', 'published-writable'):
        full_reboot()
        config.write_text('{"fixed_sepolicy":true,"custom":9}')
        rules.unlink(missing_ok=True)
        target = build / 'restore-source'
        target.write_text('original contents\n')
        if entry == 'symlink':
            rules.symlink_to(target)
        else:
            rules.write_text(approved_rules)
            if entry == 'writable':
                rules.chmod(0o664)
        cli_run('config', 'set', 'fixed_sepolicy', 'false', code=75, stop_before_publish=True)
        if entry == 'published-writable':
            rules.with_suffix('.rule.switch').replace(rules)
            rules.chmod(0o664)
        # Losing /dev state must not prevent recovery of the on-disk intent.
        full_reboot()
        cli_run('policy-boot')
        recovered = json.loads(cli_run('config', 'get').stdout)
        assert not recovered['fixed_sepolicy']
        assert recovered['custom'] == 9 and target.read_text() == 'original contents\n'
        assert not os.path.lexists(rules) and reboot_required.exists()
        assert not list(config.parent.glob('yzconfig.json.commit*'))
        assert not list(module.glob('sepolicy.rule.*'))
        cli_run('policy-boot')
        assert struct.unpack_from('=II', boot.read_bytes())[1] == 0

    # Recover on either side of the rules rename, including older and damaged journals.
    for phase in ('prepared', 'published', 'committed', 'replaced-rules',
                  'missing-rules', 'replaced-config', 'unproven-rollback', 'old-published',
                  'legacy-prepared', 'legacy-published'):
        full_reboot()
        old_settings = {'fixed_sepolicy': True, 'custom': 9}
        config.write_text(json.dumps(old_settings))
        rules.write_text(approved_rules)
        previous = config.with_suffix('.json.previous')
        previous_rules = rules.with_suffix('.rule.previous')
        next_config = config.with_suffix('.json.next')
        next_rules = rules.with_suffix('.rule.next')
        intent = config.with_suffix('.json.publish' if phase.startswith('legacy-') else '.json.commit')
        if not phase.startswith('legacy-'):
            os.link(config, previous)
            if phase not in ('unproven-rollback', 'old-published'):
                os.link(rules, previous_rules)
        next_config.write_text(json.dumps({**old_settings, 'custom': 10}))
        os.link(next_config, intent)
        if phase != 'missing-rules':
            next_rules.write_text(approved_rules.replace('test_daemon', 'next_daemon'))
            switch = rules.with_suffix('.rule.switch')
            os.link(next_rules, switch)
            if phase in ('published', 'committed', 'replaced-rules', 'old-published', 'legacy-published'):
                switch.replace(rules)
        if phase in ('committed', 'replaced-rules'):
            next_config.replace(config)
        if phase == 'replaced-rules':
            rules.unlink()
            rules.write_text('unverified rules\n')
        if phase == 'replaced-config':
            config.unlink()
            config.write_text(json.dumps({**old_settings, 'custom': 11}))
        valid = phase in ('prepared', 'published', 'committed', 'old-published', 'legacy-published')
        expected_custom = {'committed': 10, 'replaced-rules': 10, 'replaced-config': 11}.get(phase, 9)
        for _ in range(2):
            recovered = json.loads(cli_run('config', 'get').stdout)
            assert recovered['fixed_sepolicy'] == valid and rules.exists() == valid
            assert recovered['custom'] == expected_custom
        if valid:
            assert rules.read_text() == (approved_rules if phase == 'prepared' else
                                         approved_rules.replace('test_daemon', 'next_daemon'))
        assert not any(p.exists() for p in (previous, previous_rules, next_config, next_rules, intent))
        # A roll-forward with the old rule pinned can prove that a grant was removed.
        assert reboot_required.is_file() == (not valid or phase in ('published', 'committed'))
        cli_run('policy-boot')
        _, enabled = struct.unpack_from('=II', boot.read_bytes())
        assert enabled == int(valid)

    # An in-place restore keeps the inode. Pending config/rules must not
    # overwrite restored fields even when the old and new JSON have equal size.
    for legacy in (False, True):
        full_reboot()
        config.write_text('{"fixed_sepolicy":true,"custom":1}')
        rules.write_text(approved_rules)
        cli_run('config', 'set', 'fixed_sepolicy', 'false', code=75, stop_before_publish=True)
        previous = config.with_suffix('.json.previous')
        assert previous.read_bytes() == config.read_bytes() and not previous.samefile(config)
        if legacy:
            previous.unlink()
            os.link(config, previous)
        rules.with_suffix('.rule.switch').replace(rules)
        original_inode = config.stat().st_ino
        config.write_text('{"fixed_sepolicy":true,"custom":2}')
        assert config.stat().st_ino == original_inode
        current = json.loads(cli_run('config', 'get').stdout)
        assert not current['fixed_sepolicy'] and current['custom'] == 2
        assert reboot_required.exists() and not rules.exists() and not previous.exists()
        cli_run('policy-boot')

    # A JSON-only restore cannot endorse extra or malformed rules scanned by the host.
    for restore in ('independent-first', 'type-last',
                    'attribute-first', 'extra-statement', 'semicolon'):
        full_reboot()
        config.write_text('{"custom":7}')
        cli_run('config', 'set', 'fixed_sepolicy', 'true', control='policy-ready')
        full_reboot()
        restored = json.loads(config.read_text())
        if restore == 'extra-statement':
            with rules.open('a') as stream:
                stream.write('allow obsolete obsolete process execmem\n')
        if restore == 'semicolon':
            with rules.open('a') as stream:
                stream.write('# metadata; unrecognized statement\n')
        if restore in ('independent-first', 'type-last', 'attribute-first'):
            lines = rules.read_text().splitlines(keepends=True)
            index = next(i for i, line in enumerate(lines) if line.startswith('type '))
            if restore == 'type-last':
                lines.append(lines.pop(index))
            elif restore == 'attribute-first':
                lines[index], lines[index + 1] = lines[index + 1], lines[index]
            else:
                independent = next(i for i, line in enumerate(lines) if line.startswith('allow ')
                                   and ' yukizygisk_file ' not in line)
                lines.insert(index, lines.pop(independent))
            rules.write_text(''.join(lines))
        clean = restore == 'independent-first'
        previous = (rules.stat().st_ino, rules.read_bytes(), config.read_bytes())
        result = cli_run('policy-install', 'ksu', code=0 if clean else 1)
        if not clean:
            assert os.strerror(errno.ESTALE) in result.stderr
        assert (rules.stat().st_ino, rules.read_bytes(), config.read_bytes()) == previous
        cli_run('policy-boot')
        assert struct.unpack_from('=II', boot.read_bytes())[1] == int(clean)
        assert json.loads(config.read_text()) == {**restored, 'fixed_sepolicy': clean}
        assert rules.exists() == clean and reboot_required.exists() != clean
        cli_run('policy-boot')
        assert reboot_required.exists() != clean
        full_reboot()
        cli_run('policy-boot')
        assert not reboot_required.exists() and rules.exists() == clean
    full_reboot()
    config.write_text('{}')
    rules.write_text('# metadata; unrecognized statement\n')
    cli_run('policy-boot')
    assert not rules.exists() and reboot_required.exists()

    # Changing the optional class in either direction defers this boot without
    # rewriting the administrator's config or publishing new grants offline.
    memfd = context_node.parent / 'class/memfd_file'
    memfd.parent.mkdir()
    preference = b'{ "custom":7, "fixed_sepolicy": true }\n'
    for was_present in (False, True):
        for install_first in (False, True):
            full_reboot()
            if was_present:
                memfd.touch()
            else:
                memfd.unlink(missing_ok=True)
            config.write_bytes(preference)
            cli_run('policy-install', 'ksu', control='policy-ready')
            assert (' memfd_file ' in rules.read_text()) == was_present
            config.write_bytes(preference)
            if was_present:
                memfd.unlink()
            else:
                memfd.touch()
            if install_first:
                cli_run('policy-install', 'ksu')
            cli_run('policy-boot')
            assert config.read_bytes() == preference and reboot_required.exists()
            deferred = boot.read_bytes()
            assert struct.unpack_from('=II', deferred)[1] == 0
            inert = rules.read_text()
            assert inert and all(line.startswith('#') for line in inert.splitlines())
            cli_run('policy-refresh', control='identity-busy', code=1)
            cli_run('policy-install', 'ksu')
            assert rules.read_text() == inert and config.read_bytes() == preference
            full_reboot()
            cli_run('policy-boot')
            assert boot.read_bytes() == deferred and not reboot_required.exists()
            cli_run('policy-refresh', control='policy-ready')
            assert config.read_bytes() == preference and 'allow domain ' in rules.read_text()
            assert (' memfd_file ' in rules.read_text()) != was_present
            cli_run('policy-boot')
            assert boot.read_bytes() == deferred
            full_reboot()
            cli_run('policy-boot')
            assert struct.unpack_from('=II', boot.read_bytes())[1] == 1
    memfd.unlink(missing_ok=True)
    incoming.mkdir()
    for retired in ('test_daemon',):
        full_reboot()
        config.write_bytes(preference)
        cli_run('policy-install', 'ksu', control='policy-ready')
        approved = rules.read_bytes()
        context_node.unlink()
        cli_run('policy-boot', code=1)
        assert not boot.exists() and rules.read_bytes() == approved
        context_node.touch()
        cli_run('policy-boot', reject_context=retired)
        assert struct.unpack_from('=II', boot.read_bytes())[1] == 0 and reboot_required.exists()
        assert config.read_bytes() == preference and staged.read_bytes() == rules.read_bytes()
        assert rules.read_text() == '# YukiZygisk fixed policy pending revalidation\n'
        full_reboot()
        staged.write_bytes(approved)
        cli_run('policy-boot', reject_context=retired)
        assert struct.unpack_from('=II', boot.read_bytes())[1] == 0 and not reboot_required.exists()
        assert staged.read_bytes() == rules.read_bytes()
        staged.write_bytes(approved)
        cli_run('policy-refresh', control='policy-ready', reject_context=retired, code=1)
        assert rules.read_bytes() == staged.read_bytes() and 'allow ' not in rules.read_text()
        cli_run('policy-refresh', control='policy-ready')
        assert rules.read_bytes() == staged.read_bytes() == approved
    staged.unlink()
    incoming.rmdir()
    boot.write_bytes(bytes(len(original)))
    cli_run('policy-boot', code=1)
    full_reboot()
    config.write_text('{')
    rules.write_text('rules loaded before deferred activation\n')
    cli_run('policy-boot')
    for control, error in ((None, 'cannot open YukiZygisk kernel control session'),
                           ('denied', os.strerror(errno.EACCES)),
                           ('status-failed', 'cannot query kernel runtime state')):
        failed = cli_run('status', '--json', code=1, control=control)
        status = json.loads(failed.stdout)
        assert not status['kernel_alive'] and not status['late_load_pending']
        assert status['policy']['reboot_required'] and not status['policy']['supported']
        assert error in status['error'] and status['error'] in failed.stderr
        failed = cli_run('status', code=1, control=control)
        assert 'Fully reboot' in failed.stdout and error in failed.stderr
    rejection = cli_run('status', control='status-rejected').stdout
    assert 'error -13' in rejection and 'activation is pending' not in rejection
    activation.mkdir(mode=0o700)
    pending = activation / 'pending'
    pending.touch(mode=0o600)
    pending_status = json.loads(cli_run('status', '--json').stdout)
    assert pending_status['late_load_pending'] and pending_status['policy']['reboot_required']
    assert 'Fully reboot' in cli_run('status').stdout
    detail = 'source=' + 's' * 64 + ' target=test_daemon class=fd missing_av=0x4'
    rejected = cli_run('status', control='status-rejected').stdout
    assert 'error -13' in rejected and detail in rejected
    assert 'activation is pending' in rejected and 'soft-reboot' not in rejected and 'Fully reboot' in rejected
    reported = json.loads(cli_run('status', '--json', control='status-rejected').stdout)
    assert reported['late_load_pending'] and reported['policy']['error'] == -errno.EACCES
    assert reported['policy']['missing_av'] == 4 and reported['policy']['missing_source'] == 's' * 64
    for control in ('status-healthy', 'status-legacy'):
        assert 'please soft-reboot' in cli_run('status', control=control).stdout
    full_reboot()
    cli_run('policy-boot')
    assert not json.loads(cli_run('status', '--json').stdout)['policy']['reboot_required']
    late_module = build / 'module'
    (late_module / 'bin').mkdir(parents=True)
    (late_module / 'bin/yzctl').symlink_to(cli)
    action = shutil.copy(root / 'module/action.sh', late_module)
    output = subprocess.check_output(['sh', action], text=True, env={**os.environ, 'YZ_TEST_CONTROL': 'status-rejected'})
    assert detail in output and 'soft-reboot' not in output and 'kernel control is unavailable' not in output
    shutil.copy(root / 'module/late-load.sh', late_module)
    (late_module / 'late-load-common.sh').write_text((root / 'module/late-load-common.sh').read_text()
        .replace('/dev/yukizygisk-late-load', str(activation)))
    for name in ('module.prop', 'module.prop.orig'):
        shutil.copyfile(root / 'module/module.prop', late_module / name)
    late_env = {**os.environ, 'KSU_LATE_LOAD': '1', 'YZ_TEST_SELINUX_CONTEXT': str(context_node)}
    late_script = ['sh', str(late_module / 'late-load.sh')]
    config.chmod(0o664)
    failure = subprocess.run(late_script, text=True, capture_output=True, env=late_env, timeout=10)
    assert failure.returncode == 1 and os.strerror(errno.EPERM) in failure.stderr
    for control in (None, 'status-healthy'):
        code = 0 if control else 1
        result = json.loads(cli_run('status', '--json', control=control, code=code).stdout)
        assert result['late_load_pending'] and os.strerror(errno.EPERM) in result['late_load_error']
        human = cli_run('status', control=control, code=code).stdout
        assert os.strerror(errno.EPERM) in human and 'soft-reboot' not in human
    assert os.strerror(errno.EPERM) in cli_run('ensure-daemon', code=1).stderr
    config.chmod(0o600)
    cli_run('policy-boot')
    assert not (activation / 'policy-error').exists()
    config.chmod(0o664)
    cli_run('policy-boot', code=1)
    assert os.strerror(errno.EPERM) in cli_run('status', '--json', code=1).stdout
    config.chmod(0o600)
    subprocess.run(late_script, check=True, env=late_env, timeout=10)
    assert 'late_load_error' not in json.loads(cli_run('status', '--json').stdout)
    assert 'soft-reboot' in cli_run('status').stdout
    launch_error = activation / 'launch-policy-error'
    cli_run('policy-launch-failed', control='status-rejected')
    assert detail in launch_error.read_text() and 'error -13' in launch_error.read_text()
    for control in (None, 'status-legacy'):
        cli_run('policy-launch-failed', control=control)
        assert detail in cli_run('ensure-daemon', code=1).stderr
    for script in (late_script, ['sh', shutil.copy(root / 'module/boot-completed.sh', late_module)]):
        stage = subprocess.run(script, check=True, text=True, capture_output=True, env=late_env)
        assert 'soft-reboot' not in stage.stdout
        description = (late_module / 'module.prop').read_text()
        assert detail in description and 'soft-reboot' not in description
    rejected = json.loads(cli_run('status', '--json', code=1).stdout)
    assert rejected['late_load_pending'] and detail in rejected['late_load_error']
    cli_run('policy-launch-failed', control='status-healthy')
    assert not launch_error.exists() and 'soft-reboot' in cli_run('status').stdout
    replacement = build / 'proc/43/attr/current'
    replacement.parent.mkdir(parents=True)
    replacement.write_text('u:r:replacement_daemon:s0')
    config.write_text('{"fixed_sepolicy":true}')
    for control in ('identity-busy-first', 'identity-busy-second', 'identity-replace-on-validate'):
        rules.unlink(missing_ok=True)
        cli_run('policy-install', 'ksu', control=control)
        assert rules.read_text().splitlines()[0] == '# YukiZygisk daemon ksu replacement_daemon'
    # Even an approved offline copy must not override live contention or a changed identity.
    approved = rules.read_bytes()
    for control, error in (('identity-changed', errno.ESTALE), ('identity-busy', errno.EAGAIN)):
        assert os.strerror(error) in cli_run('policy-install', 'ksu', code=1, control=control).stderr
        assert rules.read_bytes() == approved
    incoming.mkdir()
    cli_run('policy-install', 'ksu', str(incoming), control='policy-ready')
    before = (config.read_bytes(), rules.stat().st_ino, rules.read_bytes())
    for control, error in (('identity-reject-replacement', errno.ENETUNREACH),
                           ('identity-churn', errno.ESTALE), ('identity-before-publish', errno.ESTALE)):
        if control == 'identity-before-publish':
            staged.write_text('# stale staged rules\n')
        failed = cli_run('config', 'set', 'fixed_sepolicy', 'true', 'denylist_mode', '1',
                         control=control, code=1)
        assert os.strerror(error) in failed.stderr
        assert (config.read_bytes(), rules.stat().st_ino, rules.read_bytes()) == before
        if control == 'identity-before-publish':
            assert staged.read_bytes() == before[2]
        assert not config.with_suffix('.json.commit.v2').exists()
    cli_run('config', 'set', 'fixed_sepolicy', 'true', 'denylist_mode', '1',
            control='identity-replace-on-validate')
    assert json.loads(config.read_text())['denylist_mode'] == 1
    assert rules.read_text().splitlines()[0] == '# YukiZygisk daemon ksu replacement_daemon'
    assert staged.read_bytes() == rules.read_bytes() and 'allow domain ' in rules.read_text()
    # The first installation publishes directly to the supplied directory.
    module.rename(old_module)
    staged.write_text('# previous installer rule\n')
    cli_run('policy-install', 'ksu', str(incoming), control='identity-installer-write', code=1)
    assert staged.read_text() == '# previous installer rule\n'
    assert not (incoming / '.sepolicy.rule.install').exists()
    old_module.rename(module)
    staged.unlink()
    incoming.rmdir()
    for install in (False, True):
        full_reboot()
        config.write_text('{}')
        rules.unlink(missing_ok=True)
        cli_run('policy-boot')
        for command in [('config', 'set', 'fixed_sepolicy', 'true'),
                        ('policy-install', 'ksu')]:
            if command[0] == 'policy-install':
                config.write_text('{"fixed_sepolicy":true}')
            failed = cli_run(*command, code=1, control='identity-busy')
            assert os.strerror(errno.EAGAIN) in failed.stderr
            assert 'mount isolation' not in failed.stderr and not rules.exists()
        cli_run('config', 'set', 'fixed_sepolicy', 'true', control='policy-ready')
        cli_run('policy-boot')
        if install:
            pending.rename(activation / 'active')
        subprocess.run(late_script, check=True, timeout=10, env=late_env)
        scan = dev / 'policy.scan'
        assert scan.read_bytes() == rules.read_bytes()
        cli_run('config', 'set', 'fixed_sepolicy', 'false', code=75,
                control='policy-ready', stop_before_publish=True)
        assert json.loads(cli_run('config', 'get').stdout)['fixed_sepolicy']
        assert not reboot_required.exists()
        if install:
            saved_config = json.loads(config.read_text())
            saved_config['fixed_sepolicy'] = False
            config.write_text(json.dumps(saved_config, indent=2) + '\n')
            original_config = (config.stat().st_ino, config.read_bytes())
            cli_run('policy-install', 'ksu', control='policy-ready')
            assert (config.stat().st_ino, config.read_bytes()) == original_config
        else:
            cli_run('config', 'set', 'fixed_sepolicy', 'false', control='policy-ready')
        assert not rules.exists()
        offline_status = cli_run('status', '--json', code=1 if install else 0)
        assert json.loads(offline_status.stdout)['policy']['reboot_required']
        cli_run('policy-boot')
        assert reboot_required.is_file()
        full_reboot()
        cli_run('policy-boot')
        assert not reboot_required.exists()
        if install:
            (activation / 'active').rename(pending)

    # A config exactly at the read limit can be published. One more byte must
    # be rejected before a reload marker, rules rename or journal is published.
    full_reboot()
    config.write_text('{}')
    rules.unlink(missing_ok=True)
    cli_run('policy-boot')
    limit = 512 * 1024
    def config_bytes(value):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(', ', ':')).encode()
    candidate = {**json.loads(cli_run('config', 'get').stdout),
                 'fixed_sepolicy': True, 'yukilinker': True, 'custom': '界'}
    candidate['custom'] += 'x' * (limit - len(config_bytes(candidate)))
    initial = {k: v for k, v in candidate.items() if k != 'yukilinker'}
    initial['fixed_sepolicy'] = False
    config.write_bytes(config_bytes(initial))
    cli_run('config', 'set', 'fixed_sepolicy', 'true', 'yukilinker', 'true', control='policy-ready')
    assert config.read_bytes() == config_bytes(candidate) and config.stat().st_size == limit
    cli_run('policy-boot')
    installed = (config.stat().st_ino, rules.stat().st_ino, rules.read_bytes())
    for args in [('fixed_sepolicy', 'true', 'yukilinker', 'false'), ('yukilinker', 'false')]:
        failed = cli_run('config', 'set', *args, control='policy-ready', code=1)
        assert os.strerror(errno.EFBIG) in failed.stderr
        assert json.loads(cli_run('config', 'get').stdout) == candidate
        assert (config.stat().st_ino, rules.stat().st_ino, rules.read_bytes()) == installed
        assert config.with_suffix('.json.lock').stat().st_size == 0 and not reboot_required.exists()
        assert set(config.parent.iterdir()) == {config, config.with_suffix('.json.lock')}
        assert set(module.iterdir()) == {rules}
    cli_run('config', 'set', 'fixed_sepolicy', 'false')
    assert json.loads(cli_run('config', 'get').stdout) == {**candidate, 'fixed_sepolicy': False}
    assert config.stat().st_size <= limit and not rules.exists() and reboot_required.exists()
    full_reboot()
    cli_run('policy-boot')
    assert not reboot_required.exists() and struct.unpack_from('=II', boot.read_bytes())[1] == 0
    cli_run('config', 'set', 'fixed_sepolicy', 'true', control='policy-ready')

    # Older writers could leave an oversized intent on either side of the
    # rules rename. Restore a proven old pair or withdraw an unrelated pin.
    for phase in ('prepared', 'published', 'replaced-pin'):
        full_reboot()
        memfd.unlink(missing_ok=True)
        cli_run('config', 'set', 'fixed_sepolicy', 'true', control='policy-ready')
        old_config = config.read_bytes()
        old_rules = (rules.stat().st_ino, rules.read_bytes())
        memfd.touch()
        cli_run('config', 'set', 'fixed_sepolicy', 'true', 'denylist_mode', '1',
                control='policy-ready', code=75, stop_before_publish=True)
        memfd.unlink()
        next_config = config.with_suffix('.json.next')
        staged = json.loads(next_config.read_text())
        staged['custom'] += 'x' * (limit + 1 - len(config_bytes(staged)))
        next_config.write_bytes(config_bytes(staged))
        assert next_config.stat().st_size == limit + 1
        if phase != 'prepared':
            rules.with_suffix('.rule.switch').replace(rules)
        if phase == 'replaced-pin':
            pin = rules.with_suffix('.rule.previous')
            pin.unlink()
            pin.write_text('unrelated rules\n')
            saved = json.loads(old_config)
            saved['custom'] += 'x' * (limit - len(old_config))
            config.write_bytes(config_bytes(saved))
        cli_run('policy-boot')
        recovered = json.loads(cli_run('config', 'get').stdout)
        if phase == 'replaced-pin':
            assert recovered == {**saved, 'fixed_sepolicy': False} and not rules.exists()
            assert config.stat().st_size <= limit
        else:
            assert config.read_bytes() == old_config
            assert (rules.stat().st_ino, rules.read_bytes()) == old_rules
        assert reboot_required.exists() == (phase != 'prepared')
        assert set(config.parent.iterdir()) == {config, config.with_suffix('.json.lock')}
        assert set(module.iterdir()) == ({rules} if rules.exists() else set())

    # Reformatting an opaque array alone may exceed the limit. Disabling
    # must preserve its contents even when omitting defaults cannot make it fit.
    full_reboot()
    dense = {'fixed_sepolicy': True, 'custom': {'values': [0.1] * 256,
             'fixed_sepolicy': True, 'padding': ''}}
    dense['custom']['padding'] = 'x' * (limit - len(json.dumps(dense, separators=(',', ':'))))
    config.write_text(json.dumps(dense, separators=(',', ':')))
    assert config.stat().st_size == limit
    rules.write_text(approved_rules)
    cli_run('policy-boot')
    cli_run('config', 'set', 'fixed_sepolicy', 'false')
    disabled = json.loads(cli_run('config', 'get').stdout)
    assert not disabled['fixed_sepolicy'] and disabled['custom'] == dense['custom']
    assert not rules.exists() and reboot_required.exists() and config.stat().st_size <= limit

    # An old writer could leave the active file over the limit. Installation
    # and boot must preserve every byte and withdraw rules before using defaults.
    config.write_text('{}')
    defaults = json.loads(cli_run('config', 'get').stdout)
    for index, command in enumerate((('policy-install', 'ksu'), ('policy-boot',), ('config', 'get'))):
        full_reboot()
        rules.write_text('previous fixed grant\n')
        if index == 2:
            config.write_text('{"fixed_sepolicy":true}')
            cli_run('config', 'set', 'fixed_sepolicy', 'false', code=75, stop_before_publish=True)
        original_bytes = config_bytes({'custom': str(index) * limit, 'fixed_sepolicy': True})
        config.write_bytes(original_bytes)
        backup = config.with_name('yzconfig.json.oversized' + (f'.{index}' if index else ''))
        if index == 2:
            hidden_dev = dev.rename(build / 'unavailable-dev')
            cli_run(*command, code=1)
            assert backup.samefile(config) and rules.exists()
            hidden_dev.rename(dev)
        result = cli_run(*command)
        assert str(backup) in result.stderr and backup.read_bytes() == original_bytes
        assert not backup.samefile(config)
        assert not rules.exists() and reboot_required.exists()
        assert json.loads(cli_run('config', 'get').stdout) == defaults
        cli_run('policy-boot')
        assert struct.unpack_from('=II', boot.read_bytes())[1] == 0
        assert len(list(config.parent.glob('yzconfig.json.oversized*'))) == index + 1
        assert not list(config.parent.glob('yzconfig.json.commit*'))
    config.write_bytes(original_bytes)
    config.chmod(0o666)
    cli_run('policy-install', 'ksu', code=1)
    assert config.read_bytes() == original_bytes and len(list(config.parent.glob('*.oversized*'))) == 3
    config.chmod(0o600)

    config.write_text('{}')
    full_reboot()
    cli_run('policy-boot')
    assert 'activation is deferred' in cli_run('ensure-daemon', code=1).stderr
    cli_run('reload', code=1)  # An explicit reload must still report absence.
    assert json.loads(cli_run('config', 'get').stdout)['anonymous_memory']
    saved = cli_run('config', 'set', 'anonymous_memory', 'false')
    assert 'applies when late-load activates' in saved.stdout
    assert not saved.stderr
    assert not json.loads(cli_run('config', 'get').stdout)['anonymous_memory']
    mixed = cli_run('config', 'set', 'fixed_sepolicy', 'false', 'denylist_mode', '1')
    assert 'applies when late-load activates' in mixed.stdout and 'Fully reboot' in mixed.stdout
    settings_before = json.loads(config.read_text())
    config.write_text(json.dumps({**settings_before, 'fixed_sepolicy': True, 'denylist_mode': 2}))
    rules.write_text('approved fixed rules\n')
    rules_inode = rules.stat().st_ino
    saved = cli_run('config', 'set', 'denylist_mode', '0')
    assert 'applies when late-load activates' in saved.stdout
    current = json.loads(config.read_text())
    assert current['fixed_sepolicy'] and current['denylist_mode'] == 0
    assert rules.stat().st_ino == rules_inode and rules.read_text() == 'approved fixed rules\n'
    cli_run('config', 'set', 'fixed_zn_domains', '["system_server"]', code=1)
    assert json.loads(config.read_text()) == current
    # Startup can leave a ready daemon alive without consuming pending. Saving
    # must notify that daemon, which the next startup can reuse without re-exec.
    saved = cli_run('config', 'set', 'anonymous_memory', 'true',
                    'denylist_mode', '2', control='available')
    assert 'reload signalled' in saved.stdout
    assert not saved.stderr
    snapshots = [json.loads(line) for line in reload_trace.read_text().splitlines()]
    assert len(snapshots) == 1
    assert snapshots[0]['anonymous_memory'] and snapshots[0]['denylist_mode'] == 2
    assert pending.is_file()
    cli_run('config', 'set', 'denylist_mode', 'invalid', code=1, control='available')
    assert not reload_trace.exists()
    failed = cli_run('config', 'set', 'anonymous_memory', 'false',
                     code=1, control='reload-failed')
    assert 'kernel reload failed' in failed.stderr
    assert not json.loads(cli_run('config', 'get').stdout)['anonymous_memory']
    denied = cli_run('config', 'set', 'anonymous_memory', 'true',
                     code=1, control='denied')
    assert 'cannot open YukiZygisk kernel control session' in denied.stderr
    pending.chmod(0o666)
    cli_run('status', '--json', code=1)
    cli_run('config', 'set', 'anonymous_memory', 'true', code=1)
    pending.chmod(0o600)
    pending.rename(activation / 'active')
    cli_run('config', 'set', 'anonymous_memory', 'false', control='available')
    assert not json.loads(reload_trace.read_text())['anonymous_memory']
    cli_run('config', 'set', 'anonymous_memory', 'false', code=1)
    cli_run('status', '--json', code=1)
    print('PASS: pending CLI/config persistence, live-daemon reload, recovery guard and reload errors')
    replay = build / 'crash_protection_test'
    run(compiler, *flags, '-I' + str(build), str(root / 'userspace/zygisk/tests/crash_protection_test.cpp'),
        str(root / 'userspace/zygisk/daemon/crash_monitor.cpp'),
        '-Wl,--wrap=flock', '-Wl,--wrap=fsync', '-o', str(replay))
    run(str(replay))
    fixture = os.environ.get('YZ_TOMBSTONE_FIXTURE')
    if fixture:
        run(str(replay), fixture)
    source = build / 'netlink_test.cpp'
    source.write_text(netlink)
    binary = build / 'netlink_test'
    run(compiler, *flags, str(source), '-o', str(binary))
    run(str(binary))
    endpoint = root / 'userspace/zygisk/endpoint.cpp'
    binary = build / 'endpoint_test'
    run(compiler, *flags, '-pthread',
        str(root / 'userspace/zygisk/tests/endpoint_test.cpp'), str(endpoint),
        '-Wl,--wrap=connect', '-o', str(binary))
    run(str(binary))
    load_config = root / 'userspace/zygisk/tests/load_config_test.cpp'
    if load_config.is_file():
        binary = build / 'load_config_test'
        run(compiler, *flags, '-pthread', str(load_config), str(endpoint), '-o', str(binary))
        run(str(binary))
