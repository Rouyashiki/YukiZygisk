# SPDX-License-Identifier: Apache-2.0
#
# YukiZygisk - Host regression test runner.
#
# License: Apache-2.0
#
# Author: Anatdx

import os
import json
from pathlib import Path
import subprocess
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
with tempfile.TemporaryDirectory(prefix='yz-host-tests-') as temporary:
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
    cli_source = build / 'yzctl-main.cpp'
    cli_source.write_text((root / 'userspace/yzctl/main.cpp').read_text().replace(
        '/data/adb/yukizygisk/yzconfig.json', str(config)))
    cli = build / 'yzctl'
    run(compiler, '-I' + str(include), *flags, '-pthread',
        '-I' + str(root / 'userspace/yzctl'), '-I' + str(root / 'userspace/common'),
        '-I' + str(root / 'userspace/zygisk/daemon'), str(cli_source),
        str(root / 'userspace/zygisk/tests/config_reload_control.cpp'),
        *[str(root / name) for name in (
            'userspace/yzctl/status.cpp', 'userspace/yzctl/host.cpp',
            'userspace/yzctl/health.cpp', 'userspace/zygisk/endpoint.cpp',
            'userspace/zygisk/daemon/module_description.cpp')],
        '-Wl,--wrap=syscall', '-Wl,--wrap=ioctl', '-o', str(cli))

    reload_trace = build / 'reload-events.jsonl'

    def cli_run(*args, code=0, control=None):
        reload_trace.unlink(missing_ok=True)
        environment = os.environ.copy()
        environment.pop('YZ_TEST_CONTROL', None)
        if control:
            environment.update(YZ_TEST_CONTROL=control, YZ_TEST_CONFIG=str(config),
                               YZ_TEST_RELOAD_TRACE=str(reload_trace))
        result = subprocess.run([str(cli), *args], text=True, capture_output=True,
                                timeout=10, env=environment)
        assert result.returncode == code, (args, result.returncode, result.stdout, result.stderr)
        return result

    cli_run('status', '--json', code=1)
    activation.mkdir(mode=0o700)
    pending = activation / 'pending'
    pending.touch(mode=0o600)
    assert json.loads(cli_run('status', '--json').stdout)['late_load_pending']
    assert 'activation is deferred' in cli_run('ensure-daemon', code=1).stderr
    cli_run('reload', code=1)  # An explicit reload must still report absence.
    assert json.loads(cli_run('config', 'get').stdout)['anonymous_memory']
    saved = cli_run('config', 'set', 'anonymous_memory', 'false')
    assert 'applies when late-load activates' in saved.stdout
    assert not saved.stderr
    assert not json.loads(cli_run('config', 'get').stdout)['anonymous_memory']
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
    run(compiler, *flags, str(root / 'userspace/zygisk/tests/crash_protection_test.cpp'),
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
