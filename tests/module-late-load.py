#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# YukiZygisk - Host regression tests for late-load stage ordering and failures.
#
# License: Apache-2.0
#
# Author: Anatdx

"""Run real module scripts with stub Android commands and host flock in a temp tree."""

from __future__ import annotations

import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import tempfile
import time
import unittest


REPO = Path(__file__).resolve().parents[1]


class LateLoadTests(unittest.TestCase):
    shell_name = "dash"

    @classmethod
    def setUpClass(cls) -> None:
        if os.name != "posix":
            raise unittest.SkipTest("run with Linux/WSL Python, dash and BusyBox")
        cls.shell = shutil.which(cls.shell_name)
        if not cls.shell:
            raise RuntimeError(f"missing required shell: {cls.shell_name}")
        if not shutil.which("flock"):
            raise RuntimeError("missing required host tool: flock (util-linux)")

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="yz late-load ")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.module = self.root / "module"
        self.base = self.root / "data/adb/yukizygisk"
        self.state = self.root / "dev/yukizygisk-late-load"
        self.commands = self.root / "commands"
        self.events = self.root / "events"
        self.events.touch()
        self.state.parent.mkdir()
        self.commands.mkdir()
        (self.module / "bin").mkdir(parents=True)
        cleanup = self.root / "data/adb/service.d/.yz_cleanup.sh"
        cleanup.parent.mkdir(parents=True)
        cleanup.touch()
        (self.root / "proc-modules").touch()
        for name in ("post-fs-data.sh", "late-load.sh", "late-load-common.sh",
                     "boot-completed.sh", "action.sh"):
            text = (REPO / "module" / name).read_text()
            # Redirect fixed Android locations only; leave control flow intact.
            text = text.replace("/data/adb", str(self.root / "data/adb"))
            text = text.replace("/dev/yukizygisk-late-load", str(self.state))
            text = text.replace("/proc/modules", str(self.root / "proc-modules"))
            text = text.replace("/system/bin/env", shutil.which("env"))
            (self.module / name).write_text(text)

        (self.commands / "sh").symlink_to(self.shell)
        self.write_command(self.module / "bin/viola", r'''
[ -z "${LD_LIBRARY_PATH+x}${UNTRUSTED_FIXTURE+x}" ] || exit 80
[ ! -e /proc/$$/fd/9 ] || exit 81
guarded=false
case "${4:-}:${5:-}" in
    --runtime-guard:stopped) guarded=true ;;
    :) ;;
    *) exit 82 ;;
esac
[ ! -f "$fixture/dev/yukizygisk-late-load/pending" ] || $guarded || exit 83
printf 'viola %s\n' "$1" >> "$fixture/events"
[ ! -e "$fixture/$1.fail" ] || exit 1
pause_launch() {
    [ -e "$fixture/pause-$1" ] || return 0
    : > "$fixture/launch.entered"
    while [ -e "$fixture/pause-$1" ]; do /bin/sleep 0.01; done
}
if [ "$1" = launch ]; then
    pause_launch before
    # The native guard itself is exercised by tests/viola. This boundary
    # double checks that the script requests it and preserves pending on refusal.
    if $guarded; then
        [ "$(/bin/cat "$fixture/properties/sys.boot_completed")" = 0 ] &&
            [ "$(/bin/cat "$fixture/properties/init.svc.zygote")" = stopped ] || exit 1
    fi
    : > "$fixture/kernel.ready"
    if [ ! -e "$fixture/daemon.ready" ]; then
        printf 'daemon start\n' >> "$fixture/starts"
        : > "$fixture/daemon.ready"
    fi
    pause_launch after
fi
exit 0
''')
        self.write_command(self.module / "bin/yzctl", r'''
[ "$1" != description ] || {
    printf '%s\n' "$2" > "$fixture/description"
    exit 0
}
[ "$1" != status ] || {
    printf 'query\n' >> "$fixture/status-queries"
    if [ -f "$fixture/dev/yukizygisk-late-load/pending" ]; then
        echo 'After late-load finishes, manually soft-reboot from KernelSU to activate injection.'
        exit 0
    fi
    [ -f "$fixture/kernel.ready" ] && [ ! -e "$fixture/status.fail" ]
    exit $?
}
exit 0
''')
        self.write_command(self.commands / "getprop", r'''
cat "$fixture/properties/$1" 2>/dev/null || true
''')
        # Model Android ownership without requiring root on the host. Limit
        # the stub to the state directory's owner query; other calls must fail.
        (self.root / "state-owner").write_text("0\n")
        self.write_command(self.commands / "stat", r'''
[ "$#" -eq 3 ] && [ "$1" = -c ] && [ "$2" = %u ] &&
    [ "$3" = "$fixture/dev/yukizygisk-late-load" ] || exit 84
cat "$fixture/state-owner"
''')
        for name in ("setprop", "reboot", "stop", "start", "killall", "rmmod"):
            self.write_command(self.commands / name, r'''
printf 'unexpected runtime control: %s %s\n' "${0##*/}" "$*" >> "$fixture/events"
exit 99
''')
        self.environment = {
            "PATH": str(self.commands) + os.pathsep + os.defpath,
            "KSU_LATE_LOAD": "1",
            "LD_LIBRARY_PATH": str(self.root / "untrusted"),
            "UNTRUSTED_FIXTURE": "must-not-reach-viola",
        }
        (self.root / "properties").mkdir()
        self.property("ro.zygote", "zygote64")
        self.start_runtime()

    def property(self, name: str, value: str) -> None:
        (self.root / "properties" / name).write_text(value + "\n")

    def start_runtime(self) -> None:
        self.property("sys.boot_completed", "1")
        self.property("init.svc.zygote", "running")

    def stop_runtime(self) -> None:
        self.property("sys.boot_completed", "0")
        self.property("init.svc.zygote", "stopped")

    def write_command(self, path: Path, text: str) -> None:
        path.write_text("#!/bin/sh\nfixture=" + shlex.quote(str(self.root)) + "\n" + text)
        path.chmod(0o755)

    def run_stage(self, name: str, *args: str, expected: int = 0) -> subprocess.CompletedProcess:
        result = subprocess.run(
            [str(self.commands / "sh"), str(self.module / name), *args],
            env=self.environment, capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def trace(self) -> list[str]:
        return self.events.read_text().splitlines()

    def start_count(self) -> int:
        starts = self.root / "starts"
        return len(starts.read_text().splitlines()) if starts.exists() else 0

    def start_stage(self, name: str = "post-fs-data.sh") -> subprocess.Popen:
        process = subprocess.Popen(
            [str(self.commands / "sh"), str(self.module / name)],
            env=self.environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
        )
        self.addCleanup(self.stop_stage, process)
        return process

    @staticmethod
    def stop_stage(process: subprocess.Popen) -> None:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.communicate(timeout=5)

    def wait_for_launch(self, process: subprocess.Popen) -> None:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if (self.root / "launch.entered").exists():
                return
            self.assertIsNone(process.poll(), "startup exited before reaching Viola")
            time.sleep(0.01)
        self.fail("startup did not reach Viola")

    def assert_no_restart(self) -> None:
        self.assertFalse(any("runtime control" in line for line in self.trace()), self.trace())

    def test_normal_boot_keeps_existing_startup_without_restart(self) -> None:
        self.environment.pop("KSU_LATE_LOAD")
        self.run_stage("post-fs-data.sh")
        self.run_stage("boot-completed.sh")
        self.assertEqual(self.trace(), ["viola launch"])
        self.assertFalse(self.state.exists())
        self.assertTrue((self.base / "yzconfig.json").is_file())

    def test_initial_late_load_and_zygote_restart_never_start_core(self) -> None:
        log = self.base / "log/zygiskd64.log"
        log.parent.mkdir(parents=True)
        log.write_text("previous boot log\n")
        for _ in range(2):
            self.run_stage("late-load.sh")
            # The initial late-load flow invokes boot-completed with Android up.
            self.run_stage("boot-completed.sh")
            # Sui's ctl.restart zygote does not replay KSU's post-fs-data or
            # reset sys.boot_completed. Boot callbacks must leave us pending.
            self.property("init.svc.zygote", "restarting")
            self.run_stage("boot-completed.sh")
            self.property("init.svc.zygote", "stopped")
            # Even an out-of-stage post-fs-data call cannot activate here.
            self.run_stage("post-fs-data.sh")
            self.assertTrue((self.state / "pending").is_file())
            self.assertFalse((self.root / "kernel.ready").exists())
            self.start_runtime()
            self.run_stage("boot-completed.sh")
        self.assertEqual(self.trace(), [])
        self.assertFalse((self.root / "kernel.ready").exists())
        self.assertFalse((self.root / "status-queries").exists())
        self.assertTrue((self.state / "pending").is_file())
        self.assertFalse((self.state / "active").exists())
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.root / "description").read_text().strip(), "late-load-pending")
        action = self.run_stage("action.sh")
        self.assertIn("manually soft-reboot from KernelSU", action.stdout)
        self.assertNotIn("kernel control is unavailable", action.stdout)
        self.assertEqual(log.read_text(), "previous boot log\n")
        self.assert_no_restart()

    def test_manual_soft_reboot_activates_before_runtime_restart(self) -> None:
        log = self.base / "log/zygiskd64.log"
        log.parent.mkdir(parents=True)
        log.write_text("previous boot log\n")
        self.run_stage("late-load.sh")
        self.run_stage("post-fs-data.sh")  # Android is still running: defer.
        self.assertEqual(self.trace(), [])
        self.stop_runtime()
        self.run_stage("post-fs-data.sh")
        self.assertEqual(self.trace(), ["viola launch"])
        self.assertFalse((self.state / "pending").exists())
        self.assertTrue((self.state / "active").is_file())
        self.start_runtime()
        self.run_stage("boot-completed.sh")
        log.write_text("live daemon log\n")
        self.run_stage("late-load.sh")
        self.run_stage("post-fs-data.sh")  # No relaunch while Android is up.
        self.assertEqual(log.read_text(), "live daemon log\n")
        self.assertEqual(log.with_name("zygiskd64.old.log").read_text(), "previous boot log\n")
        self.assertEqual(self.trace(), ["viola launch"])
        self.assertEqual(self.start_count(), 1)
        self.assertFalse((self.state / "pending").exists())
        self.assert_no_restart()

    def test_runtime_resume_during_launch_keeps_pending_and_can_retry(self) -> None:
        self.run_stage("late-load.sh")
        self.stop_runtime()
        pause = self.root / "pause-before"
        pause.touch()
        process = self.start_stage()
        self.wait_for_launch(process)
        # KSU's shared deadline leaves this script alive, then starts Android.
        self.start_runtime()
        self.run_stage("boot-completed.sh")
        pause.unlink()
        stdout, stderr = process.communicate(timeout=15)
        self.assertEqual(process.returncode, 1, stdout + stderr)
        self.assertFalse((self.root / "kernel.ready").exists())
        self.assertTrue((self.state / "pending").is_file())
        self.assertFalse((self.state / "active").exists())
        self.assertEqual((self.root / "description").read_text().strip(), "late-load-pending")
        self.run_stage("boot-completed.sh")
        self.assertEqual((self.root / "description").read_text().strip(), "late-load-pending")
        self.stop_runtime()
        self.run_stage("post-fs-data.sh")
        self.assertEqual(self.start_count(), 1)
        self.assertFalse((self.state / "pending").exists())
        self.assert_no_restart()

    def test_runtime_mode_also_identifies_late_load(self) -> None:
        self.environment.pop("KSU_LATE_LOAD")
        self.environment["KSU_RUNTIME_MODE"] = "late-load"
        self.run_stage("late-load.sh")
        self.run_stage("boot-completed.sh")
        self.assertEqual(self.trace(), [])
        self.stop_runtime()
        self.run_stage("post-fs-data.sh")
        self.assertEqual(self.trace(), ["viola launch"])

    def test_late_entry_outside_late_mode_is_inert(self) -> None:
        self.environment.pop("KSU_LATE_LOAD")
        self.run_stage("late-load.sh")
        self.assertEqual(self.trace(), [])
        self.assertFalse(self.state.exists())

    def test_pending_health_check_never_unloads(self) -> None:
        self.run_stage("late-load.sh")
        (self.root / "proc-modules").write_text("yukizygisk 123 0 - Live 0\n")
        (self.root / "status.fail").touch()
        self.run_stage("boot-completed.sh")
        self.assertEqual(self.trace(), [])
        self.assertFalse((self.root / "status-queries").exists())

    def test_launch_failure_does_not_restart_and_allows_startup_retry(self) -> None:
        failure = self.root / "launch.fail"
        failure.touch()
        self.run_stage("late-load.sh")
        self.stop_runtime()
        self.run_stage("post-fs-data.sh", expected=1)
        self.assertTrue((self.state / "pending").is_file())
        self.assertFalse((self.state / "active").exists())
        self.run_stage("boot-completed.sh")
        self.assert_no_restart()
        failure.unlink()
        self.run_stage("late-load.sh")
        self.assertEqual(self.trace(), ["viola launch"])
        self.run_stage("post-fs-data.sh")
        self.assertEqual(self.trace(), ["viola launch", "viola launch"])
        self.assertFalse((self.state / "pending").exists())

    def test_missing_verifier_reports_failure_without_claiming_readiness(self) -> None:
        (self.module / "bin/viola").unlink()
        self.run_stage("late-load.sh")
        self.stop_runtime()
        self.run_stage("post-fs-data.sh", expected=1)
        self.run_stage("boot-completed.sh")
        self.assertEqual(self.trace(), [])
        self.assertFalse((self.root / "daemon.ready").exists())
        self.assertTrue((self.state / "pending").is_file())
        self.assertNotIn("core ready", (self.base / "zygiskd.log").read_text())

    def test_stale_mode_marker_does_not_skip_initialization(self) -> None:
        self.state.mkdir(mode=0o700)
        self.run_stage("late-load.sh")
        self.assertEqual(self.start_count(), 0)
        self.stop_runtime()
        self.run_stage("post-fs-data.sh")
        self.assertEqual(self.start_count(), 1)
        self.assertTrue((self.base / "yzconfig.json").is_file())

    def check_interrupted_startup(self, after_ready: bool) -> None:
        self.run_stage("late-load.sh")
        self.stop_runtime()
        pause = self.root / ("pause-after" if after_ready else "pause-before")
        pause.touch()
        process = self.start_stage()
        self.wait_for_launch(process)
        log = self.base / "log/zygiskd64.log"
        log.write_text("preserve interrupted startup log\n")
        self.stop_stage(process)
        self.assertEqual(process.returncode, -signal.SIGKILL)
        self.assertEqual((self.root / "daemon.ready").exists(), after_ready)
        self.assertTrue((self.state / "pending").is_file())
        pause.unlink()
        self.run_stage("late-load.sh")
        self.assertEqual(self.trace(), ["viola launch"])
        self.run_stage("post-fs-data.sh")
        self.assertEqual(self.trace(), ["viola launch", "viola launch"])
        self.assertTrue((self.root / "daemon.ready").exists())
        self.assertEqual(self.start_count(), 1)
        self.assertEqual(log.read_text(), "preserve interrupted startup log\n")
        self.assert_no_restart()

    def test_interrupted_startup_can_retry(self) -> None:
        self.check_interrupted_startup(after_ready=False)

    def test_interrupted_ready_notification_preserves_running_daemon(self) -> None:
        self.check_interrupted_startup(after_ready=True)

    def test_daemon_exit_can_retry_only_at_stopped_post_fs_data(self) -> None:
        self.run_stage("late-load.sh")
        self.stop_runtime()
        self.run_stage("post-fs-data.sh")
        (self.root / "daemon.ready").unlink()
        self.start_runtime()
        self.run_stage("late-load.sh")
        self.run_stage("post-fs-data.sh")
        self.assertFalse((self.root / "daemon.ready").exists())
        self.stop_runtime()
        self.run_stage("post-fs-data.sh")
        self.assertTrue((self.root / "daemon.ready").exists())
        self.assertEqual(self.start_count(), 2)
        self.assert_no_restart()

    def test_kernel_failure_blocks_restart(self) -> None:
        self.run_stage("late-load.sh")
        self.stop_runtime()
        self.run_stage("post-fs-data.sh")
        (self.root / "status.fail").touch()
        self.run_stage("boot-completed.sh")
        self.assertEqual(self.trace(), ["viola launch"])

    def test_disable_or_remove_blocks_startup_and_activation(self) -> None:
        for name in ("disable", "remove"):
            with self.subTest(marker=name):
                marker = self.module / name
                marker.touch()
                self.run_stage("late-load.sh")
                self.assertEqual(self.trace(), [])
                marker.unlink()
        self.run_stage("late-load.sh")
        (self.module / "disable").touch()
        self.stop_runtime()
        self.run_stage("post-fs-data.sh")
        self.run_stage("boot-completed.sh")
        self.assertEqual(self.trace(), [])
        self.assertTrue((self.state / "pending").is_file())

    def test_concurrent_startup_serializes_idempotent_launches(self) -> None:
        self.run_stage("late-load.sh")
        self.stop_runtime()
        processes = [self.start_stage() for _ in range(2)]
        for process in processes:
            stdout, stderr = process.communicate(timeout=15)
            self.assertEqual(process.returncode, 0, stdout + stderr)
        self.run_stage("boot-completed.sh")
        self.assertEqual(self.trace(), ["viola launch", "viola launch"])
        self.assertEqual(self.start_count(), 1)

    def test_post_fs_data_without_initial_marker_still_defers_in_late_mode(self) -> None:
        self.run_stage("post-fs-data.sh")
        self.assertEqual(self.trace(), [])
        self.assertTrue((self.state / "pending").is_file())
        self.stop_runtime()
        self.run_stage("post-fs-data.sh")
        self.assertEqual(self.start_count(), 1)

    def test_original_late_startup_argument_cannot_bypass_deferral(self) -> None:
        self.stop_runtime()
        self.run_stage("post-fs-data.sh", "late-load", expected=2)
        self.assertEqual(self.trace(), [])

    def test_all_runtime_stop_conditions_are_required(self) -> None:
        self.run_stage("late-load.sh")
        for name, value in (("sys.boot_completed", "1"),
                            ("init.svc.zygote", "stopping"),
                            ("ro.zygote", "")):
            with self.subTest(property=name):
                self.stop_runtime()
                self.property(name, value)
                self.run_stage("post-fs-data.sh")
                self.assertEqual(self.trace(), [])
                self.property(name, "")
        self.stop_runtime()
        self.property("ro.zygote", "zygote64_32")
        self.property("init.svc.zygote_secondary", "running")
        self.run_stage("post-fs-data.sh")
        self.assertEqual(self.trace(), [])
        self.assertTrue((self.state / "pending").is_file())
        self.property("init.svc.zygote_secondary", "stopped")
        self.run_stage("post-fs-data.sh")
        self.assertEqual(self.start_count(), 1)

    def test_optional_vendor_zygote_does_not_block_manual_activation(self) -> None:
        self.run_stage("late-load.sh")
        self.stop_runtime()
        self.property("init.svc.zygote_ocomp", "running")
        self.run_stage("post-fs-data.sh")
        self.assertEqual(self.start_count(), 1)

    def test_concurrent_late_entries_only_publish_pending(self) -> None:
        processes = [self.start_stage("late-load.sh") for _ in range(2)]
        for process in processes:
            stdout, stderr = process.communicate(timeout=15)
            self.assertEqual(process.returncode, 0, stdout + stderr)
        self.assertEqual(self.trace(), [])
        self.assertTrue((self.state / "pending").is_file())

    def test_invalid_state_never_starts_core(self) -> None:
        self.state.symlink_to(self.root / "properties", target_is_directory=True)
        self.run_stage("late-load.sh", expected=1)
        self.stop_runtime()
        self.run_stage("post-fs-data.sh", expected=1)
        self.assertEqual(self.trace(), [])

    def test_non_root_state_owner_never_starts_core(self) -> None:
        self.state.mkdir()
        (self.root / "state-owner").write_text("1000\n")
        self.run_stage("late-load.sh", expected=1)
        self.stop_runtime()
        self.run_stage("post-fs-data.sh", expected=1)
        self.assertEqual(self.trace(), [])
        self.assertFalse((self.state / "pending").exists())
        self.assertFalse((self.state / "startup.lock").exists())


class BusyBoxLateLoadTests(LateLoadTests):
    shell_name = "busybox"


if __name__ == "__main__":
    unittest.main(verbosity=2)
