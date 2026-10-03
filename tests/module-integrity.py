#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# YukiZygisk - Host tests for checked module ZIP extraction.
#
# License: Apache-2.0
#
# Author: Anatdx

"""Exercise the real install hook with dash and BusyBox ash, without Android.

The only executable payload is a host shell stub. It emits a marker and exits
73, so customize.sh must abort before common.sh or any /data/adb operation.
Both shells use BusyBox unzip and sha256sum, matching module installer tools.
"""

from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile


REPO = Path(__file__).resolve().parents[1]
VIOLA_MARKER = "TEST_VIOLA_REACHED"
LATE_MARKER = "TEST_INSTALLER_PAST_VIOLA"
ENV_MARKER = "TEST_VIOLA_ENV_CLEAN"
BAD_VERIFIER_MARKER = "TEST_CORRUPTED_VERIFIER_EXECUTED"

INSTALLER_ENV = r"""
ui_print() { printf '%s\n' "$*"; }
abort() { printf '%s\n' "$*" >&2; exit 1; }
set_perm_recursive() {
    [ "$1" = "$MODPATH" ] || abort "Unexpected host permission target"
    find "$1" -type d -exec chmod "$4" '{}' ';' || exit 2
    find "$1" -type f -exec chmod "$5" '{}' ';' || exit 2
}
set_perm() {
    case "$1" in
    "$MODPATH"/*) chmod "$4" "$1" ;;
    *) abort "Unexpected host permission target" ;;
    esac
}
. "$1"
"""


class ModuleIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if os.name != "posix":
            raise unittest.SkipTest("run with Linux/WSL Python, BusyBox and dash")
        cls.busybox = shutil.which("busybox")
        cls.dash = shutil.which("dash")
        if not cls.busybox or not cls.dash:
            raise RuntimeError("these integration tests require both busybox and dash")
        for relative in ("module/verify.sh", "tools/module_checksums.py"):
            if not (REPO / relative).is_file():
                raise RuntimeError(f"required production file is missing: {relative}")

        cls.temporary = tempfile.TemporaryDirectory(prefix="yz-module-integrity-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.stage = cls.root / "package"
        shutil.copytree(REPO / "module", cls.stage)
        for path in cls.stage.rglob("*.sh"):
            # Map only the Android system utility location into the host.
            path.write_bytes(path.read_bytes().replace(b"\r\n", b"\n").replace(
                b"/system/bin/env", os.fsencode(shutil.which("env"))))

        # Guard the first post-Viola script too. A broken abort must never let
        # this host fixture reach the installer's Android filesystem actions.
        common = cls.stage / "common.sh"
        common.write_bytes(
            f"printf '%s\\n' '{LATE_MARKER}'\nexit 74\n".encode()
            + common.read_bytes()
        )
        payloads = {
            "bin/viola": (
                "#!/bin/sh\n"
                "[ -z \"${LD_PRELOAD+x}${LD_LIBRARY_PATH+x}${UNTRUSTED_FIXTURE+x}\" ] || exit 75\n"
                f"printf '%s\\n' '{ENV_MARKER}' '{VIOLA_MARKER}'\nexit 73\n"
            ).encode(),
            "bin/zygiskd64": b"host fixture, never execute daemon64\n",
            "bin/zygiskd32": b"host fixture, never execute daemon32\n",
            "bin/yzctl": b"host fixture, never execute yzctl\n",
            "lkm/android16-6.12_yukizygisk.ko": b"kernel fixture\x00\x01\xff",
            "lib64/libzygisk.so": b"arm64 core fixture\x00",
            "lib64/libyukilinker.so": b"arm64 loader fixture\x00",
            "lib64/libyukizncore.so": b"arm64 native fixture\x00",
            "lib/libzygisk.so": b"arm32 core fixture\x00",
            "lib/libyukilinker.so": b"arm32 loader fixture\x00",
            "lib/libyukizncore.so": b"arm32 native fixture\x00",
            "viola.manifest": b"manifest fixture, no GPG needed\n",
            "viola.sig": b"detached signature fixture\n",
            "viola.pgp": b"public key fixture\n",
            "webroot/index.html": b"<!doctype html><title>Integrity fixture</title>\n",
            "webroot/assets/test.js": b"export const fixture = true;\n",
            "webroot/assets/empty.css": b"",
            "LICENSE": b"test fixture license\n",
        }
        for relative, data in payloads.items():
            path = cls.stage / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        cls.original = {
            path.relative_to(cls.stage).as_posix(): path.read_bytes()
            for path in cls.stage.rglob("*") if path.is_file()
        }
        generated = subprocess.run(
            [sys.executable, str(REPO / "tools/module_checksums.py"), str(cls.stage)],
            check=False, capture_output=True, text=True, timeout=20,
        )
        if generated.returncode:
            raise RuntimeError(f"checksum generation failed:\n{generated.stdout}{generated.stderr}")
        cls.entries = {
            path.relative_to(cls.stage).as_posix(): path.read_bytes()
            for path in cls.stage.rglob("*") if path.is_file()
        }
        cls.good_zip = cls.archive(cls.entries)

        # Use BusyBox applets in both shells, rather than accidentally passing
        # because ash found the host's richer Info-ZIP/GNU commands on PATH.
        cls.applets = cls.root / "busybox-applets"
        cls.applets.mkdir()
        names = subprocess.check_output([cls.busybox, "--list"], text=True).splitlines()
        for name in names:
            (cls.applets / name).symlink_to(cls.busybox)
        cls.test_path = str(cls.applets) + os.pathsep + os.defpath
        for name in ("unzip", "sha256sum"):
            resolved = shutil.which(name, path=cls.test_path)
            if not resolved or not os.path.samefile(resolved, cls.busybox):
                raise RuntimeError(f"test must use the BusyBox {name} applet")
        cls.shells = (("dash", (cls.dash,)), ("busybox-ash", (cls.busybox, "ash")))

    @staticmethod
    def archive(entries: dict[str, bytes]) -> bytes:
        result = io.BytesIO()
        with zipfile.ZipFile(result, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in sorted(entries.items()):
                archive.writestr(name, data)
        return result.getvalue()

    def archive_with_symlink(self, name: str, target: str) -> bytes:
        result = io.BytesIO()
        with zipfile.ZipFile(result, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for entry_name, data in sorted(self.entries.items()):
                if entry_name != name:
                    archive.writestr(entry_name, data)
                    continue
                info = zipfile.ZipInfo(entry_name)
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(info, target.encode())
        return result.getvalue()

    def run_hook(self, shell: tuple[str, ...], archive: bytes):
        attempt = tempfile.TemporaryDirectory(prefix="installer with spaces ", dir=self.root)
        self.addCleanup(attempt.cleanup)
        root = Path(attempt.name)
        modpath = root / "installed module"
        temporary = root / "installer temporary"
        modpath.mkdir()
        temporary.mkdir()
        zip_path = root / "module with spaces.zip"
        zip_path.write_bytes(archive)
        environment = {
            "PATH": self.test_path,
            "TMPDIR": str(temporary),
            "MODPATH": str(modpath),
            "ZIPFILE": str(zip_path),
            "BOOTMODE": "true",
            "LANG": "C",
            "LC_ALL": "C",
            "LD_LIBRARY_PATH": str(root / "untrusted-libraries"),
            "UNTRUSTED_FIXTURE": "must-not-reach-viola",
        }
        result = subprocess.run(
            [*shell, "-c", INSTALLER_ENV, "integrity-fixture", str(self.stage / "customize.sh")],
            env=environment, cwd=root, check=False, capture_output=True, text=True, timeout=15,
        )
        output = result.stdout + result.stderr
        self.assertNotIn(LATE_MARKER, output, output)
        self.assertNotIn(BAD_VERIFIER_MARKER, output, output)
        return result, output, modpath, temporary

    def assert_rejected(self, archive: bytes, label: str) -> None:
        for shell_name, shell in self.shells:
            with self.subTest(case=label, shell=shell_name):
                result, output, _, _ = self.run_hook(shell, archive)
                self.assertEqual(result.returncode, 1, output)
                self.assertNotIn(VIOLA_MARKER, output, output)
                self.assertRegex(output.lower(), r"download(?:ing)?[^\n]*again", output)

    def changed_archive(self, replacements=None, missing=()) -> bytes:
        entries = dict(self.entries)
        entries.update(replacements or {})
        for name in missing:
            entries.pop(name)
        return self.archive(entries)

    def test_generated_inventory_covers_every_input_file(self) -> None:
        inventory = self.entries["files.list"].decode().splitlines()
        self.assertEqual(len(inventory), len(set(inventory)), "duplicate inventory entry")
        self.assertEqual(set(inventory), set(self.original))
        for name in [*inventory, "files.list"]:
            with self.subTest(file=name):
                expected = hashlib.sha256(self.entries[name]).hexdigest()
                self.assertEqual(self.entries[name + ".sha256"].decode().strip(), expected)

    def test_complete_zip_reaches_only_the_stub_verifier(self) -> None:
        for shell_name, shell in self.shells:
            with self.subTest(shell=shell_name):
                result, output, modpath, temporary = self.run_hook(shell, self.good_zip)
                self.assertEqual(result.returncode, 1, output)  # stub exit 73 -> abort
                self.assertEqual(output.count(VIOLA_MARKER), 1, output)
                self.assertIn(ENV_MARKER, output)
                self.assertIn("Package integrity verified", output)
                self.assertLess(output.index("Package integrity verified"), output.index(VIOLA_MARKER))
                self.assertIn("core verification failed", output)
                expected = set(self.original) - {"customize.sh", "verify.sh"}
                actual = {p.relative_to(modpath).as_posix() for p in modpath.rglob("*") if p.is_file()}
                self.assertEqual(actual, expected, "metadata or unchecked files leaked into MODPATH")
                for name in expected:
                    self.assertEqual((modpath / name).read_bytes(), self.original[name], name)
                self.assertTrue(list(temporary.rglob("files.list")))
                self.assertTrue(list(temporary.rglob("*.sha256")))

    def test_corrupted_payloads_stop_before_viola(self) -> None:
        for name in (
            "bin/viola", "lkm/android16-6.12_yukizygisk.ko", "lib64/libzygisk.so",
            "lib/libyukizncore.so", "webroot/index.html", "action.sh", "module.prop",
            "customize.sh", "viola.manifest", "viola.sig",
        ):
            self.assert_rejected(
                self.changed_archive({name: self.entries[name] + b"\n# corrupted\n"}), name
            )

    def test_missing_payload(self) -> None:
        self.assert_rejected(self.changed_archive(missing=("webroot/index.html",)), "missing payload")

    def test_missing_payload_checksum(self) -> None:
        self.assert_rejected(
            self.changed_archive(missing=("lib64/libzygisk.so.sha256",)), "missing checksum"
        )

    def test_missing_payload_and_checksum(self) -> None:
        self.assert_rejected(
            self.changed_archive(missing=("webroot/index.html", "webroot/index.html.sha256")),
            "missing payload and checksum",
        )

    def test_corrupted_bootstrap_verifier_is_not_sourced(self) -> None:
        damaged = f"printf '%s\\n' '{BAD_VERIFIER_MARKER}'\n".encode() + self.entries["verify.sh"]
        self.assert_rejected(self.changed_archive({"verify.sh": damaged}), "corrupt bootstrap verifier")

    def test_symlinked_bootstrap_verifier_is_rejected(self) -> None:
        for name in ("verify.sh", "verify.sh.sha256"):
            with self.subTest(file=name):
                self.assert_rejected(
                    self.archive_with_symlink(name, "customize.sh"),
                    "symlinked bootstrap " + name,
                )

    def test_missing_bootstrap_verifier_or_checksum(self) -> None:
        for name in ("verify.sh", "verify.sh.sha256"):
            self.assert_rejected(self.changed_archive(missing=(name,)), "missing " + name)

    def test_corrupted_inventory(self) -> None:
        self.assert_rejected(
            self.changed_archive({"files.list": self.entries["files.list"] + b"missing-file\n"}),
            "corrupt inventory",
        )

    def test_missing_inventory_or_checksum(self) -> None:
        for missing in (("files.list",), ("files.list.sha256",), ("files.list", "files.list.sha256")):
            self.assert_rejected(self.changed_archive(missing=missing), "missing " + ", ".join(missing))

    def test_malformed_checksums(self) -> None:
        for name in ("verify.sh.sha256", "webroot/index.html.sha256"):
            for value in (b"0" * 63, b"g" * 64):
                self.assert_rejected(self.changed_archive({name: value}), "malformed " + name)

    def test_truncated_zip(self) -> None:
        self.assert_rejected(self.good_zip[:len(self.good_zip) // 2], "truncated ZIP")


if __name__ == "__main__":
    unittest.main(verbosity=2)
