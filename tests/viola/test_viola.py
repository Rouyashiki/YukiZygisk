#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# YukiZygisk - Production Viola verifier and signing-tool regression tests
# License: Apache-2.0
# Author: Anatdx
"""Run with Python, a host C compiler, GPG and tools/requirements-viola.txt.

All private keys are disposable keys generated in a temporary GNUPGHOME.
No personal signing key, Android device, or production signature is used.
"""
import argparse
import contextlib
import ctypes as C
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

# For ASan, preload its runtime into Python itself, then stop propagating it to
# GPG/compiler subprocesses. Instrumented test executables link their own runtime.
SANITIZERS = os.environ.get("VIOLA_TEST_SANITIZERS", "")
if SANITIZERS:
    if SANITIZERS not in ("address,undefined", "undefined"):
        raise RuntimeError("supported VIOLA_TEST_SANITIZERS: address,undefined or undefined")
    if "address" in SANITIZERS and not os.environ.pop("LD_PRELOAD", None):
        raise RuntimeError("ASan ctypes tests require LD_PRELOAD=$(cc -print-file-name=libasan.so)")

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("viola_tool", ROOT / "tools/viola.py")
V = importlib.util.module_from_spec(spec)
spec.loader.exec_module(V)


class View(C.Structure):
    _fields_ = [("data", C.c_void_p), ("size", C.c_size_t), ("release_id", C.c_void_p),
                ("trust_id", C.c_void_p), ("version_code", C.c_uint64), ("profile", C.c_uint32),
                ("policy", C.c_uint32), ("protocol", C.c_uint32), ("entry_count", C.c_uint16)]


def pgp_packet(tag, data):
    return bytes([0xc0 | tag, 255]) + len(data).to_bytes(4, "big") + data


def note_image(context, role, abi, kmi, loader_digest=None):
    """Synthetic ELF containers exercise metadata parsing; never executed."""
    desc = b"VIOLAID1" + struct.pack("<IIIIIIQ", context["profile"], context["policy"], context["protocol"], role, abi, kmi,
                                      context["version_code"])
    desc += bytes.fromhex(context["release_id"] + context["trust_id"])
    notes = [(b".note.viola", struct.pack("<III", 6, 104, 1) + b"VIOLA\0\0\0" + desc)]
    if loader_digest is not None:
        notes.append((b".note.viola.loader", struct.pack("<III", 6, 72, 2) +
                      b"VIOLA\0\0\0VIOLALDR" + loader_digest))
    names = b"\0.shstrtab\0" + b"".join(name + b"\0" for name, _ in notes)
    is64 = abi == 1
    head = bytearray(64 if is64 else 52)
    head[:16] = b"\x7fELF" + bytes([2 if is64 else 1, 1, 1]) + bytes(9)
    struct.pack_into("<HHI", head, 16, 1 if role == 2 else 3, 183 if is64 else 40, 1)
    phsize = (56 if is64 else 32) if role in (1, 3) else 0
    image = head + bytes(phsize) + names
    sections = [(0, 0, 0, 0)]
    sections.append((1, 3, len(head) + phsize, len(names)))
    if role in (1, 3):
        interpreter = b"/system/bin/linker64\0" if is64 else b"/system/bin/linker\0"
        location = len(image)
        image += interpreter
        if is64:
            struct.pack_into("<Q", image, 32, len(head))
            struct.pack_into("<IIQQQQQQ", image, len(head), 3, 4, location, 0, 0, len(interpreter), len(interpreter), 1)
        else:
            struct.pack_into("<I", image, 28, len(head))
            struct.pack_into("<IIIIIIII", image, len(head), 3, location, 0, 0, len(interpreter), len(interpreter), 4, 1)
    for name, value in notes:
        while len(image) % 4:
            image += b"\0"
        sections.append((names.index(name), 7, len(image), len(value)))
        image += value
    while len(image) % 8:
        image += b"\0"
    shoff = len(image)
    if is64:
        struct.pack_into("<Q", image, 40, shoff)
        struct.pack_into("<HHHHHH", image, 52, 64, phsize, int(bool(phsize)), 64, len(sections), 1)
        for name, kind, offset, size in sections:
            image += struct.pack("<IIQQQQIIQQ", name, kind, 0, 0, offset, size, 0, 0, 4, 0)
    else:
        struct.pack_into("<I", image, 32, shoff)
        struct.pack_into("<HHHHHH", image, 40, 52, phsize, int(bool(phsize)), 40, len(sections), 1)
        for name, kind, offset, size in sections:
            image += struct.pack("<IIIIIIIIII", name, kind, 0, 0, offset, size, 0, 0, 4, 0)
    return bytes(image)


class ViolaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="viola-production-test-")
        cls.base = Path(cls.tmp.name)
        cls.home = cls.base / "gnupg"
        cls.home.mkdir(mode=0o700)
        cls.addClassCleanup(cls.cleanup_keys)
        cls.gpg = shutil.which("gpg")
        if not cls.gpg:
            raise RuntimeError("GPG is required for real detached signature fixtures")
        cls.command("--quick-generate-key", "Viola disposable test <test@example.invalid>", "ed25519", "cert", "1d")
        cls.primary = cls.fingerprints()[0]
        cls.command("--quick-add-key", cls.primary, "ed25519", "sign", "1d")
        cls.signer = cls.fingerprints()[1]
        cls.public = cls.command("--export", cls.primary)
        cls.context_dir = cls.base / "context"
        cls.args = argparse.Namespace(out=str(cls.context_dir), profile="dev", key=cls.signer,
            public_key=None, gpg=cls.gpg, homedir=str(cls.home), version_code=12345,
            source_revision="test-revision", release_id="01" * 32, build_config="test")
        # Concurrent local edits must not make certificate/tool fixtures depend
        # on when a different build task changes the real workspace. Source
        # digest behavior itself is tested separately with controlled inputs.
        cls.real_source_digest = V.source_digest
        digest_patch = patch.object(V, "source_digest", return_value=V.source_digest())
        digest_patch.start()
        cls.addClassCleanup(digest_patch.stop)
        with contextlib.redirect_stdout(io.StringIO()):
            V.prepare(cls.args)
        cls.context = V.read_context(cls.context_dir)
        cls.module = cls.base / "module"
        cls.module.mkdir()
        viola = note_image(cls.context, 1, 1, 0)
        loader_digest = hashlib.sha512(viola).digest()
        for identity, relative in V.PATHS.items():
            if identity[0] == 2 and identity[2] != 7:
                continue
            path = cls.module / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(note_image(cls.context, *identity,
                loader_digest=loader_digest if identity[0] == 2 else None))
        cls.manifest = V.make_manifest(cls.module, cls.context)
        cls.signature = cls.sign(cls.manifest)
        (cls.module / "viola.manifest").write_bytes(cls.manifest)
        (cls.module / "viola.sig").write_bytes(cls.signature)
        shared = ROOT / "shared/viola"
        cls.library_path = cls.base / "libviola-test.so"
        cc = os.environ.get("CC", "cc")
        flags = ["-DVIOLA_NO_ARGON2"]
        if SANITIZERS:
            flags += ["-fsanitize=" + SANITIZERS, "-fno-omit-frame-pointer", "-g"]
        subprocess.run([cc, *flags, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC",
            "-I" + str(shared), "-I" + str(cls.context_dir), str(shared / "viola.c"),
            str(shared / "vendor/monocypher.c"), str(shared / "vendor/monocypher-ed25519.c"),
            "-o", str(cls.library_path)], check=True)
        cls.lib = C.CDLL(str(cls.library_path))
        cls.lib.viola_manifest_verify.argtypes = [C.c_void_p, C.c_size_t, C.c_void_p, C.c_size_t, C.POINTER(View)]
        cls.lib.viola_manifest_verify.restype = C.c_int
        cls.lib.viola_manifest_parse.argtypes = [C.c_void_p, C.c_size_t, C.POINTER(View)]
        cls.lib.viola_manifest_parse.restype = C.c_int
        cls.host_verifier = cls.base / "viola-host"
        subprocess.run([cc, *flags, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
            "-I" + str(shared), "-I" + str(cls.context_dir), str(ROOT / "userspace/viola/host_verify.c"),
            str(shared / "viola.c"), str(shared / "vendor/monocypher.c"),
            str(shared / "vendor/monocypher-ed25519.c"), "-o", str(cls.host_verifier)], check=True)
        cls.launcher_verifier = cls.base / "viola-launcher-verify"
        cxx = os.environ.get("CXX", "c++")
        loader_dir = ROOT / "userspace/viola"
        loader_sources = [loader_dir / "module_loader.cpp",
                          loader_dir / "third_party/lkmloader/src/loader.cpp",
                          loader_dir / "third_party/lkmloader/src/vermagic.cpp"]
        loader_objects = []
        for index, source in enumerate(loader_sources):
            obj = cls.base / f"module-loader-{index}.o"
            definitions = ["-Dsyscall=viola_lkm_syscall"] if index == 1 else []
            subprocess.run([cxx, *flags, *definitions, "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
                "-fno-exceptions", "-fno-rtti", "-c", str(source), "-o", str(obj)], check=True)
            loader_objects.append(str(obj))
        loader_links = [*loader_objects, "-lstdc++"]
        cls.loader_fixture = cls.base / "viola-module-loader"
        subprocess.run([cxx, *flags, "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
            "-I" + str(ROOT), str(ROOT / "tests/viola/module_loader.cpp"),
            *loader_links, "-Wl,--wrap=open", "-o", str(cls.loader_fixture)], check=True)
        subprocess.run([cc, *flags, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
            "-I" + str(ROOT), "-I" + str(shared), "-I" + str(cls.context_dir),
            str(ROOT / "userspace/viola/main.c"), str(shared / "viola.c"),
            str(shared / "vendor/monocypher.c"), str(shared / "vendor/monocypher-ed25519.c"),
            *loader_links, "-o", str(cls.launcher_verifier)], check=True)
        cls.recovery_fixture = cls.base / "viola-recovery"
        subprocess.run([cc, *flags, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
            "-I" + str(ROOT), "-I" + str(shared), "-I" + str(cls.context_dir),
            str(ROOT / "tests/viola/recovery.c"), str(shared / "viola.c"),
            str(shared / "vendor/monocypher.c"), str(shared / "vendor/monocypher-ed25519.c"),
            *loader_links, "-o", str(cls.recovery_fixture)], check=True)
        cls.kernel_fixture = cls.base / "viola-load-kernel"
        subprocess.run([cc, *flags, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
            "-I" + str(ROOT), "-I" + str(shared), "-I" + str(cls.context_dir),
            str(ROOT / "tests/viola/load_kernel.c"), str(shared / "viola.c"),
            str(shared / "vendor/monocypher.c"), str(shared / "vendor/monocypher-ed25519.c"),
            *loader_links, "-o", str(cls.kernel_fixture)], check=True)

    def test_embedded_lkmloader(self):
        result = subprocess.run([str(self.loader_fixture)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_corrupt_kernel_never_reaches_loading_syscall(self):
        path = self.module / V.PATHS[(2, 1, 7)]
        original = path.read_bytes()
        try:
            good = subprocess.run([str(self.kernel_fixture), str(self.module)],
                                  capture_output=True, text=True, check=True)
            self.assertEqual(good.stdout.strip(), "0 1")
            for data in (original[:-1], original[:-1] + bytes([original[-1] ^ 1])):
                path.write_bytes(data)
                bad = subprocess.run([str(self.kernel_fixture), str(self.module)],
                                     capture_output=True, text=True, check=True)
                result, calls = map(int, bad.stdout.split())
                self.assertNotEqual(result, 0)
                self.assertEqual(calls, 0)
        finally:
            path.write_bytes(original)

    @classmethod
    def cleanup_keys(cls):
        subprocess.run(["gpgconf", "--homedir", str(cls.home), "--kill", "gpg-agent"], capture_output=True)
        cls.tmp.cleanup()

    @classmethod
    def command(cls, *args, data=None):
        result = subprocess.run([cls.gpg, "--no-options", "--homedir", str(cls.home), "--batch", "--yes",
            "--pinentry-mode", "loopback", "--passphrase", "", *args], input=data, capture_output=True)
        if result.returncode:
            raise RuntimeError(result.stderr.decode(errors="replace"))
        return result.stdout

    @classmethod
    def fingerprints(cls):
        return [line.split(":")[9] for line in cls.command("--with-colons", "--list-keys").decode().splitlines()
                if line.startswith("fpr:")]

    @classmethod
    def sign(cls, data, digest="SHA512"):
        path = cls.base / "message.bin"
        signature = cls.base / "message.sig"
        path.write_bytes(data)
        cls.command("--local-user", cls.signer + "!", "--digest-algo", digest,
                    "--output", str(signature), "--detach-sign", str(path))
        return signature.read_bytes()

    def verify(self, data=None, sig=None):
        data = self.manifest if data is None else data
        sig = self.signature if sig is None else sig
        view = View()
        result = self.lib.viola_manifest_verify(data, len(data), sig, len(sig), C.byref(view))
        if result:
            self.assertFalse(view.data, "failed verification must clear the borrowed view")
        return result

    def test_real_gpg_signature_and_matching_manifest(self):
        self.assertEqual(self.verify(), 0)

    def test_signed_content_corruption(self):
        data = bytearray(self.manifest)
        data[-1] ^= 1
        self.assertEqual(self.verify(bytes(data)), 3)

    def test_signature_corruption_and_all_truncations(self):
        self.assertEqual(self.verify(sig=self.signature[:-1] + bytes([self.signature[-1] ^ 1])), 3)
        for offset in range(len(self.signature)):
            with self.subTest(offset=offset):
                self.assertEqual(self.verify(sig=self.signature[:offset]), 3)
        self.assertEqual(self.verify(sig=self.signature + b"\0"), 3)
        self.assertEqual(self.verify(sig=self.signature * 2), 3)
        self.assertEqual(self.verify(sig=b"x" * 4097), 3)

    def test_valid_signature_for_another_release_is_rejected(self):
        data = bytearray(self.manifest)
        data[32] ^= 1
        self.assertEqual(self.verify(bytes(data), self.sign(bytes(data))), 4)

    def test_valid_signature_cannot_change_trust_profile_or_version(self):
        for offset in (20, 64, 96):
            data = bytearray(self.manifest)
            data[offset] = 1 if offset == 20 else data[offset] ^ 1
            with self.subTest(offset=offset):
                self.assertEqual(self.verify(bytes(data), self.sign(bytes(data))), 4)

    def test_manifest_structure_bounds_and_duplicate_roles(self):
        mutations = []
        for offset in (0, 8, 10, 12, 16, 18, 24, 28, 104, 120, 128 + 8, 128 + 12):
            data = bytearray(self.manifest)
            data[offset] ^= 0x80
            mutations.append(bytes(data))
        data = bytearray(self.manifest)
        data[216:224] = data[128:136]
        mutations.append(bytes(data))
        mutations += [b"", self.manifest[:127], self.manifest[:-1], self.manifest + b"\0", b"x" * 8193]
        for data in mutations:
            self.assertEqual(self.lib.viola_manifest_parse(data, len(data), C.byref(View())), 2)

    def test_even_signed_partial_catalog_is_rejected(self):
        data = bytearray(self.manifest[:128] + self.manifest[216:])
        struct.pack_into("<I", data, 12, len(data))
        struct.pack_into("<H", data, 16, struct.unpack_from("<H", data, 16)[0] - 1)
        self.assertEqual(self.verify(bytes(data), self.sign(bytes(data))), 2)

    def test_sha256_signature_is_outside_runtime_profile(self):
        self.assertEqual(self.verify(sig=self.sign(self.manifest, "SHA256")), 3)

    def test_another_real_signing_key_is_not_authorized(self):
        self.command("--quick-add-key", self.primary, "ed25519", "sign", "1d")
        other = self.fingerprints()[-1]
        path, sig = self.base / "other-message", self.base / "other-signature"
        path.write_bytes(self.manifest)
        self.command("--local-user", other + "!", "--digest-algo", "SHA512",
                     "--output", str(sig), "--detach-sign", str(path))
        self.assertEqual(self.verify(sig=sig.read_bytes()), 3)

    def test_short_mpi_from_real_gpg_output(self):
        data = bytearray(self.manifest)
        for nonce in range(2048):
            data[-4:] = struct.pack("<I", nonce)
            sig = self.sign(bytes(data))
            _, body = next(V.packets(sig))
            raw = V.signature(body)["raw"]
            if raw[0] == 0 or raw[32] == 0:
                self.assertEqual(self.verify(bytes(data), sig), 0)
                return
        self.fail("GPG did not produce a short-MPI fixture within the bounded search")

    def test_noncritical_notation_works_critical_notation_is_rejected(self):
        path, sig = self.base / "notation-message", self.base / "notation-signature"
        path.write_bytes(self.manifest)
        for notation, expected in [("viola-test@example.invalid=yes", 0),
                                    ("!viola-test@example.invalid=yes", 3)]:
            self.command("--local-user", self.signer + "!", "--digest-algo", "SHA512",
                         "--sig-notation", notation, "--output", str(sig), "--detach-sign", str(path))
            self.assertEqual(self.verify(sig=sig.read_bytes()), expected)

    def test_bundled_official_certificate_needs_no_private_material(self):
        data = V.dearmor((ROOT / "shared/viola/publisher.asc").read_bytes())
        primary, _, _ = V.validate_certificate(data, V.SIGNER, "official")
        self.assertEqual(primary, V.PRIMARY)
        with self.assertRaisesRegex(ValueError, "independent development"):
            V.validate_certificate(data, V.SIGNER, "dev")

    def changed_binding(self, mutation):
        changed = []
        for tag, body in V.packets(self.public):
            if tag == 2 and body[1] == 0x18:
                body = mutation(body)
            changed.append(pgp_packet(tag, body))
        return b"".join(changed)

    def test_subkey_binding_authenticity(self):
        data = self.changed_binding(lambda body: body[:-1] + bytes([body[-1] ^ 1]))
        with self.assertRaisesRegex(ValueError, "binding"):
            V.validate_certificate(data, self.signer, "dev")

    def test_back_signature_is_verified_in_unhashed_area(self):
        def without_back(body):
            end = 6 + int.from_bytes(body[4:6], "big")
            usize = int.from_bytes(body[end:end + 2], "big")
            unhash = body[end + 2:end + 2 + usize]
            kept = bytearray()
            pos = 0
            while pos < len(unhash):
                start = pos
                size, pos = V.take_length(unhash, pos, True)
                if unhash[pos] & 127 != 32:
                    kept += unhash[start:pos + size]
                pos += size
            return body[:end] + len(kept).to_bytes(2, "big") + kept + body[end + 2 + usize:]
        data = self.changed_binding(without_back)
        with self.assertRaisesRegex(ValueError, "back signature"):
            V.validate_certificate(data, self.signer, "dev")

    def test_expired_certificate_is_rejected_at_build_time(self):
        with patch.object(V.time, "time", return_value=time.time() + 3 * 86400):
            with self.assertRaisesRegex(ValueError, "expired"):
                V.validate_certificate(self.public, self.signer, "dev")

    def test_revoked_primary_is_rejected(self):
        rev = (self.home / "openpgp-revocs.d" / (self.primary + ".rev")).read_bytes()
        rev = rev[rev.index(b":-----BEGIN PGP PUBLIC KEY BLOCK-----") + 1:]
        with self.assertRaisesRegex(ValueError, "revoked"):
            V.validate_certificate(self.public + V.dearmor(rev), self.signer, "dev")

    def test_loader_digest_is_bound_to_ko(self):
        path = self.module / V.PATHS[(2, 1, 7)]
        original = path.read_bytes()
        try:
            path.write_bytes(note_image(self.context, 2, 1, 7, bytes(64)))
            with self.assertRaisesRegex(ValueError, "different Viola executable"):
                V.make_manifest(self.module, self.context)
        finally:
            path.write_bytes(original)

    def launcher_verify(self, directory=None, environment=None):
        if environment is None:
            # Match the clean launcher entry points without changing Python's environment.
            environment = {key: value for key, value in os.environ.items()
                           if not key.startswith("LD_")}
        # Never call launch: this exercises only the production verify command.
        return subprocess.run([str(self.launcher_verifier), "verify", "--module-dir",
                               str(directory or self.module)], capture_output=True,
                              env=environment, timeout=3)

    def test_launcher_rejects_fifos_without_waiting_for_a_writer(self):
        for relative in ("viola.manifest", "viola.sig", "bin/zygiskd64"):
            with self.subTest(path=relative):
                path = self.module / relative
                saved = path.read_bytes()
                path.unlink()
                try:
                    os.mkfifo(path)
                    self.assertNotEqual(self.launcher_verify().returncode, 0)
                finally:
                    path.unlink()
                    path.write_bytes(saved)

    def test_launcher_cleans_inherited_but_rejects_explicit_loader_controls(self):
        with patch.dict(os.environ, {"LD_LIBRARY_PATH": str(self.module / "lib64")}):
            result = self.launcher_verify()
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            result = self.launcher_verify(environment=dict(os.environ))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"loader environment", result.stderr)

    def test_compat_recovery_waits_for_kernel_ready_and_rejects_stale_or_failed_owner(self):
        import errno
        for scenario, expected, requests in (
                (0, 0, 1), (1, 0, 0), (2, 0, 0),
                (3, -errno.ESTALE, 1), (4, -errno.ETXTBSY, 1),
                (5, -errno.ETIMEDOUT, 1), (6, -errno.ESTALE, 1)):
            with self.subTest(scenario=scenario):
                result = subprocess.run([str(self.recovery_fixture), str(scenario)],
                    capture_output=True, text=True, check=True, timeout=3)
                self.assertEqual(result.stdout.strip(), f"{expected} {requests}")

    def test_launcher_verify_rejects_symlink_files_directories_and_dot_paths(self):
        self.assertEqual(self.launcher_verify().returncode, 0)
        path = self.module / "bin/zygiskd64"
        saved = self.base / "saved-daemon"
        path.rename(saved)
        try:
            path.symlink_to(saved)
            self.assertNotEqual(self.launcher_verify().returncode, 0)
        finally:
            path.unlink()
            saved.rename(path)
        path = self.module / "lib64"
        saved = self.base / "saved-lib64"
        path.rename(saved)
        try:
            path.symlink_to(saved, target_is_directory=True)
            self.assertNotEqual(self.launcher_verify().returncode, 0)
        finally:
            path.unlink()
            saved.rename(path)
        self.assertNotEqual(self.launcher_verify(str(self.module) + "/.").returncode, 0)

    def test_launcher_core_exact_set_and_installed_alias(self):
        extra = self.module / "bin/unlisted-core"
        try:
            extra.write_bytes(b"unsigned")
            self.assertNotEqual(self.launcher_verify().returncode, 0)
        finally:
            extra.unlink()
        alias = self.module / "bin/zygiskd"
        for target, accepted in [("./zygiskd64", True), ("zygiskd64", True), ("../bin/zygiskd64", False)]:
            try:
                alias.symlink_to(target)
                self.assertEqual(self.launcher_verify().returncode == 0, accepted)
            finally:
                alias.unlink()
        try:
            alias.write_bytes((self.module / "bin/zygiskd64").read_bytes())
            self.assertNotEqual(self.launcher_verify().returncode, 0)
        finally:
            alias.unlink()
        config = self.module / "ordinary-config.json"
        try:
            config.write_text('{"enabled": true}')
            self.assertEqual(self.launcher_verify().returncode, 0)
        finally:
            config.unlink()

    def test_extra_unsigned_core_is_rejected(self):
        path = self.module / "bin/extra"
        try:
            path.write_bytes(b"not covered")
            with self.assertRaisesRegex(ValueError, "unsigned extra"):
                V.make_manifest(self.module, self.context)
        finally:
            path.unlink()

    def test_executable_interpreter_policy(self):
        daemon = note_image(self.context, 3, 1, 0)
        V.check_elf_policy(daemon, 3, 1)
        verifier = note_image(self.context, 1, 1, 0)
        V.check_elf_policy(verifier, 1, 1)
        with self.assertRaisesRegex(ValueError, "expected Android PIE"):
            V.check_elf_policy(verifier.replace(b"linker64", b"unsafe64"), 1, 1)
        with self.assertRaisesRegex(ValueError, "expected Android"):
            V.check_elf_policy(daemon.replace(b"linker64", b"unsafe64"), 3, 1)
        with self.assertRaisesRegex(ValueError, "expected Android"):
            V.check_elf_policy(note_image(self.context, 3, 2, 0), 3, 1)

    def test_public_prepare_is_repeatable_and_tracks_build_configuration(self):
        with contextlib.redirect_stdout(io.StringIO()):
            V.prepare(self.args)
        self.assertEqual(V.read_context(self.context_dir), self.context)
        args = argparse.Namespace(**vars(self.args))
        args.out = str(self.base / "another-context")
        args.release_id = None
        with contextlib.redirect_stdout(io.StringIO()):
            V.prepare(args)
        first = V.read_context(args.out)
        args.build_config = "changed compiler/strip configuration"
        with contextlib.redirect_stdout(io.StringIO()):
            V.prepare(args)
        self.assertNotEqual(first["release_id"], V.read_context(args.out)["release_id"])

    def test_source_digest_ignores_generated_linker_output_but_tracks_sources(self):
        root = self.base / "source-fixture"
        (root / "kernel/core").mkdir(parents=True)
        source = root / "kernel/core/module.c"
        script = root / "kernel/core/viola_notes.lds"
        generated = root / "kernel/yukizygisk.lds"
        source.write_bytes(b"int source;\n")
        script.write_bytes(b"KEEP(*(.note.viola))\n")
        generated.write_bytes(b"old output")
        listing = b"kernel/core/module.c\0kernel/core/viola_notes.lds\0kernel/yukizygisk.lds\0"
        with patch.object(V, "ROOT", root), patch.object(V, "run", return_value=listing):
            first = type(self).real_source_digest()
            generated.write_bytes(b"new generated output")
            self.assertEqual(first, type(self).real_source_digest())
            script.write_bytes(b"changed real linker fragment")
            self.assertNotEqual(first, type(self).real_source_digest())
            changed = type(self).real_source_digest()
            source.write_bytes(b"int changed_source;\n")
            self.assertNotEqual(changed, type(self).real_source_digest())

    def test_sign_command_uses_production_verifier_and_rejects_changed_payload(self):
        args = argparse.Namespace(context=str(self.context_dir), module_dir=str(self.module),
            verifier=str(self.host_verifier), gpg=self.gpg, homedir=str(self.home))
        with contextlib.redirect_stdout(io.StringIO()), patch.dict(os.environ, {"VIOLA_GPG_PASSPHRASE": ""}):
            V.sign(args)
        result = subprocess.run([str(self.host_verifier), "verify", "--module-dir", str(self.module)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        path = self.module / "lib64/libzygisk.so"
        original = path.read_bytes()
        try:
            path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
            result = subprocess.run([str(self.host_verifier), "verify", "--module-dir", str(self.module)], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
        finally:
            path.write_bytes(original)


if __name__ == "__main__":
    unittest.main()
