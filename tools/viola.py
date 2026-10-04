#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# YukiZygisk - Viola public trust preparation and signed core packaging
# License: Apache-2.0
# Author: Anatdx
"""Build-time tooling. Never exports private keys; official signing is explicit."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
PRIMARY = "71B2B58C2A543472BE0DA0D8F580A2CEEF67DC98"
SIGNER = "C01D42FA249B2E23C28F4B0347E533340DE325A5"
MAGIC = b"VIOLA\0\1\0"
PROJECT = b"YukiZygisk".ljust(16, b"\0")
KMIS = ["none", "android12-5.10", "android13-5.10", "android13-5.15",
        "android14-5.15", "android14-6.1", "android15-6.6", "android16-6.12", "android17-6.18"]
PATHS = {(1, 1, 0): "bin/viola", (3, 1, 0): "bin/zygiskd64",
         (3, 2, 0): "bin/zygiskd32", (4, 1, 0): "bin/yzctl"}
for _role, _name in [(5, "libyukilinker.so"), (6, "libzygisk.so"), (7, "libyukizncore.so")]:
    PATHS[(_role, 1, 0)] = "lib64/" + _name
    PATHS[(_role, 2, 0)] = "lib/" + _name
for _kmi in range(1, len(KMIS)):
    PATHS[(2, 1, _kmi)] = "lkm/" + KMIS[_kmi] + "_yukizygisk.ko"


def fail(message):
    raise ValueError(message)


def run(command, data=None):
    result = subprocess.run([str(x) for x in command], input=data, capture_output=True)
    if result.returncode:
        fail(f"{Path(str(command[0])).name} failed: " + result.stderr.decode(errors="replace").strip())
    return result.stdout


def gpg(args, *extra, data=None, home=None):
    command = [args.gpg, "--no-options", "--batch", "--yes", "--no-auto-key-retrieve"]
    keyhome = home or args.homedir or os.environ.get("GNUPGHOME")
    if keyhome:
        command += ["--homedir", str(keyhome)]
    return run(command + list(extra), data)


def dearmor(data):
    if not data.startswith(b"-----BEGIN"):
        return data
    lines = data.decode("ascii").splitlines()
    if lines[0] != "-----BEGIN PGP PUBLIC KEY BLOCK-----":
        fail("expected a public-key certificate, never secret-key material")
    body = False
    encoded = []
    for line in lines[1:]:
        if not body:
            if not line:
                body = True
            continue
        if line.startswith("-----END"):
            break
        if line and not line.startswith("="):
            encoded.append(line)
    return base64.b64decode("".join(encoded), validate=True)


def take_length(data, pos, subpacket=False):
    if pos >= len(data):
        fail("truncated OpenPGP length")
    lead = data[pos]
    pos += 1
    if lead < 192:
        return lead, pos
    if lead < 255 and (subpacket or lead < 224):
        if pos >= len(data):
            fail("truncated OpenPGP length")
        return ((lead - 192) << 8) + data[pos] + 192, pos + 1
    if lead == 255 and pos + 4 <= len(data):
        return int.from_bytes(data[pos:pos + 4], "big"), pos + 4
    fail("unsupported or truncated OpenPGP length")


def packets(data):
    pos = 0
    while pos < len(data):
        first = data[pos]
        pos += 1
        if not first & 128:
            fail("invalid OpenPGP packet")
        if first & 64:
            tag = first & 63
            size, pos = take_length(data, pos)
        else:
            tag = (first >> 2) & 15
            mode = first & 3
            if mode == 3 or pos + (1 << mode) > len(data):
                fail("indeterminate or truncated public-key packet")
            width = 1 << mode
            size = int.from_bytes(data[pos:pos + width], "big")
            pos += width
        if not size or pos + size > len(data):
            fail("truncated public-key packet")
        if tag in (5, 7):
            fail("secret keys are forbidden in public build inputs")
        yield tag, data[pos:pos + size]
        pos += size


def subpackets(data):
    pos = 0
    fields = {}
    while pos < len(data):
        size, pos = take_length(data, pos, True)
        if not size or pos + size > len(data):
            fail("truncated signature subpacket")
        kind = data[pos] & 127
        critical = data[pos] & 128
        if critical and kind not in (2, 3, 9, 16, 27, 29, 32, 33):
            fail("unsupported critical certificate subpacket")
        value = data[pos + 1:pos + size]
        if kind in fields and kind != 32:
            fail("ambiguous duplicate certificate subpacket")
        fields.setdefault(kind, []).append(value)
        pos += size
    return fields


def signature(body):
    if len(body) < 10 or body[0] != 4 or body[2] != 22 or body[3] not in (8, 9, 10):
        fail("certificate signatures must be v4 Ed25519 with SHA256/384/512")
    hlen = int.from_bytes(body[4:6], "big")
    end = 6 + hlen
    if end + 2 > len(body):
        fail("truncated certificate signature")
    ulen = int.from_bytes(body[end:end + 2], "big")
    pos = end + 2 + ulen
    if pos + 2 > len(body):
        fail("truncated certificate signature")
    hashed = subpackets(body[6:end])
    unhashed = subpackets(body[end + 2:pos])
    prefix = body[pos:pos + 2]
    pos += 2
    raw = bytearray()
    for _ in range(2):
        if pos + 2 > len(body):
            fail("truncated signature MPI")
        bits = int.from_bytes(body[pos:pos + 2], "big")
        pos += 2
        size = (bits + 7) // 8
        value = body[pos:pos + size]
        if not 1 <= size <= 32 or len(value) != size or int.from_bytes(value, "big").bit_length() != bits:
            fail("invalid signature MPI")
        raw += value.rjust(32, b"\0")
        pos += size
    if pos != len(body):
        fail("trailing certificate signature data")
    return {"body": body, "type": body[1], "hash": body[3], "hashed": hashed,
            "unhashed": unhashed, "header": body[:end], "prefix": prefix, "raw": bytes(raw)}


def scalar(sig, kind, default=0):
    values = sig["hashed"].get(kind)
    if not values:
        return default
    if len(values) != 1 or len(values[0]) != 4:
        fail("invalid certificate time field")
    return int.from_bytes(values[0], "big")


def key_frame(body):
    if len(body) > 65535 or len(body) < 6 or body[0] != 4:
        fail("only v4 public keys are supported")
    return b"\x99" + len(body).to_bytes(2, "big") + body


def key_fingerprint(body):
    return hashlib.sha1(key_frame(body)).hexdigest().upper()


def raw_key(body):
    if len(body) != 51 or body[5:19] != bytes.fromhex("16092b06010401da470f01010740"):
        fail("approved keys must use the Ed25519Legacy curve")
    return body[19:]


def verify_cert_signature(sig, public, message):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    h = hashlib.new({8: "sha256", 9: "sha384", 10: "sha512"}[sig["hash"]])
    h.update(message + sig["header"] + b"\x04\xff" + len(sig["header"]).to_bytes(4, "big"))
    digest = h.digest()
    if digest[:2] != sig["prefix"]:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(sig["raw"], digest)
        return True
    except (InvalidSignature, ValueError):
        return False


def valid_time(sig, now):
    created = scalar(sig, 2)
    expiry = scalar(sig, 3)
    return created > 0 and created <= now and (not expiry or now < created + expiry)


def validate_certificate(data, signer_fpr, profile):
    """Validate the selected chain itself, not only GPG's printed key flags."""
    if not data or len(data) > 65536:
        fail("public certificate exceeds its 64 KiB bound")
    rows = list(packets(data))
    if not rows or rows[0][0] != 6 or sum(tag == 6 for tag, _ in rows) != 1:
        fail("expected exactly one primary public key")
    primary = rows[0][1]
    primary_fpr = key_fingerprint(primary)
    primary_raw = raw_key(primary)
    if primary_fpr == signer_fpr:
        fail("select a signing subkey, not the primary certification key")
    if profile == "official" and (primary_fpr != PRIMARY or signer_fpr != SIGNER):
        fail("official builds require the pinned publisher and CI signing subkey")
    if profile == "dev" and (primary_fpr == PRIMARY or signer_fpr == SIGNER):
        fail("development builds require an independent development key")
    now = int(time.time())
    selves = []
    bindings = []
    revocations = []
    subkey = None
    current_key = primary
    current_uid = None
    for tag, body in rows[1:]:
        if tag == 13:
            current_uid = body
            current_key = primary
        elif tag == 14:
            current_key = body
            current_uid = None
            if key_fingerprint(body) == signer_fpr:
                if subkey is not None:
                    fail("duplicate selected subkey")
                subkey = body
        elif tag == 2:
            sig = signature(body)
            message = key_frame(primary)
            if sig["type"] in (0x10, 0x11, 0x12, 0x13) and current_uid is not None:
                message += b"\xb4" + len(current_uid).to_bytes(4, "big") + current_uid
                if verify_cert_signature(sig, primary_raw, message) and valid_time(sig, now):
                    selves.append(sig)
            elif sig["type"] == 0x1f and current_key == primary:
                if verify_cert_signature(sig, primary_raw, message) and valid_time(sig, now):
                    selves.append(sig)
            elif sig["type"] == 0x20:
                if verify_cert_signature(sig, primary_raw, message):
                    fail("publisher primary key is revoked")
            elif sig["type"] in (0x18, 0x28) and current_key != primary:
                if key_fingerprint(current_key) != signer_fpr:
                    continue
                message += key_frame(current_key)
                if verify_cert_signature(sig, primary_raw, message):
                    (bindings if sig["type"] == 0x18 else revocations).append(sig)
        elif tag not in (17, 12):
            fail("unsupported packet in public certificate")
        else:
            current_uid = None
    if not selves or subkey is None or not bindings:
        fail("missing valid primary self-signature or selected subkey binding")
    if revocations:
        fail("selected signing subkey is revoked")
    primary_self = max(selves, key=lambda s: scalar(s, 2))
    binding = max(bindings, key=lambda s: scalar(s, 2))
    if not valid_time(binding, now):
        fail("selected subkey binding is expired or not yet valid")
    for body, sig in [(primary, primary_self), (subkey, binding)]:
        born = int.from_bytes(body[1:5], "big")
        expires = scalar(sig, 9)
        if born > now or (expires and now >= born + expires):
            fail("publisher or selected signing subkey is expired or not yet valid")
    flags = binding["hashed"].get(27, [])
    if len(flags) != 1 or not flags[0] or not flags[0][0] & 2:
        fail("selected subkey has no signed data-signing capability")
    sub_raw = raw_key(subkey)
    backsigs = binding["hashed"].get(32, []) + binding["unhashed"].get(32, [])
    good_back = False
    for body in backsigs:
        back = signature(body)
        if back["type"] == 0x19 and valid_time(back, now) and verify_cert_signature(
                back, sub_raw, key_frame(primary) + key_frame(subkey)):
            good_back = True
    if not good_back:
        fail("selected signing subkey lacks a valid primary-key back signature")
    return primary_fpr, primary_raw, sub_raw


def initializer(value):
    return "{" + ",".join(f"0x{x:02x}" for x in value) + "}"


def source_digest():
    """Hash production inputs, including new sources, excluding build/test debris."""
    names = set(run(["git", "-C", ROOT, "ls-files", "-z", "--cached", "--others", "--exclude-standard"]).split(b"\0"))
    names.update(run(["git", "-C", ROOT, "ls-files", "-z", "--recurse-submodules"]).split(b"\0"))
    extensions = {".c", ".cc", ".cpp", ".h", ".hpp", ".S", ".s", ".asm", ".inc",
                  ".cmake", ".ld", ".lds", ".asc", ".pgp"}
    exact = {"CMakeLists.txt", "build.sh", "build.ps1", "tools/viola.py", "tools/requirements-viola.txt"}
    digest = hashlib.sha512(b"YukiZygisk Viola source inputs v1\0")
    for raw in sorted(name for name in names if name):
        name = raw.decode("utf-8")
        if name == "kernel/yukizygisk.lds":
            continue  # DDK-generated CFI linker output, not a source input.
        path = ROOT / name
        source = (name.startswith(("kernel/", "userspace/", "shared/viola/", "uapi/")) and
                  (path.suffix in extensions or path.name in ("Makefile", "Kbuild", "CMakeLists.txt")))
        if not (source or name in exact) or not path.is_file():
            continue
        data = path.read_bytes()
        digest.update(struct.pack("<I", len(raw)) + raw + struct.pack("<Q", len(data)) + data)
    return digest.hexdigest()


def trust_id(profile, primary_fpr, signer, primary_raw, public_raw):
    return hashlib.sha512(b"YukiZygisk Viola trust v1\0" + struct.pack("<I", profile) +
                          bytes.fromhex(primary_fpr + signer) + primary_raw + public_raw).digest()[:32].hex()


def generated_header(context):
    lines = ["/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */", "/*",
             " * YukiZygisk - Generated public Viola build configuration", " *",
             " * License: Author's work under Apache-2.0; when used as a kernel module",
             " * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.",
             " *", " * Author: Anatdx", " */",
             "#ifndef YUKIZYGISK_VIOLA_BUILD_H", "#define YUKIZYGISK_VIOLA_BUILD_H"]
    for macro, key in [("RELEASE_ID", "release_id"), ("TRUST_ID", "trust_id"),
                       ("PUBLIC_KEY", "public_key"), ("PRIMARY_PUBLIC_KEY", "primary_public_key"),
                       ("SIGNER_FINGERPRINT", "signer_fingerprint"),
                       ("PRIMARY_FINGERPRINT", "primary_fingerprint")]:
        lines += [f"#define VIOLA_{macro}_BYTES {initializer(bytes.fromhex(context[key]))}",
                  f'#define VIOLA_{macro}_HEX "{context[key]}"']
    lines += [f'#define VIOLA_PROFILE {context["profile"]}u',
              f'#define VIOLA_PROFILE_NAME "{context["profile_name"]}"',
              f'#define VIOLA_VERSION_CODE {context["version_code"]}ull',
              "#ifndef VIOLA_BUILD_KMI", "#define VIOLA_BUILD_KMI 0u", "#endif", "#endif", ""]
    return "\n".join(lines)


def read_context(directory):
    return json.loads((Path(directory) / "context.json").read_text(encoding="utf-8"))


def prepare(args):
    signer = (args.key or (SIGNER if args.profile == "official" else "")).upper().removesuffix("!")
    if not re.fullmatch(r"[0-9A-F]{40}", signer):
        fail("--key must identify an exact full signing-subkey fingerprint")
    if args.public_key:
        data = dearmor(Path(args.public_key).read_bytes())
    elif args.profile == "official":
        data = dearmor((ROOT / "shared/viola/publisher.asc").read_bytes())
    else:
        data = gpg(args, "--export", signer)
    primary_fpr, primary_raw, public_raw = validate_certificate(data, signer, args.profile)
    # The independent GPG parser must also accept this public-only certificate.
    with tempfile.TemporaryDirectory(prefix="viola-public-") as directory:
        os.chmod(directory, 0o700)
        gpg(args, "--import", data=data, home=directory)
        listing = gpg(args, "--with-colons", "--with-fingerprint", "--check-sigs", primary_fpr,
                      home=directory).decode("utf-8", errors="replace")
        if not any(line.startswith("fpr:") and line.split(":")[9] == signer for line in listing.splitlines()):
            fail("GPG did not retain the selected certified subkey")
    revision = args.source_revision or run(["git", "-C", ROOT, "rev-parse", "HEAD"]).decode().strip()
    version = args.version_code
    if version is None:
        version = int(run(["git", "-C", ROOT, "rev-list", "--count", "HEAD"])) + 10000
    if not 0 < version < 2**64:
        fail("invalid version code")
    profile = 1 if args.profile == "official" else 2
    trust = trust_id(profile, primary_fpr, signer, primary_raw, public_raw)
    context = {"format": 1, "profile": profile, "profile_name": args.profile, "policy": 1, "protocol": 2,
               "source_revision": revision, "source_digest": source_digest(), "build_config": args.build_config,
               "version_code": version, "trust_id": trust,
               "primary_fingerprint": primary_fpr, "signer_fingerprint": signer,
               "primary_public_key": primary_raw.hex(), "public_key": public_raw.hex()}
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    previous = None
    if (out / "context.json").exists():
        previous = read_context(out)
    if args.release_id:
        release = args.release_id.lower()
    elif previous and all(previous.get(k) == v for k, v in context.items()):
        release = previous["release_id"]
    else:
        release = secrets.token_hex(32)
    if not re.fullmatch(r"[0-9a-f]{64}", release) or int(release, 16) == 0:
        fail("release ID must contain exactly 32 nonzero hexadecimal bytes")
    context["release_id"] = release
    (out / "context.json").write_text(json.dumps(context, indent=2) + "\n", encoding="utf-8")
    (out / "viola_build.h").write_text(generated_header(context), encoding="utf-8")
    (out / "publisher.pgp").write_bytes(data)
    print(json.dumps(context, indent=2))


def image_identity(data, loader_note=False):
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[5] != 1 or data[4] not in (1, 2):
        fail("core image is not a little-endian ELF")
    if data[4] == 2:
        shoff = struct.unpack_from("<Q", data, 40)[0]
        shsize, shnum, shstr = struct.unpack_from("<HHH", data, 58)
        size_min, offset_field, size_field = 64, 24, 32
        word = "<Q"
    else:
        shoff = struct.unpack_from("<I", data, 32)[0]
        shsize, shnum, shstr = struct.unpack_from("<HHH", data, 46)
        size_min, offset_field, size_field = 40, 16, 20
        word = "<I"
    if shsize < size_min or not shnum or shnum > 4096 or shstr >= shnum or shoff + shsize * shnum > len(data):
        fail("invalid ELF section table")
    def section(index):
        start = shoff + shsize * index
        name = struct.unpack_from("<I", data, start)[0]
        off = struct.unpack_from(word, data, start + offset_field)[0]
        length = struct.unpack_from(word, data, start + size_field)[0]
        if off + length > len(data):
            fail("ELF section exceeds image")
        return name, data[off:off + length]
    _, names = section(shstr)
    notes = []
    for index in range(shnum):
        start = shoff + shsize * index
        name = struct.unpack_from("<I", data, start)[0]
        if name >= len(names):
            fail("invalid ELF section name")
        wanted = b".note.viola.loader" if loader_note else b".note.viola"
        if names[name:].split(b"\0", 1)[0] == wanted:
            notes.append(section(index)[1])
    if loader_note:
        if len(notes) != 1 or len(notes[0]) != 92:
            fail("KO must contain exactly one intact Viola loader digest note")
        note = notes[0]
        if (struct.unpack_from("<III", note) != (6, 72, 2) or
                note[12:20] != b"VIOLA\0\0\0" or note[20:28] != b"VIOLALDR"):
            fail("invalid KO loader digest note")
        return {"loader_sha512": note[28:92].hex()}
    if len(notes) != 1 or len(notes[0]) != 124:
        fail("ELF must contain exactly one intact Viola identity note")
    note = notes[0]
    if struct.unpack_from("<III", note) != (6, 104, 1) or note[12:20] != b"VIOLA\0\0\0" or note[20:28] != b"VIOLAID1":
        fail("unsupported Viola identity note")
    profile, policy, protocol, role, abi, kmi, version = struct.unpack_from("<IIIIIIQ", note, 28)
    machine = struct.unpack_from("<H", data, 18)[0]
    if (abi, data[4], machine) not in ((1, 2, 183), (2, 1, 40)):
        fail("ELF machine/class differs from its Viola ABI identity")
    return {"profile": profile, "policy": policy, "protocol": protocol, "role": role,
            "abi": abi, "kmi": kmi, "version_code": version,
            "release_id": note[60:92].hex(), "trust_id": note[92:124].hex()}


def check_elf_policy(data, role, abi):
    """Inspect load-time program headers, not spoofable section-name metadata."""
    is64 = data[4] == 2
    kind = struct.unpack_from("<H", data, 16)[0]
    if is64:
        phoff = struct.unpack_from("<Q", data, 32)[0]
        phsize, phnum = struct.unpack_from("<HH", data, 54)
        minimum = 56
    else:
        phoff = struct.unpack_from("<I", data, 28)[0]
        phsize, phnum = struct.unpack_from("<HH", data, 42)
        minimum = 32
    if phnum and (phsize < minimum or phnum > 1024 or phoff + phsize * phnum > len(data)):
        fail("invalid ELF program headers")
    segments = []
    for i in range(phnum):
        start = phoff + i * phsize
        if is64:
            tag, _flags, offset, address, _physical, size, _memory, _align = struct.unpack_from("<IIQQQQQQ", data, start)
        else:
            tag, offset, address, _physical, size, _memory, _flags, _align = struct.unpack_from("<IIIIIIII", data, start)
        if offset + size > len(data):
            fail("ELF segment exceeds file")
        segments.append((tag, offset, address, size))
    interpreters = [data[offset:offset + size] for tag, offset, _, size in segments if tag == 3]
    dynamics = [(offset, size) for tag, offset, _, size in segments if tag == 2]
    if len(interpreters) > 1 or len(dynamics) > 1:
        fail("ambiguous ELF interpreter or dynamic table")
    needed = []
    if dynamics:
        offset, size = dynamics[0]
        width = 16 if is64 else 8
        if size % width:
            fail("invalid ELF dynamic table size")
        string_address = string_size = None
        ended = False
        for cursor in range(offset, offset + size, width):
            tag, value = struct.unpack_from("<QQ" if is64 else "<II", data, cursor)
            if tag == 0:
                ended = True
                break
            if tag in (15, 29):
                fail("core ELF must not have RPATH or RUNPATH")
            if tag == 1:
                needed.append(value)
            elif tag == 5:
                if string_address is not None:
                    fail("duplicate ELF dynamic string table")
                string_address = value
            elif tag == 10:
                if string_size is not None:
                    fail("duplicate ELF dynamic string size")
                string_size = value
        if not ended:
            fail("unterminated ELF dynamic table")
        if needed:
            if string_address is None or string_size is None or string_size > len(data):
                fail("missing ELF dependency strings")
            locations = [offset + string_address - address for tag, offset, address, size in segments
                         if tag == 1 and address <= string_address and string_address + string_size <= address + size]
            if len(locations) != 1:
                fail("ELF dynamic strings are not in one file-backed LOAD segment")
            strings = data[locations[0]:locations[0] + string_size]
            resolved = []
            for index in needed:
                end = strings.find(b"\0", index)
                if index >= len(strings) or end < 0:
                    fail("invalid ELF dependency name")
                resolved.append(strings[index:end])
            needed = resolved
    if role == 1:
        expected = b"/system/bin/linker64\0" if abi == 1 else b"/system/bin/linker\0"
        if kind != 3 or interpreters != [expected]:
            fail("Viola must use the expected Android PIE interpreter")
        if any(name not in (b"libc.so", b"libm.so", b"libdl.so") for name in needed):
            fail("Viola depends on a non-approved shared library")
    elif role == 3:
        expected = b"/system/bin/linker64\0" if abi == 1 else b"/system/bin/linker\0"
        if kind != 3 or interpreters != [expected]:
            fail("daemon must use the expected Android system interpreter")
        if any(name not in (b"libc.so", b"libm.so", b"libdl.so") for name in needed):
            fail("daemon depends on a non-approved shared library")
    elif role != 2:
        if any(name not in (b"libc.so", b"libm.so", b"libdl.so", b"liblog.so") for name in needed):
            fail("core ELF depends on a non-approved shared library")


def check_image(data, context, role, abi, kmi):
    identity = image_identity(data)
    for field in ("profile", "policy", "protocol", "version_code", "release_id", "trust_id"):
        if identity[field] != context[field]:
            fail(f"core image differs from build context: {field}")
    if (identity["role"], identity["abi"], identity["kmi"]) != (role, abi, kmi):
        fail("core image has a different role, ABI or KMI")
    check_elf_policy(data, role, abi)


def loader(args):
    context = read_context(args.context)
    data = Path(args.image).read_bytes()
    check_image(data, context, 1, 1, 0)
    digest = hashlib.sha512(data).digest()
    text = ("/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */\n/*\n"
            " * YukiZygisk - Generated public Viola loader identity\n *\n"
            " * License: Author's work under Apache-2.0; when used as a kernel module\n"
            " * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.\n"
            " *\n * Author: Anatdx\n */\n"
            "#ifndef YUKIZYGISK_VIOLA_LOADER_H\n#define YUKIZYGISK_VIOLA_LOADER_H\n"
            f"#define VIOLA_LOADER_SHA512_BYTES {initializer(digest)}\n"
            f'#define VIOLA_LOADER_SHA512_HEX "{digest.hex()}"\n#endif\n')
    (Path(args.context) / "viola_loader.h").write_text(text, encoding="utf-8")
    (Path(args.context) / "loader.json").write_text(json.dumps({"sha512": digest.hex(),
        "release_id": context["release_id"], "trust_id": context["trust_id"]}, indent=2) + "\n", encoding="utf-8")
    print(digest.hex())


def make_manifest(directory, context):
    directory = Path(directory)
    if directory.is_symlink():
        fail("module directory cannot be a symlink")
    for folder in ("bin", "lkm", "lib", "lib64"):
        if (directory / folder).is_symlink():
            fail(f"core directory cannot be a symlink: {folder}")
    viola_image = directory / "bin/viola"
    if not viola_image.is_file() or viola_image.is_symlink():
        fail("missing regular Viola executable")
    loader_hash = hashlib.sha512(viola_image.read_bytes()).hexdigest()
    rows = []
    for (role, abi, kmi), relative in sorted(PATHS.items()):
        path = directory / relative
        if path.is_symlink():
            fail(f"core images cannot be symlinks: {relative}")
        if not path.exists():
            if role == 2:
                continue
            fail(f"missing core image: {relative}")
        if not path.is_file():
            fail(f"core image is not a regular file: {relative}")
        data = path.read_bytes()
        check_image(data, context, role, abi, kmi)
        if role == 2 and image_identity(data, loader_note=True)["loader_sha512"] != loader_hash:
            fail("KO was built for different Viola executable bytes")
        rows.append(struct.pack("<HHIIIQ", role, abi, kmi, 0, 0, len(data)) + hashlib.sha512(data).digest())
    if not any((directory / PATHS[(2, 1, kmi)]).exists() for kmi in range(1, len(KMIS))):
        fail("package has no supported kernel module")
    allowed = set(PATHS.values())
    for folder in ("bin", "lkm", "lib", "lib64"):
        base = directory / folder
        if base.is_symlink():
            fail(f"core directory cannot be a symlink: {folder}")
        for path in base.rglob("*"):
            if path.is_dir() and not path.is_symlink():
                continue
            relative = path.relative_to(directory).as_posix()
            if relative not in allowed:
                fail(f"unsigned extra core image: {relative}")
    header = bytearray(128)
    header[:8] = MAGIC
    struct.pack_into("<HHIHHIII", header, 8, 1, 128, 128 + 88 * len(rows), len(rows), 88,
                     context["profile"], context["policy"], context["protocol"])
    header[32:64] = bytes.fromhex(context["release_id"])
    header[64:96] = bytes.fromhex(context["trust_id"])
    struct.pack_into("<Q", header, 96, context["version_code"])
    header[104:120] = PROJECT
    if len(rows) > 64 or 128 + 88 * len(rows) > 8192:
        fail("manifest exceeds format limits")
    return bytes(header) + b"".join(rows)


def manifest(args):
    context = read_context(args.context)
    directory = Path(args.module_dir)
    data = make_manifest(directory, context)
    (directory / "viola.manifest").write_bytes(data)
    (directory / "viola.pgp").write_bytes((Path(args.context) / "publisher.pgp").read_bytes())
    print(f"Wrote {len(data)}-byte manifest")


def sign(args):
    context = read_context(args.context)
    certificate = (Path(args.context) / "publisher.pgp").read_bytes()
    primary, primary_raw, public_raw = validate_certificate(certificate, context["signer_fingerprint"], context["profile_name"])
    if (primary != context["primary_fingerprint"] or primary_raw.hex() != context["primary_public_key"] or
            public_raw.hex() != context["public_key"] or trust_id(context["profile"], primary,
            context["signer_fingerprint"], primary_raw, public_raw) != context["trust_id"]):
        fail("public signing certificate differs from the compiled trust context")
    secret_listing = gpg(args, "--with-colons", "--list-secret-keys", context["signer_fingerprint"])
    available = False
    record = None
    for line in secret_listing.decode("utf-8", errors="replace").splitlines():
        fields = line.split(":")
        if fields[0] in ("sec", "ssb"):
            record = fields
        elif fields[0] == "fpr" and len(fields) > 9 and fields[9] == context["signer_fingerprint"]:
            available = record is not None and len(record) > 14 and record[14] != "#"
    if not available:
        fail("GPG keyring lacks the approved signing subkey's private material")
    if source_digest() != context["source_digest"]:
        fail("production sources changed after build context preparation")
    manifest(args)
    directory = Path(args.module_dir).resolve()
    output = directory / "viola.sig"
    output.unlink(missing_ok=True)
    options = ["--local-user", context["signer_fingerprint"] + "!", "--digest-algo", "SHA512",
               "--output", str(output), "--detach-sign", str(directory / "viola.manifest")]
    passphrase = os.environ.get("VIOLA_GPG_PASSPHRASE")
    incoming = None
    if passphrase is not None:
        if "\n" in passphrase or "\r" in passphrase:
            fail("passphrase input contains a newline")
        options = ["--pinentry-mode", "loopback", "--passphrase-fd", "0"] + options
        incoming = (passphrase + "\n").encode()
    try:
        gpg(args, *options, data=incoming)
        if not output.is_file() or not 0 < output.stat().st_size <= 4096:
            fail("GPG produced an invalid-size signature")
        run([args.verifier, "verify", "--module-dir", directory])
    except Exception:
        output.unlink(missing_ok=True)
        raise
    print("Signed core manifest and verified the complete package")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    def gpg_options(p):
        p.add_argument("--gpg", default="gpg")
        p.add_argument("--homedir")
    p = sub.add_parser("prepare")
    p.add_argument("--out", required=True)
    p.add_argument("--profile", choices=("official", "dev"), required=True)
    p.add_argument("--key")
    p.add_argument("--public-key")
    p.add_argument("--version-code", type=int)
    p.add_argument("--release-id")
    p.add_argument("--source-revision")
    p.add_argument("--build-config", default="")
    gpg_options(p)
    p.set_defaults(function=prepare)
    p = sub.add_parser("loader")
    p.add_argument("--context", required=True)
    p.add_argument("--image", required=True)
    p.set_defaults(function=loader)
    for name, function in [("manifest", manifest), ("sign", sign)]:
        p = sub.add_parser(name)
        p.add_argument("--context", required=True)
        p.add_argument("--module-dir", required=True)
        if name == "sign":
            p.add_argument("--verifier", required=True)
            gpg_options(p)
        p.set_defaults(function=function)
    args = parser.parse_args()
    try:
        args.function(args)
    except (ValueError, OSError, ImportError, KeyError) as error:
        parser.exit(1, f"viola: {error}\n")


if __name__ == "__main__":
    main()
