#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# YukiZygisk - Installation package SHA-256 integrity metadata.
# License: Apache-2.0
# Author: Anatdx
"""Generate corruption checks for a final module directory, without signing it."""

import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile


SAFE_PATH = re.compile(r"[A-Za-z0-9_./+\-]+", re.ASCII)
FILE_LIST = "files.list"
HASH_SUFFIX = ".sha256"


def is_link(path):
    return path.is_symlink() or (
        hasattr(path, "is_junction") and path.is_junction()
    )


def collect_files(root):
    files = {}
    pending = [root]
    while pending:
        for path in pending.pop().iterdir():
            relative = path.relative_to(root).as_posix()
            if (not SAFE_PATH.fullmatch(relative) or
                    any(part in ("", ".", "..") for part in relative.split("/"))):
                raise ValueError(f"unsafe package path: {relative!r}")
            if is_link(path):
                raise ValueError(f"package links are not allowed: {relative}")
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                if relative == FILE_LIST:
                    raise ValueError("files.list must be a regular file")
                pending.append(path)
            elif stat.S_ISREG(info.st_mode):
                if info.st_nlink > 1:
                    raise ValueError(f"package hard links are not allowed: {relative}")
                files[relative] = path
            else:
                raise ValueError(f"package entry is not a regular file: {relative}")
    return files


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().encode("ascii")


def write_metadata(path, data):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
                mode="wb", prefix=".module-checksums-", dir=path.parent,
                delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
        temporary.chmod(0o644)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def generate(module_dir):
    if is_link(module_dir):
        raise ValueError("module directory must not be a link")
    root = module_dir.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("module directory is not a directory")
    files = collect_files(root)
    payloads = sorted(name for name in files
                      if name != FILE_LIST and not name.endswith(HASH_SUFFIX))
    allowed_hashes = {name + HASH_SUFFIX for name in payloads}
    if FILE_LIST in files:
        allowed_hashes.add(FILE_LIST + HASH_SUFFIX)
    for name in files:
        if name.endswith(HASH_SUFFIX) and name not in allowed_hashes:
            raise ValueError(f"orphan checksum file: {name}")

    # Validate the whole tree before replacing any previously generated data.
    digests = {name: sha256_file(files[name]) for name in payloads}
    listing = "".join(name + "\n" for name in payloads).encode("utf-8")
    for name in payloads:
        write_metadata(root / (name + HASH_SUFFIX), digests[name])
    write_metadata(root / FILE_LIST, listing)
    write_metadata(root / (FILE_LIST + HASH_SUFFIX),
                   hashlib.sha256(listing).hexdigest().encode("ascii"))
    return len(payloads)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("module_dir", type=Path, metavar="MODULE_DIR")
    args = parser.parse_args()
    try:
        count = generate(args.module_dir)
    except (OSError, ValueError) as error:
        parser.exit(1, f"module_checksums: {error}\n")
    print(f"Generated files.list and SHA-256 checksums for {count} files")


if __name__ == "__main__":
    main()
