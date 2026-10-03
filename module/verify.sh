#!/system/bin/sh
# SPDX-License-Identifier: MIT
#
# YukiZygisk - Verified package extraction.
# Adapted from RikkaApps/Riru-ModuleTemplate, template/magisk_module/verify.sh
# at 98a1203492fe56258fa15e06d5239333f3b342d0.
# Copyright (c) 2020 Rikka
# Copyright (c) 2026 Anatdx
# License: MIT (full terms are retained in the source copy at
# module/LICENSE-ModuleTemplate; generated packages do not carry legal files).
# Author: Rikka and Anatdx

abort_verify() {
	ui_print "! $1"
	abort "! This ZIP may be corrupted; please try downloading again"
}

# Only generated relative file names are accepted by unzip's pattern interface.
yz_verify_path() {
	case "$1" in
	''|/*|*/|*//*|*[!A-Za-z0-9_./+-]*|*.sha256)
		abort_verify "Invalid package file name: $1" ;;
	esac
	case "/$1/" in
	*/../*|*/./*) abort_verify "Invalid package file name: $1" ;;
	esac
}

# extract <zip> <file> <target dir>; checksum sidecars stay in temporary storage.
extract() {
	verify_zip=$1
	verify_file=$2
	verify_dir=$3
	yz_verify_path "$verify_file"
	verify_path="$verify_dir/$verify_file"
	verify_hash_path="$YZ_VERIFY_DIR/hashes/$verify_file.sha256"

	unzip -o "$verify_zip" "$verify_file" -d "$verify_dir" >&2 ||
		abort_verify "Unable to extract $verify_file"
	if [ ! -f "$verify_path" ] || [ -L "$verify_path" ]; then
		abort_verify "Missing package file: $verify_file"
	fi
	unzip -o "$verify_zip" "$verify_file.sha256" -d "$YZ_VERIFY_DIR/hashes" >&2 ||
		abort_verify "Unable to extract $verify_file.sha256"
	[ -f "$verify_hash_path" ] || abort_verify "Missing checksum: $verify_file"
	verify_hash="$(cat "$verify_hash_path")"
	[ "${#verify_hash}" -eq 64 ] || abort_verify "Invalid checksum: $verify_file"
	case "$verify_hash" in
	*[!0-9a-f]*) abort_verify "Invalid checksum: $verify_file" ;;
	esac
	(cd "$verify_dir" && printf '%s  %s\n' "$verify_hash" "$verify_file" | sha256sum -c - >/dev/null) ||
		abort_verify "Failed to verify $verify_file"
}

yz_verify_package() {
	ui_print "- Checking package integrity"
	mkdir -p "$YZ_VERIFY_DIR/hashes" || abort_verify "Cannot create checksum directory"
	# A checked inventory also catches a missing file together with its sidecar.
	extract "$ZIPFILE" files.list "$YZ_VERIFY_DIR"
	[ -s "$YZ_VERIFY_DIR/files.list" ] || abort_verify "Empty package file list"
	while IFS= read -r package_file || [ -n "$package_file" ]; do
		case "$package_file" in
		files.list) abort_verify "Invalid package file list" ;;
		customize.sh|verify.sh)
			extract "$ZIPFILE" "$package_file" "$YZ_VERIFY_DIR" ;;
		*) extract "$ZIPFILE" "$package_file" "$MODPATH" ;;
		esac
	done < "$YZ_VERIFY_DIR/files.list"
	ui_print "- Package integrity verified"
}
