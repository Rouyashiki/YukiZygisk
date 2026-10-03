#!/system/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# YukiZygisk module install hook.
#
# License: Apache-2.0
#
# Author: Anatdx

# shellcheck disable=SC2034
SKIPUNZIP=1

ui_print "- Installing YukiZygisk"

# Bootstrap the shell verifier before executing any packaged binary.
YZ_VERIFY_DIR="$(mktemp -d "$TMPDIR/yz-verify.XXXXXX")" ||
	abort "! Cannot create package verification directory"
unzip -o "$ZIPFILE" verify.sh verify.sh.sha256 -d "$YZ_VERIFY_DIR" >&2 ||
	abort "! Cannot extract verifier; please try downloading the ZIP again"
if [ ! -f "$YZ_VERIFY_DIR/verify.sh" ] || [ -L "$YZ_VERIFY_DIR/verify.sh" ] ||
	[ ! -f "$YZ_VERIFY_DIR/verify.sh.sha256" ] ||
	[ -L "$YZ_VERIFY_DIR/verify.sh.sha256" ]; then
	abort "! Missing verifier; please try downloading the ZIP again"
fi
YZ_VERIFY_HASH="$(cat "$YZ_VERIFY_DIR/verify.sh.sha256")"
[ "${#YZ_VERIFY_HASH}" -eq 64 ] ||
	abort "! Invalid verifier checksum; please try downloading the ZIP again"
case "$YZ_VERIFY_HASH" in
*[!0-9a-f]*) abort "! Invalid verifier checksum; please try downloading the ZIP again" ;;
esac
(cd "$YZ_VERIFY_DIR" && printf '%s  verify.sh\n' "$YZ_VERIFY_HASH" | sha256sum -c - >/dev/null) ||
	abort "! Corrupted verifier; please try downloading the ZIP again"
# shellcheck source=/dev/null
. "$YZ_VERIFY_DIR/verify.sh"
yz_verify_package

# SKIPUNZIP also skips the installer's default ownership, modes and labels.
set_perm_recursive "$MODPATH" 0 0 0755 0644

[ -f "$MODPATH/bin/viola" ] || abort "! Missing Viola verifier"
chmod 0755 "$MODPATH/bin/viola" || abort "! Cannot execute Viola"
# Remove linker controls before starting the environment utility itself.
unset LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT LD_CONFIG_FILE LD_DEBUG LD_DEBUG_OUTPUT
/system/bin/env -i PATH=/system/bin:/system/xbin "$MODPATH/bin/viola" verify --module-dir "$MODPATH" ||
	abort "! YukiZygisk core verification failed"

[ -f "$MODPATH/common.sh" ] || abort "! Missing module KMI helpers"
# shellcheck source=/dev/null
. "$MODPATH/common.sh"

ABI="$(getprop ro.product.cpu.abi 2>/dev/null)"
case "$ABI" in
arm64-v8a) ;;
*) abort "! Unsupported ABI for this package: $ABI" ;;
esac

KERNEL_RELEASE="$(uname -r 2>/dev/null)"
KMI="$(yz_detect_kmi "$KERNEL_RELEASE")" ||
	abort "! Cannot detect GKI KMI from kernel release: $KERNEL_RELEASE"
KERNEL_MODULE="$(yz_kmi_ko "$MODPATH" "$KMI")"
if [ ! -f "$KERNEL_MODULE" ]; then
	SUPPORTED_KMIS="$(yz_list_supported_kmis "$MODPATH" | tr '\n' ' ')"
	abort "! Package has no module for $KMI (available: ${SUPPORTED_KMIS:-none})"
fi
[ -f "$MODPATH/bin/zygiskd64" ] || abort "! Missing bin/zygiskd64"
[ -f "$MODPATH/bin/zygiskd32" ] || abort "! Missing bin/zygiskd32"
[ -f "$MODPATH/bin/yzctl" ] || abort "! Missing bin/yzctl"
for lib in \
	"$MODPATH/lib64/libzygisk.so" "$MODPATH/lib64/libyukilinker.so" \
	"$MODPATH/lib64/libyukizncore.so" "$MODPATH/lib/libzygisk.so" \
	"$MODPATH/lib/libyukilinker.so" "$MODPATH/lib/libyukizncore.so"; do
	[ -f "$lib" ] || abort "! Missing ${lib#"$MODPATH/"}"
done

ln -sf ./zygiskd64 "$MODPATH/bin/zygiskd"

chmod 0644 "$MODPATH"/lkm/*.ko "$MODPATH/common.sh"
chmod 0644 "$MODPATH"/lib64/*.so "$MODPATH"/lib/*.so
chmod 0755 "$MODPATH/bin/zygiskd64" "$MODPATH/bin/zygiskd32" "$MODPATH/bin/yzctl" \
	"$MODPATH/post-fs-data.sh" \
	"$MODPATH/boot-completed.sh" "$MODPATH/action.sh"

BASE_DIR="/data/adb/yukizygisk"
mkdir -p "$BASE_DIR/lib"
chmod 0755 "$BASE_DIR" "$BASE_DIR/lib"

ui_print "- Selected kernel module: $KMI"
ui_print "- YukiZygisk installed"
