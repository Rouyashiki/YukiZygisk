#!/system/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# YukiZygisk module description cleanup after disable or removal.
#
# License: Apache-2.0
#
# Author: Anatdx

MODULE_DIR="/data/adb/modules/yukizygisk"
UPDATE_DIR="/data/adb/modules_update/yukizygisk"
HOOK_DIR="/data/adb/service.d"
HOOK="$HOOK_DIR/.yz_cleanup.sh"

prop_field() {
	FIELD="$(sed -n "s/^$2=//p" "$1")"
	printf '%s' "${FIELD%"$(printf '\r')"}"
}

valid_prop() {
	[ -f "$1" ] && [ ! -L "$1" ] &&
		[ "$(grep -c '^id=' "$1")" -eq 1 ] &&
		[ "$(prop_field "$1" id)" = yukizygisk ] &&
		[ "$(grep -c '^version=' "$1")" -eq 1 ] &&
		[ "$(grep -c '^versionCode=' "$1")" -eq 1 ] &&
		[ "$(grep -c '^description=' "$1")" -eq 1 ]
}

if [ "${1:-}" = --install-hook ]; then
	SOURCE_DIR="${0%/*}"
	valid_prop "$SOURCE_DIR/module.prop.orig" || exit 1
	[ -f "$0" ] && [ ! -L "$0" ] || exit 1
	mkdir -p "$HOOK_DIR" || exit 1
	[ -d "$HOOK_DIR" ] && [ ! -L "$HOOK_DIR" ] || exit 1
	[ ! -L "$HOOK" ] || exit 1
	HOOK_TMP="$(mktemp "$HOOK_DIR/.yz_cleanup.XXXXXX")" || exit 1
	if ! cat "$0" >"$HOOK_TMP" || ! chmod 0700 "$HOOK_TMP" ||
		! mv -f "$HOOK_TMP" "$HOOK"; then
		rm -f "$HOOK_TMP"
		exit 1
	fi
	exit 0
fi

[ "$#" -eq 0 ] || exit 2
# Wait for a pending replacement before acting on the old module directory.
if [ -d "$UPDATE_DIR" ] && [ ! -L "$UPDATE_DIR" ]; then
	exit 0
fi
if [ ! -d "$MODULE_DIR" ] || [ -L "$MODULE_DIR" ] ||
	[ -e "$MODULE_DIR/remove" ] || [ -L "$MODULE_DIR/remove" ]; then
	rm -f "$HOOK"
	exit 0
fi
[ -e "$MODULE_DIR/disable" ] || [ -L "$MODULE_DIR/disable" ] || exit 0

ORIGINAL="$MODULE_DIR/module.prop.orig"
CURRENT="$MODULE_DIR/module.prop"
valid_prop "$ORIGINAL" && valid_prop "$CURRENT" || exit 1
ORIGINAL_VERSION="$(prop_field "$ORIGINAL" version)"
ORIGINAL_CODE="$(prop_field "$ORIGINAL" versionCode)"
[ -n "$ORIGINAL_VERSION" ] && [ -n "$ORIGINAL_CODE" ] &&
	[ "$ORIGINAL_VERSION" = "$(prop_field "$CURRENT" version)" ] &&
	[ "$ORIGINAL_CODE" = "$(prop_field "$CURRENT" versionCode)" ] || exit 1

RESTORE_TMP="$(mktemp "$MODULE_DIR/.module.prop.restore.XXXXXX")" || exit 1
if ! cat "$ORIGINAL" >"$RESTORE_TMP" || ! chmod 0644 "$RESTORE_TMP" ||
	! mv -f "$RESTORE_TMP" "$CURRENT"; then
	rm -f "$RESTORE_TMP"
	exit 1
fi
rm -f "$HOOK"
