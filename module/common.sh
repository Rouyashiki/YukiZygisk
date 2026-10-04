#!/system/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# YukiZygisk module helpers for selecting a KMI-specific kernel module.
#
# License: Apache-2.0
#
# Author: Anatdx

yz_detect_kmi() {
	yz_release="${1:-$(uname -r 2>/dev/null)}"
	yz_android="$(printf '%s\n' "$yz_release" |
		sed -n 's/.*\(android[0-9][0-9]*\).*/\1/p')"
	yz_kernel="$(printf '%s\n' "$yz_release" |
		sed -n 's/^\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')"

	[ -n "$yz_android" ] && [ -n "$yz_kernel" ] || return 1
	printf '%s-%s\n' "$yz_android" "$yz_kernel"
}

yz_kmi_ko() {
	yz_moddir="$1"
	yz_kmi="$2"
	printf '%s/lkm/%s_yukizygisk.ko\n' "$yz_moddir" "$yz_kmi"
}

yz_list_supported_kmis() {
	yz_moddir="$1"
	yz_found=false
	for yz_ko in "$yz_moddir"/lkm/*_yukizygisk.ko; do
		[ -f "$yz_ko" ] || continue
		yz_name="${yz_ko##*/}"
		printf '%s\n' "${yz_name%_yukizygisk.ko}"
		yz_found=true
	done
	[ "$yz_found" = true ]
}

yz_select_kmi() {
	yz_choices="$(yz_list_supported_kmis "$1")" || return 1
	# KMI names come from the verified package's whitespace-free file names.
	# shellcheck disable=SC2086
	set -- $yz_choices
	[ "$#" -gt 0 ] || return 1
	command -v getevent >/dev/null 2>&1 &&
		command -v timeout >/dev/null 2>&1 || return 1

	ui_print "- Select your kernel KMI"
	ui_print "- Volume Up: next (wraps); Volume Down: confirm"
	ui_print "- KMI: $1"
	while :; do
		# Read one event at a time so confirmation leaves no reader behind.
		yz_event="$(timeout 120 getevent -qlc 1 2>/dev/null)" || return 1
		[ -n "$yz_event" ] || return 1
		case "$yz_event" in
		*KEY_VOLUMEUP*DOWN*)
			set -- "$@" "$1"
			shift
			ui_print "- KMI: $1"
			;;
		*KEY_VOLUMEDOWN*DOWN*)
			# The install hook consumes the confirmed choice.
			# shellcheck disable=SC2034
			KMI="$1"
			return 0
			;;
		esac
	done
}

yz_prune_kmis() {
	yz_keep="$(yz_kmi_ko "$1" "$2")"
	[ -f "$yz_keep" ] && [ ! -L "$yz_keep" ] || return 1
	for yz_candidate in "$1"/lkm/*_yukizygisk.ko; do
		[ "$yz_candidate" = "$yz_keep" ] && continue
		rm -f "$yz_candidate" "$yz_candidate.sha256" || return 1
	done
}

yz_module_list_has() {
	yz_wanted_module="$1"
	while read -r yz_module_name _; do
		[ "$yz_module_name" = "$yz_wanted_module" ] && return 0
	done
	return 1
}

yz_lsmod() {
	if command -v lsmod >/dev/null 2>&1; then
		lsmod
	elif command -v toybox >/dev/null 2>&1; then
		toybox lsmod
	else
		return 127
	fi
}

yz_ksu_module_loaded() {
	yz_lsmod 2>/dev/null | yz_module_list_has kernelsu
}
