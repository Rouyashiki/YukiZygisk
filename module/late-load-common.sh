#!/system/bin/sh
# SPDX-License-Identifier: Apache-2.0
# YukiZygisk late-load activation state. Sourced by module boot scripts.
# Author: Rouyashiki Developers

# /dev survives an Android soft reboot, but is cleared by a kernel reboot.
LATE_LOAD_STATE_DIR="/dev/yukizygisk-late-load"
LATE_LOAD_PENDING="$LATE_LOAD_STATE_DIR/pending"
LATE_LOAD_ACTIVE="$LATE_LOAD_STATE_DIR/active"

late_load_mode() {
	[ "${KSU_LATE_LOAD:-}" = 1 ] ||
		[ "${KSU_RUNTIME_MODE:-}" = late-load ] ||
		[ -d "$LATE_LOAD_STATE_DIR" ]
}

late_load_lock() {
	umask 077
	mkdir "$LATE_LOAD_STATE_DIR" 2>/dev/null || true
	[ -d "$LATE_LOAD_STATE_DIR" ] && [ ! -L "$LATE_LOAD_STATE_DIR" ] &&
		[ "$(stat -c %u "$LATE_LOAD_STATE_DIR")" = 0 ] || return 1
	chmod 0700 "$LATE_LOAD_STATE_DIR" || return 1
	for name in pending active logs-prepared startup.lock; do
		path="$LATE_LOAD_STATE_DIR/$name"
		[ ! -L "$path" ] && { [ ! -e "$path" ] || [ -f "$path" ]; } || return 1
	done
	exec 9>>"$LATE_LOAD_STATE_DIR/startup.lock"
	flock -x 9 || return 1
	# An interrupted launch keeps pending; only a successful launch consumes it.
	[ -f "$LATE_LOAD_ACTIVE" ] || : >"$LATE_LOAD_PENDING"
}

late_load_notice() {
	"$MODDIR/bin/yzctl" description late-load-pending --module-dir "$MODDIR"
}

late_load_runtime_stopped() {
	# KernelSU's emulated soft reboot stops Android before replaying post-fs-data.
	# Do not activate if a caller replays that stage while the old runtime lives.
	[ "$(getprop sys.boot_completed)" = 0 ] || return 1
	[ "$(getprop init.svc.zygote)" = stopped ] || return 1
	# Match Android's stop command: vendor/WebView Zygotes are not part of
	# the primary/secondary service pair selected by ro.zygote.
	case "$(getprop ro.zygote)" in
	zygote32 | zygote64) return 0 ;;
	zygote32_64 | zygote64_32)
		[ "$(getprop init.svc.zygote_secondary)" = stopped ] ;;
	*) return 1 ;;
	esac
}
