#!/system/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# YukiZygisk module post-fs-data entry point.
#
# License: Apache-2.0
#
# Author: Rouyashiki Developers

MODDIR="${0%/*}"
[ "$#" -eq 0 ] || exit 2
STAGE=post-fs-data
# shellcheck source=module/late-load-common.sh
. "$MODDIR/late-load-common.sh"
for marker in disable remove; do
	[ ! -e "$MODDIR/$marker" ] && [ ! -L "$MODDIR/$marker" ] || exit 0
done
LATE_LOAD=false
if late_load_mode; then
	LATE_LOAD=true
	late_load_lock || exit 1
	if ! late_load_runtime_stopped; then
		[ ! -f "$LATE_LOAD_PENDING" ] || late_load_notice
		echo "post-fs-data: late-load activation deferred until Android is stopped" >&2
		exit 0
	fi
fi
BASE_DIR="/data/adb/yukizygisk"
LIB_DIR="$BASE_DIR/lib"
RUN_DIR="$BASE_DIR/run"
RUNTIME_LOG_DIR="$BASE_DIR/log"
CURRENT_RUNTIME_LOG="$RUNTIME_LOG_DIR/zygiskd64.log"
ROLLOVER_RUNTIME_LOG="$RUNTIME_LOG_DIR/zygiskd64.1.log"
PREVIOUS_RUNTIME_LOG="$RUNTIME_LOG_DIR/zygiskd64.old.log"
PREVIOUS_ROLLOVER_LOG="$RUNTIME_LOG_DIR/zygiskd64.1.old.log"
LOG_FILE="$BASE_DIR/zygiskd.log"
LATE_LOAD_LOGS_PREPARED="$LATE_LOAD_STATE_DIR/logs-prepared"

mkdir -p "$BASE_DIR" "$LIB_DIR" "$RUN_DIR" "$RUNTIME_LOG_DIR"
chmod 0755 "$BASE_DIR" "$LIB_DIR" "$RUN_DIR"
chmod 0700 "$RUNTIME_LOG_DIR"

remove_previous_log() {
	log_path="$1"
	if [ -L "$log_path" ] || [ -f "$log_path" ]; then
		rm -f "$log_path"
	elif [ -e "$log_path" ]; then
		return 1
	fi
}

archive_runtime_log() {
	log_path="$1"
	archive_path="$2"
	if [ -L "$log_path" ]; then
		rm -f "$log_path"
	elif [ -f "$log_path" ]; then
		mv -f "$log_path" "$archive_path"
	elif [ -e "$log_path" ]; then
		return 1
	fi
}

current_log_safe=true
rollover_log_safe=true
# Late-load retries still run the authenticated, idempotent launcher. Rotate
# logs only before the first attempt so a running daemon keeps its log file.
if ! $LATE_LOAD || [ ! -f "$LATE_LOAD_LOGS_PREPARED" ]; then
	previous_log_safe=true
	previous_rollover_safe=true
	remove_previous_log "$PREVIOUS_RUNTIME_LOG" || previous_log_safe=false
	remove_previous_log "$PREVIOUS_ROLLOVER_LOG" || previous_rollover_safe=false
	if $previous_log_safe; then
		archive_runtime_log "$CURRENT_RUNTIME_LOG" "$PREVIOUS_RUNTIME_LOG" || \
			current_log_safe=false
	else
		current_log_safe=false
	fi
	if $previous_rollover_safe; then
		archive_runtime_log "$ROLLOVER_RUNTIME_LOG" "$PREVIOUS_ROLLOVER_LOG" || \
			rollover_log_safe=false
	else
		rollover_log_safe=false
	fi
fi

if ! $current_log_safe; then
	printf '%s\n' "$STAGE: failed to archive current userspace log" >>"$LOG_FILE"
fi
if ! $rollover_log_safe; then
	printf '%s\n' "$STAGE: failed to archive rollover userspace log" >>"$LOG_FILE"
fi

if $current_log_safe && [ ! -e "$CURRENT_RUNTIME_LOG" ] && \
	[ ! -L "$CURRENT_RUNTIME_LOG" ]; then
	: >"$CURRENT_RUNTIME_LOG"
fi
for log_path in "$CURRENT_RUNTIME_LOG" "$ROLLOVER_RUNTIME_LOG" \
	"$PREVIOUS_RUNTIME_LOG" "$PREVIOUS_ROLLOVER_LOG"; do
	if [ ! -L "$log_path" ] && [ -f "$log_path" ]; then
		chmod 0600 "$log_path"
	fi
done
touch "$LOG_FILE" 2>/dev/null || true
# Publish log preparation before launching any daemon, including an attempt
# whose caller may be interrupted after the daemon has already started.
if $LATE_LOAD; then
	: >"$LATE_LOAD_LOGS_PREPARED" || exit 1
fi

log() {
	echo "$STAGE: $*" >>"$LOG_FILE"
}

set_description() {
	"$MODDIR/bin/yzctl" description "$1" --module-dir "$MODDIR" \
		>>"$LOG_FILE" 2>&1 || log "failed to update module description"
}

set_description starting

if [ ! -e /data/adb/service.d/.yz_cleanup.sh ] &&
	[ ! -L /data/adb/service.d/.yz_cleanup.sh ]; then
	sh "$MODDIR/cleanup.sh" --install-hook ||
		log "failed to restore module cleanup hook"
fi

if [ ! -x "$MODDIR/bin/viola" ]; then
	log "missing executable Viola verifier"
	set_description startup-failed
	exit 1
fi

# Late-load recorded the host's scan while acquiring the startup lock.
if ! $LATE_LOAD && ! "$MODDIR/bin/yzctl" policy-boot; then
	log "cannot confirm the selected boot policy"
	set_description startup-failed
	exit 1
fi

unset LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT LD_CONFIG_FILE LD_DEBUG LD_DEBUG_OUTPUT
# Prepare the boot marker before the crash monitor starts. The diagnostics
# helper uses its own FD 9, so it must not inherit the late-load startup lock.
if ! YZ_STATE_DIR="$BASE_DIR" sh "$MODDIR/diagnostics.sh" prepare-startup \
	9>&- >>"$LOG_FILE" 2>&1; then
	log "could not prepare crash diagnostics"
fi

log "starting authenticated YukiZygisk core"
set -- launch --module-dir "$MODDIR"
if $LATE_LOAD; then
	# Keep the stop condition through hashing, LKM relocation and daemon ready.
	# KernelSU may stop waiting for this script when its shared deadline expires.
	set -- "$@" --runtime-guard stopped
fi
# The bootstrap shell owns FD 9; the daemon must not inherit its startup lock.
if ! /system/bin/env -i PATH=/system/bin:/system/xbin "$MODDIR/bin/viola" "$@" 9>&- >>"$LOG_FILE" 2>&1; then
	log "Viola refused startup; see verification error above"
	if $LATE_LOAD && [ -f "$LATE_LOAD_PENDING" ] &&
		"$MODDIR/bin/yzctl" policy-launch-failed >>"$LOG_FILE" 2>&1; then
		late_load_notice >>"$LOG_FILE" 2>&1 || log "failed to update module description"
	else
		set_description startup-failed
	fi
	exit 1
fi
if $LATE_LOAD && [ -f "$LATE_LOAD_PENDING" ]; then
	mv -f "$LATE_LOAD_PENDING" "$LATE_LOAD_ACTIVE" || exit 1
	rm -f "$LATE_LOAD_LAUNCH_POLICY_ERROR" || log "could not clear the launch policy error"
fi
"$MODDIR/bin/yzctl" policy-refresh >>"$LOG_FILE" 2>&1 ||
	log "could not refresh the fixed policy for the next boot"
exit 0
