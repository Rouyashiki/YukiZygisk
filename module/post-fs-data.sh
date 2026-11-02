#!/system/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# YukiZygisk module post-fs-data entry point.
#
# License: Apache-2.0
#
# Author: Anatdx

MODDIR="${0%/*}"
# late-load.sh reuses this startup path before module mounts are applied.
STAGE="${1:-post-fs-data}"
case "$STAGE" in
post-fs-data | late-load) ;;
*) exit 2 ;;
esac
BASE_DIR="/data/adb/yukizygisk"
LIB_DIR="$BASE_DIR/lib"
RUN_DIR="$BASE_DIR/run"
RUNTIME_LOG_DIR="$BASE_DIR/log"
CURRENT_RUNTIME_LOG="$RUNTIME_LOG_DIR/zygiskd64.log"
ROLLOVER_RUNTIME_LOG="$RUNTIME_LOG_DIR/zygiskd64.1.log"
PREVIOUS_RUNTIME_LOG="$RUNTIME_LOG_DIR/zygiskd64.old.log"
PREVIOUS_ROLLOVER_LOG="$RUNTIME_LOG_DIR/zygiskd64.1.old.log"
LOG_FILE="$BASE_DIR/zygiskd.log"
CONFIG_FILE="$BASE_DIR/yzconfig.json"
LATE_LOAD_LOGS_PREPARED="/dev/yukizygisk-late-load/logs-prepared"

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
if [ "$STAGE" != late-load ] || [ ! -f "$LATE_LOAD_LOGS_PREPARED" ]; then
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
if [ "$STAGE" = late-load ]; then
	: >"$LATE_LOAD_LOGS_PREPARED" || exit 1
fi

if [ ! -f "$CONFIG_FILE" ]; then
	printf '%s\n' '{"yukilinker":true,"denylist_mode":0,"dmesg_log":false}' \
		>"$CONFIG_FILE"
fi
chmod 0600 "$CONFIG_FILE" 2>/dev/null || true

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

log "starting authenticated YukiZygisk core"
unset LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT LD_CONFIG_FILE LD_DEBUG LD_DEBUG_OUTPUT
# The bootstrap shell owns FD 9; the daemon must not inherit its startup lock.
if ! /system/bin/env -i PATH=/system/bin:/system/xbin "$MODDIR/bin/viola" launch --module-dir "$MODDIR" 9>&- >>"$LOG_FILE" 2>&1; then
	log "Viola refused startup; see verification error above"
	set_description startup-failed
	exit 1
fi
exit 0
