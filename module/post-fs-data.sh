#!/system/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# YukiZygisk module post-fs-data entry point.
#
# License: Apache-2.0
#
# Author: Anatdx

MODDIR="${0%/*}"
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
MODULES_DIR="/data/adb/modules"

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

previous_log_safe=true
previous_rollover_safe=true
remove_previous_log "$PREVIOUS_RUNTIME_LOG" || previous_log_safe=false
remove_previous_log "$PREVIOUS_ROLLOVER_LOG" || previous_rollover_safe=false

current_log_safe=true
rollover_log_safe=true
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

if ! $current_log_safe; then
	printf '%s\n' 'post-fs-data: failed to archive current userspace log' >>"$LOG_FILE"
fi
if ! $rollover_log_safe; then
	printf '%s\n' 'post-fs-data: failed to archive rollover userspace log' >>"$LOG_FILE"
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

if [ ! -f "$CONFIG_FILE" ]; then
	printf '%s\n' '{"yukilinker":true,"denylist_mode":0,"dmesg_log":false}' \
		>"$CONFIG_FILE"
fi
chmod 0600 "$CONFIG_FILE" 2>/dev/null || true

log() {
	echo "post-fs-data: $*" >>"$LOG_FILE"
}

if [ ! -f "$MODDIR/common.sh" ]; then
	log "missing module KMI helpers"
	exit 0
fi
# shellcheck source=/dev/null
. "$MODDIR/common.sh"

KERNEL_RELEASE="$(uname -r 2>/dev/null)"
if ! KMI="$(yz_detect_kmi "$KERNEL_RELEASE")"; then
	log "cannot detect GKI KMI from kernel release: $KERNEL_RELEASE"
	exit 0
fi
KERNEL_MODULE="$(yz_kmi_ko "$MODDIR" "$KMI")"
if [ ! -f "$KERNEL_MODULE" ]; then
	SUPPORTED_KMIS="$(yz_list_supported_kmis "$MODDIR" | tr '\n' ' ')"
	log "missing kernel module for $KMI; available: ${SUPPORTED_KMIS:-none}"
	exit 0
fi

random_cookie() {
	c="$(od -An -N8 -tx8 /dev/urandom 2>/dev/null | tr -d ' \n')"
	if [ -n "$c" ]; then
		echo "0x$c"
	else
		echo "0x$(date +%s)$$"
	fi
}

COOKIE="$(random_cookie)"

chmod 0755 "$MODDIR/bin/zygiskd64" "$MODDIR/bin/zygiskd32" "$MODDIR/bin/yzctl" \
	2>/dev/null || true

copy_payload() {
	source="$1"
	destination="$2"
	if [ ! -f "$source" ]; then
		log "missing payload ${source##*/}"
		exit 0
	fi
	if ! cp "$source" "$LIB_DIR/$destination.tmp" 2>>"$LOG_FILE"; then
		log "copy ${source##*/} failed"
		exit 0
	fi
	mv "$LIB_DIR/$destination.tmp" "$LIB_DIR/$destination" 2>>"$LOG_FILE" || exit 0
	chmod 0644 "$LIB_DIR/$destination" 2>/dev/null || true
}

copy_payload "$MODDIR/lib64/libzygisk.so" libzygisk64.so
copy_payload "$MODDIR/lib64/libyukilinker.so" libyukilinker64.so
copy_payload "$MODDIR/lib64/libyukizncore.so" libyukizncore64.so
copy_payload "$MODDIR/lib/libzygisk.so" libzygisk32.so
copy_payload "$MODDIR/lib/libyukilinker.so" libyukilinker32.so
copy_payload "$MODDIR/lib/libyukizncore.so" libyukizncore32.so

if ! rm -f "$LIB_DIR/libzygisk.so" "$LIB_DIR/libyukilinker.so" \
	"$LIB_DIR/libyukizncore.so" 2>>"$LOG_FILE"; then
	log "remove legacy payloads failed"
	exit 0
fi

if grep -q '^yukizygisk ' /proc/modules 2>/dev/null; then
	log "yukizygisk.ko already loaded"
	exit 0
fi

INSMOD="$(command -v insmod 2>/dev/null || echo /system/bin/insmod)"
KSU_MODULE_PRESENT=0
if yz_ksu_module_loaded; then
	KSU_MODULE_PRESENT=1
	log "KernelSU module detected by lsmod"
fi
log "loading $KERNEL_MODULE for $KMI (release=$KERNEL_RELEASE) cookie=$COOKIE ksu_module_present=$KSU_MODULE_PRESENT"
if ! "$INSMOD" "$KERNEL_MODULE" bootstrap_cookie_lo="$COOKIE" \
	ksu_module_present="$KSU_MODULE_PRESENT" \
	>>"$LOG_FILE" 2>&1; then
	log "insmod failed"
	exit 0
fi

log "starting zygiskd"
YUKIZYGISK_BOOTSTRAP_COOKIE_LO="$COOKIE" \
YUKIZYGISK_CONFIG="$CONFIG_FILE" \
YUKIZYGISK_LOG_DIR="$RUNTIME_LOG_DIR" \
YUKIZYGISK_MODULES_DIR="$MODULES_DIR" \
"$MODDIR/bin/zygiskd64" >>"$LOG_FILE" 2>&1 &

exit 0
