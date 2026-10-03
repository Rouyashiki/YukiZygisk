#!/system/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# YukiZygisk module boot-completed health check.
#
# License: Apache-2.0
#
# Author: Anatdx

MODDIR="${0%/*}"
BASE_DIR="/data/adb/yukizygisk"
LOG_FILE="$BASE_DIR/zygiskd.log"

mkdir -p "$BASE_DIR"
touch "$LOG_FILE" 2>/dev/null || true

log() {
	echo "boot-completed: $*" >>"$LOG_FILE"
}

if "$MODDIR/bin/yzctl" status --json >/dev/null 2>>"$LOG_FILE"; then
	log "kernel control status ok"
	exit 0
fi

log "kernel control unavailable; unloading yukizygisk.ko"
"$MODDIR/bin/yzctl" description kernel-unavailable --module-dir "$MODDIR" \
	>>"$LOG_FILE" 2>&1 || log "failed to update module description"
if ! grep -q '^yukizygisk ' /proc/modules 2>/dev/null; then
	log "yukizygisk.ko already absent"
	exit 0
fi

RMMOD="$(command -v rmmod 2>/dev/null || true)"
[ -n "$RMMOD" ] || RMMOD="/system/bin/rmmod"

if "$RMMOD" yukizygisk >>"$LOG_FILE" 2>&1; then
	log "yukizygisk.ko unloaded"
else
	log "yukizygisk.ko unload failed"
fi

exit 0
