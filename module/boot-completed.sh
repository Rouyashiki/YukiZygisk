#!/system/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# YukiZygisk module boot-completed health check.
#
# License: Apache-2.0
#
# Author: Anatdx

MODDIR="${0%/*}"
# shellcheck source=module/late-load-common.sh
. "$MODDIR/late-load-common.sh"
for marker in disable remove; do
	[ ! -e "$MODDIR/$marker" ] && [ ! -L "$MODDIR/$marker" ] || exit 0
done
# KernelSU runs this stage during late-load too, before any manual soft reboot.
# An intentionally absent LKM is not a health failure or an unload request.
if [ -f "$LATE_LOAD_PENDING" ]; then
	late_load_notice
	exit 0
fi
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
