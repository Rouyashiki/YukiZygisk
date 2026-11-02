#!/system/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# YukiZygisk module late-load startup; Android runtime restarts stay manual.
#
# License: Apache-2.0
#
# Author: Anatdx

MODDIR="${0%/*}"
LOG_FILE="/data/adb/yukizygisk/zygiskd.log"
# /dev is cleared by a kernel reboot, but survives an Android runtime restart.
STATE_DIR="/dev/yukizygisk-late-load"

[ "${KSU_LATE_LOAD:-}" = 1 ] ||
	[ "${KSU_RUNTIME_MODE:-}" = late-load ] || exit 0
for marker in disable remove; do
	[ ! -e "$MODDIR/$marker" ] && [ ! -L "$MODDIR/$marker" ] || exit 0
done
umask 077

[ "$#" -eq 0 ] || exit 2
# This directory records the boot mode, not successful daemon startup.
if ! mkdir "$STATE_DIR" 2>/dev/null; then
	if [ ! -d "$STATE_DIR" ] || [ -L "$STATE_DIR" ]; then
		echo "late-load: cannot create startup state" >&2
		exit 1
	fi
fi
# Serialize log preparation and startup with a process-owned lock. An
# interrupted attempt must not prevent the next stage from retrying Viola.
LOCK_FILE="$STATE_DIR/startup.lock"
[ ! -L "$LOCK_FILE" ] && { [ ! -e "$LOCK_FILE" ] || [ -f "$LOCK_FILE" ]; } || exit 1
exec 9>>"$LOCK_FILE"
flock -x 9 || exit 1
sh "$MODDIR/post-fs-data.sh" late-load || exit 1

echo "late-load: core ready; manually soft-reboot Android to activate Zygote injection" >>"$LOG_FILE"
exit 0
