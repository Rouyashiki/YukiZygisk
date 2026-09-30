#!/system/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# YukiZygisk module action: print current health and recent startup messages.
#
# License: Apache-2.0
#
# Author: Anatdx

MODDIR="${0%/*}"
LOG_FILE="/data/adb/yukizygisk/zygiskd.log"

echo "YukiZygisk status"
echo
if ! "$MODDIR/bin/yzctl" status 2>/dev/null; then
	echo "kernel control is unavailable"
fi

if [ -f "$LOG_FILE" ]; then
	echo
	echo "Recent startup log"
	tail -n 20 "$LOG_FILE" 2>/dev/null || true
fi

exit 0
