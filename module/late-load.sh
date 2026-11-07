#!/system/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# YukiZygisk late-load deferral; activation waits for a manual soft reboot.
#
# License: Apache-2.0
#
# Author: Rouyashiki Developers

MODDIR="${0%/*}"
# shellcheck source=module/late-load-common.sh
. "$MODDIR/late-load-common.sh"

[ "${KSU_LATE_LOAD:-}" = 1 ] ||
	[ "${KSU_RUNTIME_MODE:-}" = late-load ] || exit 0
for marker in disable remove; do
	[ ! -e "$MODDIR/$marker" ] && [ ! -L "$MODDIR/$marker" ] || exit 0
done
[ "$#" -eq 0 ] || exit 2
late_load_lock || exit 1
# This stage must never load the LKM or launch Viola: the root loader and
# Android runtime may still be recovering. Repeating it only keeps the marker.
if [ -f "$LATE_LOAD_PENDING" ]; then
	late_load_notice || exit 1
	echo "late-load: activation deferred; after late-load finishes, manually soft-reboot from KernelSU"
fi
exit 0
