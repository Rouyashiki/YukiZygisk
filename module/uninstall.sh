#!/system/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# YukiZygisk module uninstall hook.
#
# License: Apache-2.0
#
# Author: Anatdx

rm -f /data/adb/service.d/.yz_cleanup.sh

case "${KSU:-false}:${APATCH:-false}" in
true:false) YZ_CTL_LINK=/data/adb/ksu/bin/yzctl ;;
false:true) YZ_CTL_LINK=/data/adb/ap/bin/yzctl ;;
*) exit 0 ;;
esac
if [ -L "$YZ_CTL_LINK" ] &&
	[ "$(readlink "$YZ_CTL_LINK")" = /data/adb/modules/yukizygisk/bin/yzctl ]; then
	rm -f "$YZ_CTL_LINK"
fi
