#!/system/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# YukiZygisk boot diagnostics and report helpers.
#
# License: Apache-2.0
#
# Author: Anatdx

YZ_STATE_DIR="${YZ_STATE_DIR:-/data/adb/yukizygisk}"
YZ_DIAGNOSTICS_DIR="$YZ_STATE_DIR/diagnostics"
YZ_CURRENT_DIAGNOSTICS_DIR="$YZ_DIAGNOSTICS_DIR/current"
YZ_OLD_DIAGNOSTICS_DIR="$YZ_DIAGNOSTICS_DIR/old"
YZ_CONFIG_FILE="$YZ_STATE_DIR/yzconfig.json"
YZ_LEGACY_LOG_DIR="$YZ_STATE_DIR/log"
YZ_FALLBACK_DIAGNOSTICS_DIR="$YZ_LEGACY_LOG_DIR"
YZ_BOOT_ID_FILE="${YZ_BOOT_ID_FILE:-/proc/sys/kernel/random/boot_id}"
YZ_TOMBSTONES_DIR="${YZ_TOMBSTONES_DIR:-/data/tombstones}"
YZ_PSTORE_DIR="${YZ_PSTORE_DIR:-/sys/fs/pstore}"
YZ_MAX_CAPTURE_FILE_BYTES=33554432
YZ_DIAGNOSTICS_OWNER="${YZ_DIAGNOSTICS_OWNER:-0}"

yz_diag_owner() {
	stat -c '%u' "$1" 2>/dev/null
}

yz_diag_safe_dir() {
	[ ! -L "$1" ] && [ -d "$1" ] &&
		[ "$(yz_diag_owner "$1")" = "$YZ_DIAGNOSTICS_OWNER" ]
}

yz_diag_safe_file() {
	[ ! -L "$1" ] && [ -f "$1" ] &&
		[ "$(yz_diag_owner "$1")" = "$YZ_DIAGNOSTICS_OWNER" ]
}

yz_diag_ensure_dir() {
	directory="$1"
	mode="$2"
	if [ ! -e "$directory" ] && [ ! -L "$directory" ]; then
		mkdir -p "$directory" 2>/dev/null || return 1
	fi
	yz_diag_safe_dir "$directory" || return 1
	chmod "$mode" "$directory" 2>/dev/null || return 1
}

yz_diag_atomic_write() {
	destination="$1"
	temporary="${destination}.tmp.$$"
	if [ -L "$destination" ] || { [ -e "$destination" ] && [ ! -f "$destination" ]; }; then
		return 1
	fi
	rm -f "$temporary" 2>/dev/null || return 1
	if ! cat >"$temporary"; then
		rm -f "$temporary" 2>/dev/null
		return 1
	fi
	chmod 0600 "$temporary" 2>/dev/null || {
		rm -f "$temporary" 2>/dev/null
		return 1
	}
	mv -f "$temporary" "$destination"
}

yz_diag_remove_generation() {
	target="$1"
	if [ ! -e "$target" ] && [ ! -L "$target" ]; then
		return 0
	fi
	yz_diag_safe_dir "$target" || return 1
	rm -rf "$target"
}

yz_diag_copy_config() {
	generation="$1"
	if yz_diag_safe_file "$YZ_CONFIG_FILE"; then
		yz_diag_atomic_write "$generation/config.json" <"$YZ_CONFIG_FILE"
	else
		return 0
	fi
}

yz_diag_digest() {
	command -v sha256sum >/dev/null 2>&1 || return 1
	digest="$(sha256sum "$1" 2>/dev/null)" || return 1
	digest="${digest%% *}"
	[ "${#digest}" -eq 64 ] || return 1
	case "$digest" in
	*[!0-9a-fA-F]*) return 1 ;;
	esac
	printf '%s\n' "$digest"
}

yz_diag_inventory() {
	source_dir="$1"
	destination="$2"
	hash_contents="${3:-false}"
	hashed_bytes=0
	temporary="${destination}.tmp.$$"
	: >"$temporary" || return 1
	if yz_diag_safe_dir "$source_dir"; then
		for source in "$source_dir"/*; do
			[ -e "$source" ] || continue
			yz_diag_safe_file "$source" || continue
			name="${source##*/}"
			case "$name" in
			*'|'*) continue ;;
			esac
		size="$(stat -c '%s' "$source" 2>/dev/null)" || continue
		mtime="$(stat -c '%Y' "$source" 2>/dev/null)" || continue
		if $hash_contents; then
			digest="?"
			if [ "$size" -le $((33554432 - hashed_bytes)) ]; then
				digest="$(yz_diag_digest "$source" 2>/dev/null || echo '!')"
				hashed_bytes=$((hashed_bytes + size))
			fi
			printf '%s|%s|%s|%s\n' "$name" "$size" "$mtime" "$digest" >>"$temporary"
		else
			printf '%s|%s|%s\n' "$name" "$size" "$mtime" >>"$temporary"
		fi
		done
	fi
	chmod 0600 "$temporary" 2>/dev/null || {
		rm -f "$temporary" 2>/dev/null
		return 1
	}
	mv -f "$temporary" "$destination"
}

yz_diag_capture_changed() {
	source_dir="$1"
	baseline="$2"
	destination="$3"
	max_files="$4"
	max_bytes="$5"
	hash_contents="${6:-false}"
	YZ_CAPTURE_AVAILABLE=false
	YZ_CAPTURE_COPIED=0
	YZ_CAPTURE_FAILED=0
	YZ_CAPTURE_SKIPPED=0
	YZ_CAPTURE_BYTES=0

	yz_diag_safe_dir "$source_dir" || return 0
	YZ_CAPTURE_AVAILABLE=true
	yz_diag_ensure_dir "$destination" 0700 || {
		YZ_CAPTURE_FAILED=1
		return 0
	}
	for source in "$source_dir"/*; do
		[ -e "$source" ] || continue
		yz_diag_safe_file "$source" || continue
		name="${source##*/}"
		case "$name" in
		*'|'*)
			YZ_CAPTURE_SKIPPED=$((YZ_CAPTURE_SKIPPED + 1))
			continue
			;;
		esac
		size="$(stat -c '%s' "$source" 2>/dev/null)" || {
			YZ_CAPTURE_FAILED=$((YZ_CAPTURE_FAILED + 1))
			continue
		}
		mtime="$(stat -c '%Y' "$source" 2>/dev/null)" || {
			YZ_CAPTURE_FAILED=$((YZ_CAPTURE_FAILED + 1))
			continue
		}
		if [ "$YZ_CAPTURE_COPIED" -ge "$max_files" ] ||
			[ "$size" -gt "$YZ_MAX_CAPTURE_FILE_BYTES" ] ||
			[ "$size" -gt $((max_bytes - YZ_CAPTURE_BYTES)) ]; then
			YZ_CAPTURE_SKIPPED=$((YZ_CAPTURE_SKIPPED + 1))
			continue
		fi
		stamp="$name|$size|$mtime"
		if $hash_contents; then
			digest="$(yz_diag_digest "$source" 2>/dev/null || true)"
			if [ -n "$digest" ]; then
				stamp="$stamp|$digest"
			else
				stamp=""
			fi
		fi
		if [ -n "$stamp" ] && [ -f "$baseline" ] &&
			grep -Fqx "$stamp" "$baseline" 2>/dev/null; then
			continue
		fi
		if cp -p "$source" "$destination/$name" 2>/dev/null &&
			chmod 0600 "$destination/$name" 2>/dev/null; then
			YZ_CAPTURE_COPIED=$((YZ_CAPTURE_COPIED + 1))
			YZ_CAPTURE_BYTES=$((YZ_CAPTURE_BYTES + size))
		else
			rm -f "$destination/$name" 2>/dev/null
			YZ_CAPTURE_FAILED=$((YZ_CAPTURE_FAILED + 1))
		fi
	done
}

yz_diag_has_evidence() {
	generation="$1"
	for candidate in "$generation/evidence" "$generation/linker64.json" \
		"$generation/linker32.json" "$generation/logs/"*; do
		if yz_diag_safe_file "$candidate" && [ -s "$candidate" ]; then
			return 0
		fi
	done
	return 1
}

yz_diag_capture_previous() {
	generation="$1"
	yz_diag_copy_config "$generation" || true
	yz_diag_has_evidence "$generation" || return 0

	yz_diag_capture_changed "$YZ_TOMBSTONES_DIR" \
		"$generation/.tombstones.baseline" "$generation/tombstones" 32 134217728 false
	tombstones_available="$YZ_CAPTURE_AVAILABLE"
	tombstones_copied="$YZ_CAPTURE_COPIED"
	tombstones_failed="$YZ_CAPTURE_FAILED"
	tombstones_skipped="$YZ_CAPTURE_SKIPPED"
	tombstones_bytes="$YZ_CAPTURE_BYTES"

	yz_diag_capture_changed "$YZ_PSTORE_DIR" \
		"$generation/.pstore.baseline" "$generation/pstore" 32 33554432 true
	pstore_available="$YZ_CAPTURE_AVAILABLE"
	pstore_copied="$YZ_CAPTURE_COPIED"
	pstore_failed="$YZ_CAPTURE_FAILED"
	pstore_skipped="$YZ_CAPTURE_SKIPPED"
	pstore_bytes="$YZ_CAPTURE_BYTES"

	if [ "$tombstones_copied" -gt 0 ] || [ "$pstore_copied" -gt 0 ]; then
		printf '%s\n' 'previous-boot-crash-data' | yz_diag_atomic_write "$generation/evidence" || true
	fi
	{
		printf '{\n'
		printf '  "captured_at_unix": %s,\n' "$(date +%s 2>/dev/null || echo 0)"
		printf '  "tombstones": {"available": %s, "copied": %s, "failed": %s, "skipped": %s, "bytes": %s},\n' \
			"$tombstones_available" "$tombstones_copied" "$tombstones_failed" \
			"$tombstones_skipped" "$tombstones_bytes"
		printf '  "pstore": {"available": %s, "copied": %s, "failed": %s, "skipped": %s, "bytes": %s}\n' \
			"$pstore_available" "$pstore_copied" "$pstore_failed" \
			"$pstore_skipped" "$pstore_bytes"
		printf '}\n'
	} | yz_diag_atomic_write "$generation/capture.json" || true
}

yz_diag_write_boot_state() {
	generation="$1"
	phase="$2"
	case "$phase" in
	early | module-started | post-fs-data | kernel-loaded | daemon-started | fallback | \
		boot-completed-ok | boot-completed-failed) ;;
	*) phase=unknown ;;
	esac
	boot_id="$(tr -d '\r\n' <"$generation/boot_id" 2>/dev/null)"
	current_boot_id="$(tr -d '\r\n' <"$YZ_BOOT_ID_FILE" 2>/dev/null)"
	[ -n "$boot_id" ] && [ "$boot_id" = "$current_boot_id" ] || return 1
	{
		printf '{\n'
		printf '  "boot_id": "%s",\n' "$boot_id"
		printf '  "updated_at_unix": %s,\n' "$(date +%s 2>/dev/null || echo 0)"
		printf '  "phase": "%s"\n' "$phase"
		printf '}\n'
	} | yz_diag_atomic_write "$generation/boot.json"
}

yz_diag_initialize_generation() {
	generation="$1"
	boot_id="$2"
	yz_diag_ensure_dir "$generation" 0700 || return 1
	yz_diag_ensure_dir "$generation/logs" 0700 || return 1
	printf '%s\n' "$boot_id" | yz_diag_atomic_write "$generation/boot_id" || return 1
	yz_diag_inventory "$YZ_TOMBSTONES_DIR" "$generation/.tombstones.baseline" false || true
	yz_diag_inventory "$YZ_PSTORE_DIR" "$generation/.pstore.baseline" true || true
	yz_diag_copy_config "$generation" || true
	yz_diag_write_boot_state "$generation" early || return 1
}

yz_diag_import_legacy() {
	[ ! -e "$YZ_OLD_DIAGNOSTICS_DIR" ] && [ ! -L "$YZ_OLD_DIAGNOSTICS_DIR" ] || return 0
	staging="$YZ_DIAGNOSTICS_DIR/.legacy.tmp"
	yz_diag_remove_generation "$staging" || return 1
	yz_diag_ensure_dir "$staging" 0700 || return 1
	yz_diag_ensure_dir "$staging/logs" 0700 || return 1
	imported=false
	for name in zygiskd64.log zygiskd64.1.log zygiskd64.old.log \
		zygiskd64.1.old.log zygiskd32.log zygiskd32.1.log \
		zygiskd32.old.log zygiskd32.1.old.log; do
		source="$YZ_LEGACY_LOG_DIR/$name"
		if yz_diag_safe_file "$source" && [ -s "$source" ] &&
			cp -p "$source" "$staging/logs/legacy-$name" 2>/dev/null; then
			chmod 0600 "$staging/logs/legacy-$name" 2>/dev/null || true
			imported=true
		fi
	done
	if yz_diag_safe_file "$YZ_STATE_DIR/zygiskd.log" && [ -s "$YZ_STATE_DIR/zygiskd.log" ] &&
		cp -p "$YZ_STATE_DIR/zygiskd.log" "$staging/logs/legacy-bootstrap.log" 2>/dev/null; then
		chmod 0600 "$staging/logs/legacy-bootstrap.log" 2>/dev/null || true
		imported=true
	fi
	if $imported; then
		printf '%s\n' 'legacy-log' | yz_diag_atomic_write "$staging/evidence" || true
		mv "$staging" "$YZ_OLD_DIAGNOSTICS_DIR" || return 1
	else
		yz_diag_remove_generation "$staging" || true
	fi
}

yz_diag_lock() {
	command -v flock >/dev/null 2>&1 || return 1
	YZ_DIAGNOSTICS_LOCK="$YZ_DIAGNOSTICS_DIR/.lock"
	if [ -L "$YZ_DIAGNOSTICS_LOCK" ] ||
		{ [ -e "$YZ_DIAGNOSTICS_LOCK" ] && [ ! -f "$YZ_DIAGNOSTICS_LOCK" ]; }; then
		return 1
	fi
	: >>"$YZ_DIAGNOSTICS_LOCK" || return 1
	yz_diag_safe_file "$YZ_DIAGNOSTICS_LOCK" || return 1
	chmod 0600 "$YZ_DIAGNOSTICS_LOCK" 2>/dev/null || return 1
	exec 9>>"$YZ_DIAGNOSTICS_LOCK" || return 1
	if flock -n 9; then
		YZ_DIAGNOSTICS_LOCKED=true
		return 0
	fi
	exec 9>&-
	return 1
}

yz_diag_unlock() {
	if [ "${YZ_DIAGNOSTICS_LOCKED:-false}" = true ]; then
		flock -u 9 2>/dev/null || true
		exec 9>&-
		YZ_DIAGNOSTICS_LOCKED=false
	fi
}

yz_diagnostics_prepare() {
	boot_id="$(tr -d '\r\n' <"$YZ_BOOT_ID_FILE" 2>/dev/null)"
	[ -n "$boot_id" ] || return 1
	yz_diag_ensure_dir "$YZ_STATE_DIR" 0700 || return 1
	yz_diag_ensure_dir "$YZ_DIAGNOSTICS_DIR" 0700 || return 1
	yz_diag_lock || return 1

	stored_boot_id=""
	if yz_diag_safe_dir "$YZ_CURRENT_DIAGNOSTICS_DIR" &&
		yz_diag_safe_file "$YZ_CURRENT_DIAGNOSTICS_DIR/boot_id"; then
		stored_boot_id="$(tr -d '\r\n' <"$YZ_CURRENT_DIAGNOSTICS_DIR/boot_id" 2>/dev/null)"
	fi
	if [ "$stored_boot_id" = "$boot_id" ]; then
		yz_diag_ensure_dir "$YZ_CURRENT_DIAGNOSTICS_DIR/logs" 0700 || {
			yz_diag_unlock
			return 1
		}
		yz_diag_copy_config "$YZ_CURRENT_DIAGNOSTICS_DIR" || true
		printf '%s\n' 'module-started' | yz_diag_atomic_write "$YZ_CURRENT_DIAGNOSTICS_DIR/evidence" || true
		yz_diag_unlock
		return 0
	fi

	if [ -e "$YZ_CURRENT_DIAGNOSTICS_DIR" ] || [ -L "$YZ_CURRENT_DIAGNOSTICS_DIR" ]; then
		yz_diag_safe_dir "$YZ_CURRENT_DIAGNOSTICS_DIR" || {
			yz_diag_unlock
			return 1
		}
		yz_diag_capture_previous "$YZ_CURRENT_DIAGNOSTICS_DIR"
		yz_diag_remove_generation "$YZ_OLD_DIAGNOSTICS_DIR" || {
			yz_diag_unlock
			return 1
		}
		mv "$YZ_CURRENT_DIAGNOSTICS_DIR" "$YZ_OLD_DIAGNOSTICS_DIR" || {
			yz_diag_unlock
			return 1
		}
	else
		yz_diag_import_legacy || {
			yz_diag_unlock
			return 1
		}
	fi

	staging="$YZ_DIAGNOSTICS_DIR/.current.tmp"
	yz_diag_remove_generation "$staging" || {
		yz_diag_unlock
		return 1
	}
	yz_diag_ensure_dir "$staging" 0700 || {
		yz_diag_unlock
		return 1
	}
	if ! yz_diag_initialize_generation "$staging" "$boot_id" ||
		! mv "$staging" "$YZ_CURRENT_DIAGNOSTICS_DIR"; then
		yz_diag_remove_generation "$staging" || true
		yz_diag_unlock
		return 1
	fi
	printf '%s\n' 'module-started' | yz_diag_atomic_write "$YZ_CURRENT_DIAGNOSTICS_DIR/evidence" || true
	yz_diag_unlock
}

yz_diagnostics_update_phase() {
	phase="${YZ_DIAGNOSTICS_PHASE:-unknown}"
	yz_diag_write_boot_state "$YZ_CURRENT_DIAGNOSTICS_DIR" "$phase"
}

yz_diag_rotate_fallback_file() {
	path="$1"
	archive="$2"
	if [ -L "$archive" ] || [ -f "$archive" ]; then
		rm -f "$archive" 2>/dev/null || return 1
	elif [ -e "$archive" ]; then
		return 1
	fi
	if [ -L "$path" ]; then
		rm -f "$path" 2>/dev/null || return 1
	elif [ -f "$path" ]; then
		mv "$path" "$archive" 2>/dev/null || return 1
	elif [ -e "$path" ]; then
		return 1
	fi
}

yz_diagnostics_prepare_fallback() {
	boot_id="$(tr -d '\r\n' <"$YZ_BOOT_ID_FILE" 2>/dev/null)"
	[ -n "$boot_id" ] || return 1
	yz_diag_ensure_dir "$YZ_STATE_DIR" 0700 || return 1
	yz_diag_ensure_dir "$YZ_FALLBACK_DIAGNOSTICS_DIR" 0700 || return 1
	stored_boot_id=""
	if yz_diag_safe_file "$YZ_FALLBACK_DIAGNOSTICS_DIR/boot_id"; then
		stored_boot_id="$(tr -d '\r\n' <"$YZ_FALLBACK_DIAGNOSTICS_DIR/boot_id" 2>/dev/null)"
	fi
	if [ "$stored_boot_id" != "$boot_id" ]; then
		for pair in bootstrap.log:bootstrap.old.log \
			zygiskd64.log:zygiskd64.old.log \
			zygiskd64.1.log:zygiskd64.1.old.log \
			zygiskd32.log:zygiskd32.old.log \
			zygiskd32.1.log:zygiskd32.1.old.log \
			linker64.json:linker64.old.json linker32.json:linker32.old.json \
			boot.json:boot.old.json evidence:evidence.old; do
			name="${pair%%:*}"
			archive_name="${pair#*:}"
			yz_diag_rotate_fallback_file \
				"$YZ_FALLBACK_DIAGNOSTICS_DIR/$name" \
				"$YZ_FALLBACK_DIAGNOSTICS_DIR/$archive_name" || return 1
		done
	fi
	printf '%s\n' "$boot_id" |
		yz_diag_atomic_write "$YZ_FALLBACK_DIAGNOSTICS_DIR/boot_id" || return 1
	yz_diag_write_boot_state "$YZ_FALLBACK_DIAGNOSTICS_DIR" fallback || return 1
	printf '%s\n' 'fallback-log' |
		yz_diag_atomic_write "$YZ_FALLBACK_DIAGNOSTICS_DIR/evidence" || true
}

yz_diag_prune_reports() {
	reports_dir="$1"
	set -- "$reports_dir"/YukiZygisk_report_*.tar.gz
	[ -e "$1" ] || return 0
	while [ "$#" -gt 3 ]; do
		if yz_diag_safe_file "$1"; then
			rm -f "$1" 2>/dev/null || true
		fi
		shift
	done
}

yz_diagnostics_export() {
	moddir="${YZ_MODULE_DIR:-${0%/*}}"
	reports_dir="$YZ_STATE_DIR/reports"
	staging="$YZ_STATE_DIR/.report.$$"
	yz_diag_ensure_dir "$reports_dir" 0700 || return 1
	yz_diag_prune_reports "$reports_dir"
	yz_diag_remove_generation "$staging" || return 1
	yz_diag_ensure_dir "$staging" 0700 || return 1

	collected_diagnostics=false
	collected_status=false
	collected_config=false
	collected_dmesg=false
	collected_fallback=false
	collected_legacy_bootstrap=false
	if yz_diag_safe_dir "$YZ_DIAGNOSTICS_DIR" &&
		cp -a "$YZ_DIAGNOSTICS_DIR" "$staging/diagnostics" 2>/dev/null; then
		collected_diagnostics=true
	fi
	if yz_diag_safe_file "$YZ_CONFIG_FILE" &&
		cp -p "$YZ_CONFIG_FILE" "$staging/config.json" 2>/dev/null; then
		collected_config=true
	fi
	if yz_diag_safe_dir "$YZ_LEGACY_LOG_DIR" &&
		cp -a "$YZ_LEGACY_LOG_DIR" "$staging/fallback" 2>/dev/null; then
		collected_fallback=true
	fi
	if yz_diag_safe_file "$YZ_STATE_DIR/zygiskd.log" &&
		cp -p "$YZ_STATE_DIR/zygiskd.log" "$staging/legacy-bootstrap.log" 2>/dev/null; then
		collected_legacy_bootstrap=true
	fi
	if [ -x "$moddir/bin/yzctl" ] &&
		"$moddir/bin/yzctl" status --json >"$staging/status.json" 2>/dev/null &&
		[ -s "$staging/status.json" ]; then
		collected_status=true
	else
		rm -f "$staging/status.json" 2>/dev/null
	fi
	if dmesg -r >"$staging/dmesg.txt" 2>/dev/null && [ -s "$staging/dmesg.txt" ]; then
		collected_dmesg=true
	else
		rm -f "$staging/dmesg.txt" 2>/dev/null
	fi
	if [ -f "$moddir/module.prop" ] && [ ! -L "$moddir/module.prop" ]; then
		cp -p "$moddir/module.prop" "$staging/module.prop" 2>/dev/null || true
	fi
	{
		printf 'diagnostics: %s\n' "$collected_diagnostics"
		printf 'status.json: %s\n' "$collected_status"
		printf 'config.json: %s\n' "$collected_config"
		printf 'dmesg.txt: %s\n' "$collected_dmesg"
		printf 'fallback: %s\n' "$collected_fallback"
		printf 'legacy-bootstrap.log: %s\n' "$collected_legacy_bootstrap"
	} >"$staging/collection.txt"
	chmod -R go-rwx "$staging" 2>/dev/null || true

	timestamp="$(date +%Y-%m-%d_%H-%M-%S 2>/dev/null || echo unknown)"
	name="YukiZygisk_report_${timestamp}.tar.gz"
	archive="$reports_dir/$name"
	temporary="$reports_dir/.${name}.tmp.$$"
	if [ -e "$archive" ] || [ -L "$archive" ]; then
		name="YukiZygisk_report_${timestamp}_$$.tar.gz"
		archive="$reports_dir/$name"
		temporary="$reports_dir/.${name}.tmp.$$"
	fi
	rm -f "$temporary" 2>/dev/null
	if ! tar -czf "$temporary" -C "$staging" . 2>/dev/null ||
		! tar -tzf "$temporary" >/dev/null 2>&1 || [ ! -s "$temporary" ]; then
		rm -f "$temporary" 2>/dev/null
		yz_diag_remove_generation "$staging" || true
		return 1
	fi
	chmod 0600 "$temporary" 2>/dev/null || true
	mv -f "$temporary" "$archive" || {
		yz_diag_remove_generation "$staging" || true
		return 1
	}
	yz_diag_remove_generation "$staging" || true

	download_dir="${YZ_DOWNLOAD_DIR:-/sdcard/Download}"
	final_path="$archive"
	if [ -d "$download_dir" ] && [ ! -L "$download_dir" ]; then
		download_tmp="$download_dir/.${name}.tmp.$$"
		download_path="$download_dir/$name"
		if [ ! -e "$download_path" ] && [ ! -L "$download_path" ] &&
			cp "$archive" "$download_tmp" 2>/dev/null &&
			mv "$download_tmp" "$download_path" 2>/dev/null; then
			final_path="$download_path"
			rm -f "$archive" 2>/dev/null || true
			if command -v am >/dev/null 2>&1; then
				am broadcast -a android.intent.action.MEDIA_SCANNER_SCAN_FILE \
					-d "file://$download_path" >/dev/null 2>&1 || true
			fi
		else
			rm -f "$download_tmp" 2>/dev/null
		fi
	fi
	yz_diag_prune_reports "$reports_dir"
	printf '%s\n' "$final_path"
}

yz_diagnostics_main() {
	case "${1:-}" in
	prepare)
		yz_diagnostics_prepare
		;;
	phase)
		YZ_DIAGNOSTICS_PHASE="${2:-unknown}"
		yz_diagnostics_update_phase
		;;
	export)
		yz_diagnostics_export
		;;
	*)
		printf '%s\n' 'Usage: diagnostics.sh {prepare|phase NAME|export}' >&2
		return 2
		;;
	esac
}

if [ "${0##*/}" = "diagnostics.sh" ]; then
	yz_diagnostics_main "$@"
fi
