#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# YukiZygisk local build and module packager.
#
# License: Apache-2.0
#
# Author: Anatdx

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"
OUT_DIR="$BUILD_DIR/out"
LKM_OUT_DIR="$OUT_DIR/lkm"
MODULE_TEMPLATE_DIR="$PROJECT_ROOT/module"
WEBUI_DIR="$PROJECT_ROOT/webui"
PACKAGE_DIR="$BUILD_DIR/package"

COMMAND="${1:-package}"
if [[ $# -gt 0 ]]; then
	shift
fi

ABI="arm64-v8a"
KMI="$(cat "$PROJECT_ROOT/.ddk-version" 2>/dev/null || echo android16-6.12)"
ANDROID_PLATFORM="android-31"
ANDROID_NDK="${ANDROID_NDK:-${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}}"
SKIP_KERNEL=false
SKIP_DAEMON=false
SKIP_CTL=false
SKIP_PAYLOADS=false
KEEP_BUILD=false
STRIP_ANDROID=true
VERBOSE=false
ALL_KMIS=false

KMI_TARGETS=(
	android12-5.10
	android13-5.10
	android13-5.15
	android14-5.15
	android14-6.1
	android15-6.6
	android16-6.12
)

usage() {
	cat <<EOF
YukiZygisk local build and module packager.

Usage:
  ./build.sh [package|kernel|daemon|ctl|payloads|clean] [options]

Options:
  -k, --kmi KMI              Build/package one DDK target (default: .ddk-version)
      --all-kmis             Build/package every supported KMI
  -a, --abi ABI              Primary device ABI; compat ARM is always included
      --android-platform API Android platform (default: android-31)
      --ndk PATH             Android NDK path
      --skip-kernel          Reuse KMI-tagged modules in build/out/lkm
      --skip-daemon          Reuse build/out/zygiskd64 and zygiskd32
      --skip-ctl             Reuse build/out/yzctl
      --skip-payloads        Reuse dual-ABI build/out/lib*.so payloads
      --keep-build           Keep intermediate build directories
      --no-strip             Keep debug info in Android artifacts
  -v, --verbose              Verbose CMake configure output
  -h, --help                 Show this help
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	-k | --kmi)
		KMI="$2"
		shift 2
		;;
	--all-kmis)
		ALL_KMIS=true
		shift
		;;
	-a | --abi)
		ABI="$2"
		shift 2
		;;
	--android-platform)
		ANDROID_PLATFORM="$2"
		shift 2
		;;
	--ndk)
		ANDROID_NDK="$2"
		shift 2
		;;
	--skip-kernel)
		SKIP_KERNEL=true
		shift
		;;
	--skip-daemon)
		SKIP_DAEMON=true
		shift
		;;
	--skip-ctl)
		SKIP_CTL=true
		shift
		;;
	--skip-payloads)
		SKIP_PAYLOADS=true
		shift
		;;
	--keep-build)
		KEEP_BUILD=true
		shift
		;;
	--no-strip)
		STRIP_ANDROID=false
		shift
		;;
	-v | --verbose)
		VERBOSE=true
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "Unknown option: $1" >&2
		usage >&2
		exit 1
		;;
	esac
done

info() {
	printf '>>> %s\n' "$*"
}

die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

need_cmd() {
	command -v "$1" >/dev/null 2>&1 || die "$1 is required"
}

find_ndk() {
	if [[ -n "$ANDROID_NDK" && -d "$ANDROID_NDK" ]]; then
		return
	fi

	local bases=(
		"$HOME/Library/Android/sdk/ndk"
		"$HOME/Android/Sdk/ndk"
		"$HOME/android-sdk/ndk"
		"/opt/android-sdk/ndk"
	)
	local base latest
	for base in "${bases[@]}"; do
		if [[ -d "$base" ]]; then
			latest="$(find "$base" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | tail -n 1)"
			if [[ -n "$latest" && -d "$latest" ]]; then
				ANDROID_NDK="$latest"
				return
			fi
		fi
	done

	die "Android NDK not found; set ANDROID_NDK, ANDROID_NDK_HOME, or --ndk"
}

detect_ndk_host() {
	local prebuilt="$ANDROID_NDK/toolchains/llvm/prebuilt"
	local host
	for host in darwin-x86_64 darwin-arm64 linux-x86_64; do
		if [[ -d "$prebuilt/$host" ]]; then
			echo "$host"
			return
		fi
	done
	die "cannot detect NDK prebuilt toolchain under $prebuilt"
}

strip_android_file() {
	local mode="$1"
	local file="$2"
	[[ "$STRIP_ANDROID" == true ]] || return 0
	find_ndk
	local host strip
	host="$(detect_ndk_host)"
	strip="$ANDROID_NDK/toolchains/llvm/prebuilt/$host/bin/llvm-strip"
	[[ -x "$strip" ]] || die "missing llvm-strip: $strip"
	"$strip" "$mode" "$file"
}

strip_kernel_file() {
	local file="$1"
	[[ "$STRIP_ANDROID" == true ]] || return 0
	if command -v llvm-strip >/dev/null 2>&1; then
		llvm-strip -d "$file"
	else
		strip_android_file -d "$file"
	fi
}

check_common_deps() {
	need_cmd cmake
	need_cmd ninja
}

check_kernel_deps() {
	need_cmd ddk
}

check_package_deps() {
	need_cmd zip
}

compute_version() {
	local version count
	version="$(sed -n 's/^version=//p' "$PROJECT_ROOT/module/module.prop" | tr -d '\r')"
	[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid base version in module/module.prop: $version"
	count="$(git -C "$PROJECT_ROOT" rev-list --count HEAD 2>/dev/null || echo "0")"
	VERSION_CODE=$((count + 10000))
	VERSION_NAME="${version}-${VERSION_CODE}"
	export VERSION_NAME VERSION_CODE
}

stamp_module_prop() {
	local prop="$PACKAGE_DIR/module.prop"
	[[ -f "$prop" ]] || die "missing $prop"
	if [[ "$(uname -s)" == "Darwin" ]]; then
		sed -i '' "s/^version=.*/version=$VERSION_NAME/" "$prop"
		sed -i '' "s/^versionCode=.*/versionCode=$VERSION_CODE/" "$prop"
	else
		sed -i "s/^version=.*/version=$VERSION_NAME/" "$prop"
		sed -i "s/^versionCode=.*/versionCode=$VERSION_CODE/" "$prop"
	fi
}

kernel_targets() {
	if [[ "$ALL_KMIS" == true ]]; then
		printf '%s\n' "${KMI_TARGETS[@]}"
	else
		printf '%s\n' "$KMI"
	fi
}

validate_kmi() {
	local target="$1"
	[[ "$target" =~ ^android[0-9]+-[0-9]+\.[0-9]+$ ]] ||
		die "invalid KMI target: $target"
}

validate_android_platform() {
	local api
	if [[ "$ANDROID_PLATFORM" =~ ^android-([0-9]+)$ ]]; then
		api=$((10#${BASH_REMATCH[1]}))
	elif [[ "$ANDROID_PLATFORM" =~ ^[0-9]+$ ]]; then
		api=$((10#$ANDROID_PLATFORM))
		ANDROID_PLATFORM="android-$api"
	else
		die "invalid Android platform: $ANDROID_PLATFORM"
	fi
	((api >= 31 && api < 10000)) ||
		die "Android platform must be a concrete API level >= 31"
}

lkm_output_path() {
	printf '%s/%s_yukizygisk.ko\n' "$LKM_OUT_DIR" "$1"
}

check_staged_kernels() {
	local target output
	while IFS= read -r target; do
		validate_kmi "$target"
		output="$(lkm_output_path "$target")"
		[[ -f "$output" ]] || die "missing staged kernel module: $output"
	done < <(kernel_targets)
}

build_one_kernel() {
	local target="$1"
	local output
	validate_kmi "$target"
	output="$(lkm_output_path "$target")"

	info "Build yukizygisk.ko with DDK ($target)"
	case "$target" in
	android15-6.6 | android16-6.12)
		ddk build --target "$target" -- W=1
		;;
	*)
		ddk build --target "$target"
		;;
	esac
	[[ -f "$PROJECT_ROOT/kernel/yukizygisk.ko" ]] ||
		die "DDK build completed but kernel/yukizygisk.ko is missing"

	mkdir -p "$LKM_OUT_DIR"
	cp "$PROJECT_ROOT/kernel/yukizygisk.ko" "$output"
	strip_kernel_file "$output"
	info "Kernel: $output"
}

build_kernel() {
	if [[ "$SKIP_KERNEL" == true ]]; then
		check_staged_kernels
		info "Skip kernel build"
		return
	fi

	check_kernel_deps
	local target
	if [[ "$ALL_KMIS" == true ]]; then
		while IFS= read -r target; do
			rm -f "$(lkm_output_path "$target")"
		done < <(kernel_targets)
	fi
	while IFS= read -r target; do
		build_one_kernel "$target"
		if [[ "$ALL_KMIS" == true ]]; then
			ddk clean --target "$target" >/dev/null 2>&1 || true
		fi
	done < <(kernel_targets)
}

build_daemon() {
	if [[ "$SKIP_DAEMON" == true ]]; then
		[[ -f "$OUT_DIR/zygiskd64" && -f "$OUT_DIR/zygiskd32" ]] ||
			die "--skip-daemon requested but dual-ABI daemon outputs are missing"
		info "Skip daemon build"
		return
	fi

	check_common_deps
	find_ndk
	[[ -f "$ANDROID_NDK/build/cmake/android.toolchain.cmake" ]] ||
		die "invalid Android NDK: $ANDROID_NDK"

	mkdir -p "$OUT_DIR"
	local target_abi output subdir bin
	for target_abi in arm64-v8a armeabi-v7a; do
		output="zygiskd64"
		[[ "$target_abi" == armeabi-v7a ]] && output="zygiskd32"
		subdir="$BUILD_DIR/$target_abi"
		local cmake_args=(
			-S "$PROJECT_ROOT"
			-B "$subdir"
			-G Ninja
			-DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK/build/cmake/android.toolchain.cmake"
			-DANDROID_ABI="$target_abi"
			-DANDROID_PLATFORM="$ANDROID_PLATFORM"
			-DCMAKE_BUILD_TYPE=Release
		)
		if [[ "$VERBOSE" == true ]]; then
			cmake_args+=("--log-level=VERBOSE")
		fi
		info "Build $output ($target_abi, $ANDROID_PLATFORM)"
		cmake "${cmake_args[@]}"
		cmake --build "$subdir" --target "$output"
		bin="$subdir/userspace/zygisk/daemon/$output"
		[[ -f "$bin" ]] || die "$output missing: $bin"
		cp "$bin" "$OUT_DIR/$output"
		strip_android_file --strip-all "$OUT_DIR/$output"
		chmod 0755 "$OUT_DIR/$output"
	done
}

build_payloads() {
	local lib
	rm -f "$OUT_DIR/libzygisk.so" "$OUT_DIR/libyukilinker.so" \
		"$OUT_DIR/libyukizncore.so"
	if [[ "$SKIP_PAYLOADS" == true ]]; then
		for lib in libzygisk64.so libzygisk32.so libyukilinker64.so \
			libyukilinker32.so libyukizncore64.so libyukizncore32.so; do
			[[ -f "$OUT_DIR/$lib" ]] ||
				die "--skip-payloads requested but build/out/$lib is missing"
		done
		info "Skip runtime payload build"
		return
	fi

	check_common_deps
	find_ndk
	[[ -f "$ANDROID_NDK/build/cmake/android.toolchain.cmake" ]] ||
		die "invalid Android NDK: $ANDROID_NDK"

	mkdir -p "$OUT_DIR"
	local target_abi suffix subdir src output
	for target_abi in arm64-v8a armeabi-v7a; do
		suffix="64"
		[[ "$target_abi" == armeabi-v7a ]] && suffix="32"
		subdir="$BUILD_DIR/$target_abi"
		local cmake_args=(
			-S "$PROJECT_ROOT"
			-B "$subdir"
			-G Ninja
			-DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK/build/cmake/android.toolchain.cmake"
			-DANDROID_ABI="$target_abi"
			-DANDROID_PLATFORM="$ANDROID_PLATFORM"
			-DCMAKE_BUILD_TYPE=Release
		)
		if [[ "$VERBOSE" == true ]]; then
			cmake_args+=("--log-level=VERBOSE")
		fi
		info "Build runtime payloads ($target_abi, $ANDROID_PLATFORM)"
		cmake "${cmake_args[@]}"
		cmake --build "$subdir" --target zygisk yukilinker yukizncore
		for lib in libzygisk libyukilinker libyukizncore; do
			src="$subdir/userspace/zygisk/core/$lib$suffix.so"
			output="$lib$suffix.so"
			[[ -f "$src" ]] || die "runtime payload output missing: $src"
			cp "$src" "$OUT_DIR/$output"
			strip_android_file --strip-all "$OUT_DIR/$output"
			chmod 0644 "$OUT_DIR/$output"
		done
	done
}

build_ctl() {
	if [[ "$SKIP_CTL" == true ]]; then
		[[ -f "$OUT_DIR/yzctl" ]] ||
			die "--skip-ctl requested but build/out/yzctl is missing"
		info "Skip yzctl build"
		return
	fi

	check_common_deps
	find_ndk
	[[ -f "$ANDROID_NDK/build/cmake/android.toolchain.cmake" ]] ||
		die "invalid Android NDK: $ANDROID_NDK"

	mkdir -p "$OUT_DIR"
	local subdir="$BUILD_DIR/arm64-v8a"
	local cmake_args=(
		-S "$PROJECT_ROOT"
		-B "$subdir"
		-G Ninja
		-DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK/build/cmake/android.toolchain.cmake"
		-DANDROID_ABI=arm64-v8a
		-DANDROID_PLATFORM="$ANDROID_PLATFORM"
		-DCMAKE_BUILD_TYPE=Release
	)
	if [[ "$VERBOSE" == true ]]; then
		cmake_args+=("--log-level=VERBOSE")
	fi
	info "Build yzctl (arm64-v8a, $ANDROID_PLATFORM)"
	cmake "${cmake_args[@]}"
	cmake --build "$subdir" --target yzctl
	local bin="$subdir/userspace/yzctl/yzctl"
	[[ -f "$bin" ]] || die "yzctl missing: $bin"
	cp "$bin" "$OUT_DIR/yzctl"
	strip_android_file --strip-all "$OUT_DIR/yzctl"
	chmod 0755 "$OUT_DIR/yzctl"
}

validate_android_platform

[[ "$ABI" == "arm64-v8a" ]] ||
	die "standalone packages require an arm64-v8a device with optional ARM compat"

stage_payloads() {
	local source destination payload
	local payloads=(
		"libzygisk64.so:lib64/libzygisk.so"
		"libyukilinker64.so:lib64/libyukilinker.so"
		"libyukizncore64.so:lib64/libyukizncore.so"
		"libzygisk32.so:lib/libzygisk.so"
		"libyukilinker32.so:lib/libyukilinker.so"
		"libyukizncore32.so:lib/libyukizncore.so"
	)
	for payload in "${payloads[@]}"; do
		source="${payload%%:*}"
		destination="${payload#*:}"
		if [[ -f "$OUT_DIR/$source" ]]; then
			mkdir -p "$PACKAGE_DIR/${destination%/*}"
			cp "$OUT_DIR/$source" "$PACKAGE_DIR/$destination"
		else
			die "missing runtime payload: build/out/$source"
		fi
	done
}

package_module() {
	check_package_deps
	compute_version

	[[ -d "$MODULE_TEMPLATE_DIR" ]] || die "missing module template: $MODULE_TEMPLATE_DIR"
	[[ -f "$WEBUI_DIR/index.html" ]] || die "missing WebUI: $WEBUI_DIR"
	[[ -f "$OUT_DIR/zygiskd64" && -f "$OUT_DIR/zygiskd32" ]] ||
		die "missing dual-ABI daemon outputs"
	[[ -f "$OUT_DIR/yzctl" ]] || die "missing yzctl output"
	check_staged_kernels

	info "Stage module"
	rm -rf "$PACKAGE_DIR"
	mkdir -p "$PACKAGE_DIR"
	cp -R "$MODULE_TEMPLATE_DIR/." "$PACKAGE_DIR/"
	cp -R "$WEBUI_DIR" "$PACKAGE_DIR/webroot"
	stamp_module_prop
	cp "$PROJECT_ROOT/LICENSE" "$PACKAGE_DIR/LICENSE"
	cp "$PROJECT_ROOT/LICENSE-GPL-2.0" "$PACKAGE_DIR/LICENSE-GPL-2.0"
	cp "$PROJECT_ROOT/NOTICE" "$PACKAGE_DIR/NOTICE"
	cp "$PROJECT_ROOT/userspace/zygisk/third_party/lsplt/LICENSE" \
		"$PACKAGE_DIR/LICENSE-LSPLT"
	mkdir -p "$PACKAGE_DIR/lkm"
	local target source
	while IFS= read -r target; do
		source="$(lkm_output_path "$target")"
		cp "$source" "$PACKAGE_DIR/lkm/${target}_yukizygisk.ko"
	done < <(kernel_targets)
	mkdir -p "$PACKAGE_DIR/bin" "$PACKAGE_DIR/lib64" "$PACKAGE_DIR/lib"
	cp "$OUT_DIR/zygiskd64" "$PACKAGE_DIR/bin/zygiskd64"
	cp "$OUT_DIR/zygiskd32" "$PACKAGE_DIR/bin/zygiskd32"
	cp "$OUT_DIR/yzctl" "$PACKAGE_DIR/bin/yzctl"
	stage_payloads

	chmod 0644 "$PACKAGE_DIR/module.prop" "$PACKAGE_DIR"/lkm/*.ko \
		"$PACKAGE_DIR"/lib64/*.so "$PACKAGE_DIR"/lib/*.so "$PACKAGE_DIR"/LICENSE* \
		"$PACKAGE_DIR/NOTICE"
	chmod 0755 "$PACKAGE_DIR/bin/zygiskd64" "$PACKAGE_DIR/bin/zygiskd32" \
		"$PACKAGE_DIR/bin/yzctl" \
		"$PACKAGE_DIR/post-fs-data.sh" \
		"$PACKAGE_DIR/boot-completed.sh" "$PACKAGE_DIR/customize.sh" \
		"$PACKAGE_DIR/action.sh" \
		2>/dev/null || true
	find "$PACKAGE_DIR/webroot" -type f -exec chmod 0644 {} +

	local package_target="$KMI"
	if [[ "$ALL_KMIS" == true ]]; then
		package_target="all-kmi"
	fi
	local zip_name="YukiZygisk-${VERSION_NAME}-${package_target}-${ABI}.zip"
	local zip_path="$OUT_DIR/$zip_name"
	rm -f "$zip_path"
	info "Create module zip: $zip_path"
	find "$PACKAGE_DIR" -type f -exec touch -t 198001010000 {} +
	(
		cd "$PACKAGE_DIR"
		LC_ALL=C find . -type f -print | LC_ALL=C sort | zip -qX "$zip_path" -@
	)
	info "Done: $zip_path"
}

clean() {
	rm -rf "$BUILD_DIR"
	local target
	while IFS= read -r target; do
		ddk clean --target "$target" >/dev/null 2>&1 || true
	done < <(kernel_targets)
	info "Cleaned"
}

case "$COMMAND" in
kernel)
	build_kernel
	;;
daemon)
	build_daemon
	;;
ctl)
	build_ctl
	;;
payloads)
	build_payloads
	;;
package)
	build_kernel
	build_daemon
	build_ctl
	build_payloads
	package_module
	if [[ "$KEEP_BUILD" != true ]]; then
		rm -rf "${BUILD_DIR:?}/$ABI" "${PACKAGE_DIR:?}"
		if [[ "$ALL_KMIS" != true ]]; then
			ddk clean --target "$KMI" >/dev/null 2>&1 || true
		fi
	fi
	;;
clean)
	clean
	;;
-h | --help | help)
	usage
	;;
*)
	die "unknown command: $COMMAND"
	;;
esac
