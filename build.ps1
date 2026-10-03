#!/usr/bin/env pwsh
# SPDX-License-Identifier: Apache-2.0
#
# YukiZygisk native Windows build (standalone)
# Usage: .\build.ps1 [-k KMI] [--clean] [--skip-lkm] [-i] [--serial SERIAL] [--help]
# -k/--kmi: DDK target (default: .ddk-version, currently android16-6.12)
# --skip-lkm: Reuse existing build/out/lkm/<kmi>_yukizygisk.ko
# -i/--install: Run `ksud module install` after packaging
# --serial: Optional adb serial when multiple devices are connected

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Show-Usage {
	@'
YukiZygisk native Windows build (standalone)

Usage:
  .\build.ps1 [options]

Options:
  -k, --kmi KMI              DDK target/KMI (default: .ddk-version)
  --clean                     Delete CMake build dirs before compiling userspace
  --skip-lkm                  Reuse existing build/out/lkm/<KMI>_yukizygisk.ko
  -i, --install               Install resulting module zip with `ksud module install`
  --serial SERIAL             adb serial for installation
  --viola-profile PROFILE     official or dev (default: official)
  --viola-key FINGERPRINT     Development signing subkey
  --viola-public-key FILE     Development public certificate
  --no-strip                  Keep unstripped artifacts in module zip
  -h, --help                  Show this help

Environment:
  ANDROID_SDK_ROOT / ANDROID_HOME
  ANDROID_NDK_HOME / ANDROID_NDK
  DDK_RELEASE / YZ_DDK_RELEASE (default: 20260313 for docker fallback)
  YZ_DDK_IMAGE (docker image override for kernel build fallback)
  VIOLA_PYTHON (Python with tools/requirements-viola.txt installed)
  VIOLA_HOST_CC (native host C compiler; default: clang)
  VIOLA_GPG / GNUPGHOME / VIOLA_GPG_PASSPHRASE
  NUMBER_OF_PROCESSORS
'@ | Write-Host
}

function Invoke-Native {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)][string]$FilePath,
		[string[]]$ArgumentList = @(),
		[string]$WorkingDirectory
	)
	$displayArguments = @()
	foreach ($arg in $ArgumentList) {
		if ($arg -match '[\s"]') {
			$displayArguments += ('"' + ($arg -replace '"', '\"') + '"')
		}
		else {
			$displayArguments += $arg
		}
	}
	$display = "$FilePath $($displayArguments -join ' ')"
	Write-Host "  > $display" -ForegroundColor DarkGray

	$oldLocation = Get-Location
	$oldErrorActionPreference = $ErrorActionPreference
	try {
		if ($WorkingDirectory) {
			Set-Location -LiteralPath $WorkingDirectory
		}
		$ErrorActionPreference = 'Continue'
		& $FilePath @ArgumentList
		$exitCode = $LASTEXITCODE
	}
	finally {
		$ErrorActionPreference = $oldErrorActionPreference
		Set-Location -LiteralPath $oldLocation
	}
	if ($exitCode -ne 0) {
		throw "Command failed with exit code $($exitCode): $FilePath $($ArgumentList -join ' ')"
	}
}

function Assert-SafeBuildDirectory {
	param([Parameter(Mandatory = $true)][string]$Path)
	$fullPath = [IO.Path]::GetFullPath($Path)
	$repoPrefix = [IO.Path]::GetFullPath($script:RepoRoot).TrimEnd('\') + '\'
	if (-not $fullPath.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) {
		throw "Refusing to clean outside repo: $fullPath"
	}
	if ((Split-Path -Leaf $fullPath) -notmatch '^build(?:-[A-Za-z0-9._-]+)?$') {
		throw "Refusing to clean non-build directory: $fullPath"
	}
}

function Reset-BuildDirectory {
	param([Parameter(Mandatory = $true)][string]$Path)
	Assert-SafeBuildDirectory -Path $Path
	if (Test-Path -LiteralPath $Path) {
		Remove-Item -LiteralPath $Path -Recurse -Force
	}
	New-Item -ItemType Directory -Path $Path -Force | Out-Null
}

function Ensure-Command {
	param([string]$Name)
	$command = Get-Command $Name -ErrorAction SilentlyContinue
	if (-not $command) { return $null }
	return $command.Source
}

function Resolve-AndroidSdk {
	$candidates = New-Object System.Collections.Generic.List[string]
	foreach ($candidate in @($env:ANDROID_SDK_ROOT, $env:ANDROID_HOME)) {
		if ($candidate) {
			$candidates.Add($candidate)
		}
	}

	$localProperties = Join-Path $script:RepoRoot 'manager\local.properties'
	if (Test-Path -LiteralPath $localProperties) {
		$sdkLine = Get-Content -LiteralPath $localProperties | Where-Object { $_ -match '^sdk\.dir=' } | Select-Object -First 1
		if ($sdkLine -and $sdkLine -match '^sdk\.dir=(.+)$') {
			$localSdk = $Matches[1] -replace '\\:', ':' -replace '\\\\', '\'
			$candidates.Add($localSdk)
		}
	}

	if ($env:LOCALAPPDATA) { $candidates.Add((Join-Path $env:LOCALAPPDATA 'Android\Sdk')) }
	$candidates.Add('D:\Softwares\AndroidSDK')

	foreach ($candidate in $candidates | Select-Object -Unique) {
		if (-not $candidate) { continue }
		$platforms = Join-Path $candidate 'platforms'
		$ndkPath = Join-Path $candidate 'ndk'
		if ((Test-Path -LiteralPath $platforms) -and (Test-Path -LiteralPath $ndkPath)) {
			return [IO.Path]::GetFullPath($candidate)
		}
	}
	throw 'Android SDK not found. Set ANDROID_SDK_ROOT or ANDROID_HOME, or install SDK under D:\Softwares\AndroidSDK.'
}

function Resolve-Ndk {
	$ndkCandidates = New-Object System.Collections.Generic.List[string]
	foreach ($candidate in @($env:ANDROID_NDK_HOME, $env:ANDROID_NDK, $env:ANDROID_NDK_ROOT)) {
		if ($candidate) { $ndkCandidates.Add($candidate) }
	}

	if ($script:SdkRoot -and (Test-Path -LiteralPath (Join-Path $script:SdkRoot 'ndk'))) {
		$ndkFromSdk = Get-ChildItem -LiteralPath (Join-Path $script:SdkRoot 'ndk') -Directory -ErrorAction SilentlyContinue |
			Sort-Object Name -Descending |
			Select-Object -First 1 |
			ForEach-Object { $_.FullName }
		if ($ndkFromSdk) { $ndkCandidates.Add($ndkFromSdk) }
	}

	foreach ($candidate in $ndkCandidates | Select-Object -Unique) {
		if (-not $candidate) { continue }
		if (Test-Path -LiteralPath $candidate) {
			$toolchain = Join-Path $candidate 'build\cmake\android.toolchain.cmake'
			$clang = Join-Path $candidate 'toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe'
			if ((Test-Path -LiteralPath $toolchain) -and (Test-Path -LiteralPath $clang)) {
				return [IO.Path]::GetFullPath($candidate)
			}
		}
	}
	throw 'Valid Android NDK not found. Set ANDROID_NDK_HOME or provide a valid SDK with ndk directory.'
}

function Resolve-BuildTools {
	$cmakeInstall = $null
	$ninjaInstall = $null

	if ($script:NdkRoot) {
		$ndkBin = Join-Path $script:NdkRoot 'toolchains\llvm\prebuilt\windows-x86_64\bin'
		$candidateNinja = Join-Path $ndkBin 'ninja.exe'
		$candidateCmake = Join-Path $ndkBin 'cmake.exe'
		if (Test-Path -LiteralPath $candidateCmake) { $cmakeInstall = [IO.Path]::GetFullPath($candidateCmake) }
		if (Test-Path -LiteralPath $candidateNinja) { $ninjaInstall = [IO.Path]::GetFullPath($candidateNinja) }
	}

	if (-not $cmakeInstall -or -not $ninjaInstall) {
		if ($script:SdkRoot) {
			$cmakeDirs = Get-ChildItem -LiteralPath (Join-Path $script:SdkRoot 'cmake') -Directory -ErrorAction SilentlyContinue |
				Sort-Object Name -Descending
			foreach ($dir in $cmakeDirs) {
				$binDir = Join-Path $dir.FullName 'bin'
				$candidateCmake = Join-Path $binDir 'cmake.exe'
				$candidateNinja = Join-Path $binDir 'ninja.exe'
				if (-not $cmakeInstall -and (Test-Path -LiteralPath $candidateCmake)) { $cmakeInstall = [IO.Path]::GetFullPath($candidateCmake) }
				if (-not $ninjaInstall -and (Test-Path -LiteralPath $candidateNinja)) { $ninjaInstall = [IO.Path]::GetFullPath($candidateNinja) }
				if ($cmakeInstall -and $ninjaInstall) { break }
			}
		}
	}

	if (-not $cmakeInstall) {
		$cmakeBin = Ensure-Command 'cmake'
		if ($cmakeBin) { $cmakeInstall = $cmakeBin }
	}
	if (-not $ninjaInstall) {
		$ninjaBin = Ensure-Command 'ninja'
		if ($ninjaBin) { $ninjaInstall = $ninjaBin }
	}

	if (-not $cmakeInstall -or -not $ninjaInstall) {
		throw 'cmake and ninja are required. Ensure they are installed and in PATH.'
	}

	return @{
		CMake = $cmakeInstall
		Ninja = $ninjaInstall
		LLVMStrip = Join-Path $script:NdkRoot 'toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-strip.exe'
	}
}

function Get-ComputeVersion {
	$moduleVersionLine = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'module\module.prop') |
		Where-Object { $_ -match '^version=' } | Select-Object -First 1
	if (-not $moduleVersionLine -or $moduleVersionLine -notmatch '^version=(v[0-9]+\.[0-9]+\.[0-9]+)$') {
		throw 'Invalid base version in module/module.prop; expected vMAJOR.MINOR.PATCH.'
	}
	$baseVersion = $Matches[1]
	$revCount = & git -C $script:RepoRoot rev-list --count HEAD
	if ($LASTEXITCODE -ne 0) { $revCount = '0' }
	$versionCode = [int]$revCount + 10000
	$script:VersionName = "$baseVersion-$versionCode"
	$script:VersionCode = [string]$versionCode
}

function Stamp-ModuleProp {
	param([string]$Source, [string]$Destination)
	Copy-Item -LiteralPath $Source -Destination $Destination -Force
	$content = Get-Content -LiteralPath $Destination
	$content = $content -replace '^version=.*', "version=$($script:VersionName)"
	$content = $content -replace '^versionCode=.*', "versionCode=$($script:VersionCode)"
	if ($script:ViolaProfile -eq 'dev') {
		$content = $content -replace '^name=.*', 'name=YukiZygisk (Development)'
	}
  Set-Content -LiteralPath $Destination -Value $content
}

function Normalize-LineEndingsLf {
	param([string]$Path)
	$content = [IO.File]::ReadAllText($Path)
	$normalized = $content -replace "`r`n", "`n"
	if ($normalized -ne $content) {
		[IO.File]::WriteAllText($Path, $normalized)
	}
}

function Build-CMakeProject {
	param(
		[string]$Name,
		[string]$SourceDirectory,
		[string]$BuildDirectory,
		[string]$Abi,
		[int]$Platform
	)

	Write-Host ">>> Build $Name ($Abi, android-$Platform)" -ForegroundColor Cyan
	if ($script:CleanBuild) {
		Reset-BuildDirectory -Path $BuildDirectory
	}
	else {
		New-Item -ItemType Directory -Path $BuildDirectory -Force | Out-Null
	}

	$configureArguments = @(
		'-S', $SourceDirectory,
		'-B', $BuildDirectory,
		'-G', 'Ninja',
		"-DCMAKE_TOOLCHAIN_FILE=$script:NdkToolchainFile",
		"-DANDROID_ABI=$Abi",
		"-DANDROID_PLATFORM=android-$Platform",
		'-DCMAKE_BUILD_TYPE=Release',
		"-DCMAKE_MAKE_PROGRAM=$script:NinjaExe",
		"-DVIOLA_BUILD_DIR=$script:ViolaContext"
	)
	Invoke-Native -FilePath $script:CMakeExe -ArgumentList $configureArguments
	Invoke-Native -FilePath $script:CMakeExe -ArgumentList @('--build', $BuildDirectory, '--parallel', "$script:BuildJobs")
}

function Copy-RequiredFile {
	param([string]$Source, [string]$Destination)
	if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
		throw "Expected output missing: $Source"
	}
	$destDir = Split-Path -Parent $Destination
	New-Item -ItemType Directory -Path $destDir -Force | Out-Null
	Copy-Item -LiteralPath $Source -Destination $Destination -Force
}

function Strip-AndroidFile {
	param(
		[string]$FilePath,
		[string[]]$Mode = @('--strip-all')
	)
	if (-not $script:StripAndroid) { return }
	if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) { return }
	if (Test-Path -LiteralPath $script:LlvmStrip -PathType Leaf) {
		Invoke-Native -FilePath $script:LlvmStrip -ArgumentList @($Mode + $FilePath)
	}
}

function Build-KernelLkm {
	$target = $script:Kmi
	$kernelSourceKo = Join-Path $script:RepoRoot 'kernel\yukizygisk.ko'
	$lkmOutput = Join-Path $script:OutDir "lkm\${target}_yukizygisk.ko"
	New-Item -ItemType Directory -Path (Split-Path -Parent $lkmOutput) -Force | Out-Null

	if ($script:SkipLkm) {
		if (-not (Test-Path -LiteralPath $lkmOutput -PathType Leaf)) {
			throw "Skip-lkm requested but kernel module not found: $lkmOutput"
		}
		Write-Host ">>> [1/4] Skip LKM"
		return $lkmOutput
	}

	Write-Host ">>> [1/4] Build kernel LKM ($target) ..." -ForegroundColor Cyan
	$ddkCommand = Ensure-Command 'ddk'
	if ($ddkCommand) {
		$ddkArguments = @('build', '--target', $target, '--', "VIOLA_KMI_ID=$script:KmiId")
		switch ($target) {
			'android15-6.6' { $ddkArguments += @('W=1') }
			'android16-6.12' { $ddkArguments += @('W=1') }
			default { }
		}
		Invoke-Native -FilePath $ddkCommand -ArgumentList $ddkArguments -WorkingDirectory $script:RepoRoot
	}
	else {
		$dockerCommand = Ensure-Command 'docker'
		if (-not $dockerCommand) { throw 'ddk not found and docker is unavailable. Install ddk or docker to build kernel modules.' }

		$release = if ($env:DDK_RELEASE) { $env:DDK_RELEASE } elseif ($env:YZ_DDK_RELEASE) { $env:YZ_DDK_RELEASE } else { '20260313' }
		$ddkImage = if ($env:YZ_DDK_IMAGE) { $env:YZ_DDK_IMAGE } else { "ghcr.io/ylarod/ddk:${target}-$release" }
		$makeExtras = @('make', '-C', 'kernel', "-j$($script:BuildJobs)", 'KDIR=$KDIR', 'CC=clang', "VIOLA_KMI_ID=$script:KmiId")
		if ($target -in @('android15-6.6', 'android16-6.12')) {
			$makeExtras += 'W=1'
		}
		$makeCommand = "cd /src && $($makeExtras -join ' ')"
		$dockerArguments = @(
			'run', '--platform', 'linux/amd64', '--rm',
			'-v', "$($script:RepoRoot):/src",
			'-w', '/src',
			$ddkImage,
			'bash', '-lc', $makeCommand
		)
		Invoke-Native -FilePath $dockerCommand -ArgumentList $dockerArguments
	}

	Copy-RequiredFile -Source $kernelSourceKo -Destination $lkmOutput
	Strip-AndroidFile -FilePath $lkmOutput -Mode @('-d')
	return $lkmOutput
}

function Invoke-ViolaTool {
	param([string[]]$Arguments)
	$toolArguments = @((Join-Path $script:RepoRoot 'tools/viola.py')) + $Arguments
	if ($env:VIOLA_GPG -and $Arguments[0] -in @('prepare', 'sign')) {
		$toolArguments += @('--gpg', $env:VIOLA_GPG)
	}
	Invoke-Native -FilePath $script:ViolaPython -ArgumentList $toolArguments
}

function Prepare-Viola {
	$ndkLine = Get-Content (Join-Path $script:NdkRoot 'source.properties') | Where-Object { $_ -match '^Pkg.Revision\s*=' } | Select-Object -First 1
	$ndkRevision = ($ndkLine -replace '^Pkg.Revision\s*=\s*', '').Trim()
	$stripMode = if ($script:StripAndroid) { 1 } else { 0 }
	$ddkRelease = if ($env:DDK_RELEASE) { $env:DDK_RELEASE } elseif ($env:YZ_DDK_RELEASE) { $env:YZ_DDK_RELEASE } else { '20260313' }
	$buildConfig = "api=31;ndk=$ndkRevision;strip=$stripMode;ddk=$ddkRelease"
	$prepareArguments = @('prepare', '--out', $script:ViolaContext, '--profile', $script:ViolaProfile, '--version-code', "$script:VersionCode", '--build-config', $buildConfig)
	if ($script:ViolaKey) { $prepareArguments += @('--key', $script:ViolaKey) }
	if ($script:ViolaPublicKey) { $prepareArguments += @('--public-key', $script:ViolaPublicKey) }
	Invoke-ViolaTool -Arguments $prepareArguments
}

function Build-ViolaHost {
	$compiler = if ($env:VIOLA_HOST_CC) { $env:VIOLA_HOST_CC } else { 'clang' }
	$verifier = Join-Path $script:OutDir 'viola-host.exe'
	$shared = Join-Path $script:RepoRoot 'shared/viola'
	$compileArguments = @('-std=c11', '-O2', '-D_CRT_SECURE_NO_WARNINGS', "-I$shared", "-I$script:ViolaContext",
		(Join-Path $script:RepoRoot 'userspace/viola/host_verify.c'),
		(Join-Path $shared 'viola.c'), (Join-Path $shared 'vendor/monocypher.c'),
		(Join-Path $shared 'vendor/monocypher-ed25519.c'), '-o', $verifier)
	Invoke-Native -FilePath $compiler -ArgumentList $compileArguments | Out-Host
	return $verifier
}

function Build-Userspace {
	Write-Host '>>> [2/4] Build payloads/daemon/client ...' -ForegroundColor Cyan
	$buildDirArm64 = Join-Path $script:RepoRoot 'build-win-arm64'
	$buildDirArmv7 = Join-Path $script:RepoRoot 'build-win-armv7'

	Build-CMakeProject -Name 'YukiZygisk payload + daemon + yzctl (arm64)' -SourceDirectory $script:RepoRoot -BuildDirectory $buildDirArm64 -Abi $script:Abi -Platform 31
	Build-CMakeProject -Name 'YukiZygisk payload + daemon (armv7)' -SourceDirectory $script:RepoRoot -BuildDirectory $buildDirArmv7 -Abi 'armeabi-v7a' -Platform 31

	New-Item -ItemType Directory -Path $script:OutDir -Force | Out-Null
	Copy-RequiredFile -Source (Join-Path $buildDirArm64 'userspace/viola/viola') -Destination (Join-Path $script:OutDir 'viola')
	Copy-RequiredFile -Source (Join-Path $buildDirArm64 'userspace/zygisk/core/libzygisk64.so') -Destination (Join-Path $script:OutDir 'libzygisk64.so')
	Copy-RequiredFile -Source (Join-Path $buildDirArm64 'userspace/zygisk/core/libyukilinker64.so') -Destination (Join-Path $script:OutDir 'libyukilinker64.so')
	Copy-RequiredFile -Source (Join-Path $buildDirArm64 'userspace/zygisk/core/libyukizncore64.so') -Destination (Join-Path $script:OutDir 'libyukizncore64.so')
	Copy-RequiredFile -Source (Join-Path $buildDirArm64 'userspace/zygisk/daemon/zygiskd64') -Destination (Join-Path $script:OutDir 'zygiskd64')
	Copy-RequiredFile -Source (Join-Path $buildDirArm64 'userspace/yzctl/yzctl') -Destination (Join-Path $script:OutDir 'yzctl')

	Copy-RequiredFile -Source (Join-Path $buildDirArmv7 'userspace/zygisk/core/libzygisk32.so') -Destination (Join-Path $script:OutDir 'libzygisk32.so')
	Copy-RequiredFile -Source (Join-Path $buildDirArmv7 'userspace/zygisk/core/libyukilinker32.so') -Destination (Join-Path $script:OutDir 'libyukilinker32.so')
	Copy-RequiredFile -Source (Join-Path $buildDirArmv7 'userspace/zygisk/core/libyukizncore32.so') -Destination (Join-Path $script:OutDir 'libyukizncore32.so')
	Copy-RequiredFile -Source (Join-Path $buildDirArmv7 'userspace/zygisk/daemon/zygiskd32') -Destination (Join-Path $script:OutDir 'zygiskd32')

	Strip-AndroidFile -FilePath (Join-Path $script:OutDir 'viola')
	Strip-AndroidFile -FilePath (Join-Path $script:OutDir 'libzygisk64.so')
	Strip-AndroidFile -FilePath (Join-Path $script:OutDir 'libyukilinker64.so')
	Strip-AndroidFile -FilePath (Join-Path $script:OutDir 'libyukizncore64.so')
	Strip-AndroidFile -FilePath (Join-Path $script:OutDir 'libzygisk32.so')
	Strip-AndroidFile -FilePath (Join-Path $script:OutDir 'libyukilinker32.so')
	Strip-AndroidFile -FilePath (Join-Path $script:OutDir 'libyukizncore32.so')
	Strip-AndroidFile -FilePath (Join-Path $script:OutDir 'zygiskd64')
	Strip-AndroidFile -FilePath (Join-Path $script:OutDir 'zygiskd32')
	Strip-AndroidFile -FilePath (Join-Path $script:OutDir 'yzctl')

	return $true
}

function Stage-Module {
	Write-Host '>>> [3/4] Stage module content ...' -ForegroundColor Cyan
	$zipDir = Join-Path $script:RepoRoot 'build\package'
	$moduleTemplate = Join-Path $script:RepoRoot 'module'
	$webuiSource = Join-Path $script:RepoRoot 'webui'
	$kernelOut = Join-Path $script:OutDir "lkm\${script:Kmi}_yukizygisk.ko"

	if (Test-Path -LiteralPath $zipDir) { Remove-Item -LiteralPath $zipDir -Recurse -Force }
	New-Item -ItemType Directory -Path $zipDir | Out-Null

	Copy-Item -Path (Join-Path $moduleTemplate '*') -Destination $zipDir -Recurse
	New-Item -ItemType Directory -Path (Join-Path $zipDir 'webroot') -Force | Out-Null
	Copy-Item -Path (Join-Path $webuiSource '*') -Destination (Join-Path $zipDir 'webroot') -Recurse
	Stamp-ModuleProp -Source (Join-Path $moduleTemplate 'module.prop') -Destination (Join-Path $zipDir 'module.prop')

	Get-ChildItem -Path $zipDir -Recurse -File |
		Where-Object { $_.Extension -ieq '.sh' } |
		ForEach-Object { Normalize-LineEndingsLf -Path $_.FullName }

	$lkmDir = Join-Path $zipDir 'lkm'
	New-Item -ItemType Directory -Path $lkmDir -Force | Out-Null
	Copy-RequiredFile -Source $kernelOut -Destination (Join-Path $lkmDir "$(Split-Path -Leaf $kernelOut)")

	$binDir = Join-Path $zipDir 'bin'
	$lib64Dir = Join-Path $zipDir 'lib64'
	$lib32Dir = Join-Path $zipDir 'lib'
	New-Item -ItemType Directory -Path $binDir, $lib64Dir, $lib32Dir -Force | Out-Null
	Copy-RequiredFile -Source (Join-Path $script:OutDir 'viola') -Destination (Join-Path $binDir 'viola')
	Copy-RequiredFile -Source (Join-Path $script:OutDir 'zygiskd64') -Destination (Join-Path $binDir 'zygiskd64')
	Copy-RequiredFile -Source (Join-Path $script:OutDir 'zygiskd32') -Destination (Join-Path $binDir 'zygiskd32')
	Copy-RequiredFile -Source (Join-Path $script:OutDir 'yzctl') -Destination (Join-Path $binDir 'yzctl')
	Copy-RequiredFile -Source (Join-Path $script:OutDir 'libzygisk64.so') -Destination (Join-Path $lib64Dir 'libzygisk.so')
	Copy-RequiredFile -Source (Join-Path $script:OutDir 'libyukilinker64.so') -Destination (Join-Path $lib64Dir 'libyukilinker.so')
	Copy-RequiredFile -Source (Join-Path $script:OutDir 'libyukizncore64.so') -Destination (Join-Path $lib64Dir 'libyukizncore.so')
	Copy-RequiredFile -Source (Join-Path $script:OutDir 'libzygisk32.so') -Destination (Join-Path $lib32Dir 'libzygisk.so')
	Copy-RequiredFile -Source (Join-Path $script:OutDir 'libyukilinker32.so') -Destination (Join-Path $lib32Dir 'libyukilinker.so')
	Copy-RequiredFile -Source (Join-Path $script:OutDir 'libyukizncore32.so') -Destination (Join-Path $lib32Dir 'libyukizncore.so')

	# Legal texts remain in the source repository.  Keep generated module
	# artifacts lean by excluding standalone license/notice files everywhere,
	# including vendored WebUI assets.
	Get-ChildItem -LiteralPath $zipDir -Recurse -File |
		Where-Object { $_.Name -match '^(?i:license|notice|copying)' } |
		Remove-Item -Force
	return $zipDir
}

function Compress-ModulePackage {
	param([string]$PackageDir)
	$zipName = "YukiZygisk-$($script:VersionName)-$($script:Kmi)-$($script:Abi).zip"
	$zipPath = Join-Path $script:OutDir $zipName

	$tarCommand = Ensure-Command 'tar'
	if (-not $tarCommand) {
		throw 'tar is required to create module package on Windows'
	}

	$previousLocation = Get-Location
	Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue
	try {
		Set-Location -LiteralPath $PackageDir
		& $tarCommand -a -cf $zipPath *
		if ($LASTEXITCODE -ne 0) {
			throw "tar failed with exit code $LASTEXITCODE"
		}
	}
	finally {
		Set-Location -LiteralPath $previousLocation
	}
	return $zipPath
}

function Install-Module {
	param([string]$ZipPath)
	$adbCommand = Ensure-Command 'adb'
	if (-not $adbCommand) {
		throw 'adb is required for install mode. Add platform-tools/adb to PATH.'
	}

	$serialArgs = @()
	if ($script:AdbSerial) {
		$serialArgs += @('-s', $script:AdbSerial)
	}

	$remotePath = "/data/local/tmp/$(Split-Path -Leaf $ZipPath)"
	$pushArgs = @()
	$pushArgs += $serialArgs
	$pushArgs += @('push', $ZipPath, $remotePath)
	Invoke-Native -FilePath $adbCommand -ArgumentList $pushArgs

	$installArgs = @()
	$installArgs += $serialArgs
	$installArgs += @('shell', 'ksud', 'module', 'install', $remotePath)
	Invoke-Native -FilePath $adbCommand -ArgumentList $installArgs
}

try {
	$script:RepoRoot = [IO.Path]::GetFullPath($PSScriptRoot)
	$script:Kmi = (Get-Content -LiteralPath (Join-Path $script:RepoRoot '.ddk-version') -ErrorAction SilentlyContinue | Select-Object -First 1)
	if (-not $script:Kmi) { $script:Kmi = 'android16-6.12' }
	$script:Abi = 'arm64-v8a'
	$script:CleanBuild = $false
	$script:SkipLkm = $false
	$script:InstallPackage = $false
	$script:StripAndroid = $true
	$script:AdbSerial = $null
	$script:ViolaProfile = if ($env:VIOLA_PROFILE) { $env:VIOLA_PROFILE } else { 'official' }
	$script:ViolaKey = $env:VIOLA_KEY
	$script:ViolaPublicKey = $env:VIOLA_PUBLIC_KEY
	$script:ViolaPython = if ($env:VIOLA_PYTHON) { $env:VIOLA_PYTHON } else { 'python' }
	$script:ViolaContext = Join-Path $script:RepoRoot 'build/viola'


	for ($index = 0; $index -lt $args.Count; $index++) {
		$argument = [string]$args[$index]
		switch ($argument.ToLowerInvariant()) {
			{ $_ -in @('-k', '--kmi') } {
				if ($index + 1 -ge $args.Count) { throw "$argument requires value" }
				$index++
				$script:Kmi = [string]$args[$index]
				break
			}
			{ $_ -in @('--viola-profile', '--viola-key', '--viola-public-key') } {
				if ($index + 1 -ge $args.Count) { throw "$argument requires value" }
				$index++
				switch ($argument) {
					'--viola-profile' { $script:ViolaProfile = [string]$args[$index] }
					'--viola-key' { $script:ViolaKey = [string]$args[$index] }
					'--viola-public-key' { $script:ViolaPublicKey = [string]$args[$index] }
				}
				break
			}
			'--clean'  { $script:CleanBuild = $true; break }
			'--skip-lkm' { $script:SkipLkm = $true; break }
			{ $_ -in @('-i', '--install') } { $script:InstallPackage = $true; break }
			'--serial' {
				if ($index + 1 -ge $args.Count) { throw "$argument requires value" }
				$index++
				$script:AdbSerial = [string]$args[$index]
				break
			}
			'--no-strip' { $script:StripAndroid = $false; break }
			{ $_ -in @('-h', '--help') } { Show-Usage; exit 0 }
			default { throw "Unknown option: $argument" }
		}
	}

	if (-not ($script:Kmi -match '^[A-Za-z0-9.-]+$')) {
		throw "Invalid KMI: $($script:Kmi)"
	}

	$kmiNames = @('android12-5.10','android13-5.10','android13-5.15','android14-5.15','android14-6.1','android15-6.6','android16-6.12')
	$script:KmiId = [Array]::IndexOf($kmiNames, $script:Kmi) + 1
	if ($script:KmiId -le 0) { throw "Unsupported KMI: $script:Kmi" }

	$script:SdkRoot = Resolve-AndroidSdk
	$script:NdkRoot = Resolve-Ndk
	$tools = Resolve-BuildTools
	$script:CMakeExe = $tools.CMake
	$script:NinjaExe = $tools.Ninja
	$script:LlvmStrip = $tools.LLVMStrip
	$script:NdkToolchainFile = Join-Path $script:NdkRoot 'build\cmake\android.toolchain.cmake'
	$script:BuildJobs = if ($env:NUMBER_OF_PROCESSORS -match '^\d+$') { [int]$env:NUMBER_OF_PROCESSORS } else { 8 }
	$script:OutDir = Join-Path $script:RepoRoot 'build\out'
	New-Item -ItemType Directory -Path $script:OutDir -Force | Out-Null

	Write-Host '=== YukiZygisk native Windows build ===' -ForegroundColor Green
	Write-Host "KMI:        $($script:Kmi)"
	Write-Host "ABI:        $($script:Abi)"
	Write-Host "SDK:        $($script:SdkRoot)"
	Write-Host "NDK:        $($script:NdkRoot)"
	Write-Host "CMake:      $($script:CMakeExe)"
	Write-Host "Ninja:      $($script:NinjaExe)"
	Write-Host "Strip:      $(if ($script:StripAndroid) { 'enabled' } else { 'disabled' })"
	Write-Host "LKM:        $(if ($script:SkipLkm) { 'reuse existing' } else { 'build' })"
	Write-Host "Install:    $(if ($script:InstallPackage) { 'on' } else { 'off' })"
	Write-Host ''

	if ($script:CleanBuild) {
		Reset-BuildDirectory -Path (Join-Path $script:RepoRoot 'build-win-arm64')
		Reset-BuildDirectory -Path (Join-Path $script:RepoRoot 'build-win-armv7')
	}

	Get-ComputeVersion
	if ($script:ViolaProfile -eq 'dev') { $script:VersionName += '-dev' }
	Prepare-Viola
	Build-Userspace
	Invoke-ViolaTool -Arguments @('loader', '--context', $script:ViolaContext, '--image', (Join-Path $script:OutDir 'viola'))
	$kmiKo = Build-KernelLkm
	$hostVerifier = Build-ViolaHost
	$packageDir = Stage-Module
	Invoke-ViolaTool -Arguments @('sign', '--context', $script:ViolaContext, '--module-dir', $packageDir, '--verifier', $hostVerifier)
	Invoke-Native -FilePath $script:ViolaPython -ArgumentList @((Join-Path $script:RepoRoot 'tools/module_checksums.py'), $packageDir)
	$zipPath = Compress-ModulePackage -PackageDir $packageDir

	Get-Item -LiteralPath $zipPath | Format-List FullName,Length

	if ($script:InstallPackage) {
		Install-Module -ZipPath $zipPath
	}
	else {
		Write-Host "Package: $zipPath"
		Write-Host "Install: .\build.ps1 -k $($script:Kmi) --install"
		Write-Host "or adb push+ksud module install manually."
	}
}
catch {
	Write-Host "BUILD FAILED: $($_.Exception.Message)" -ForegroundColor Red
	Write-Host "At line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line)" -ForegroundColor Red
	exit 1
}
