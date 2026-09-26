<#
.SYNOPSIS
    Builds LocaleHook.dll and PacketWarden.dll (x86) using CMake + MSVC.
    Run from anywhere; outputs land in launcher/native/.

.NOTES
    Requires Visual Studio Build Tools with the "Desktop development with C++"
    workload (any of 2017, 2019, 2022).  MinGW is not supported because the
    -m32 multilib is rarely installed on Windows.
#>

$ErrorActionPreference = "Stop"
$nativeDir = $PSScriptRoot
$buildDir  = Join-Path $nativeDir "build"

# Locate cmake.exe — prefer the one bundled with VS, fall back to PATH
function Find-Cmake {
    $inPath = Get-Command cmake -ErrorAction SilentlyContinue
    if ($inPath) { return $inPath.Source }

    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $vsPath = & $vswhere -latest -property installationPath
        $candidate = Join-Path $vsPath "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
        if (Test-Path $candidate) { return $candidate }
    }
    return $null
}

$cmake = Find-Cmake
if (-not $cmake) {
    Write-Error @"
cmake.exe not found. Either install it from https://cmake.org/download/ and add
to PATH, or install VS Build Tools with the "Desktop development with C++" workload.
"@
    exit 1
}
Write-Host "Using cmake: $cmake"

$vsGenerators = @(
    "Visual Studio 17 2022",
    "Visual Studio 16 2019",
    "Visual Studio 15 2017"
)

# CMake caches which generator configured a build directory and refuses to
# reconfigure it with a different one ("Does not match the generator used
# previously..."). Since the loop below can try up to three different
# generators against this same $buildDir, a stale cache from an earlier run
# -- or a stale cache left behind by an earlier generator attempt within
# THIS SAME run -- would make a later attempt fail with that mismatch error
# instead of the real reason. So we clean $buildDir both once up front (in
# case a previous run left it in a bad state) AND again before each
# individual generator attempt inside the loop below (in case an earlier
# attempt in this same run got far enough to write a cache before failing).
if (Test-Path $buildDir) {
    Write-Host "Removing stale build directory: $buildDir"
    Remove-Item -Recurse -Force $buildDir
}

$configured  = $false
$lastOutput  = $null

# Try CMake's own default-generator auto-detection first. This picks
# whichever installed Visual Studio toolset CMake considers newest/usable
# without us having to name it explicitly -- which matters because the
# hardcoded $vsGenerators list below only knows about specific VS
# 2017/2019/2022 name strings. A newer VS major version (e.g. VS 18 /
# "Build Tools 2026") has no matching entry in that list at all, so without
# this auto-detect attempt the script could never pick it up even when it's
# the only correctly-configured install on the machine. Falling through to
# the named-generator loop below is still kept as a fallback for setups
# where auto-detect picks something unexpected.
Write-Host "Trying CMake's default generator (auto-detected)..."
if (Test-Path $buildDir) {
    Remove-Item -Recurse -Force $buildDir
}
$prevEap = $ErrorActionPreference
$ErrorActionPreference = "Continue"
$lastOutput = & $cmake -A Win32 -S $nativeDir -B $buildDir 2>&1
$ErrorActionPreference = $prevEap
if ($LASTEXITCODE -eq 0) {
    Write-Host "Configured with CMake's default generator"
    $configured = $true
} else {
    Write-Host "Default generator attempt failed:"
    $lastOutput | ForEach-Object { Write-Host "  $_" }
    Write-Host ""
}

if (-not $configured) {
    foreach ($gen in $vsGenerators) {
        Write-Host "Trying generator: $gen"
        # Belt-and-suspenders: also clean immediately before this specific
        # attempt, so a cache written by the PREVIOUS generator in this same
        # loop (e.g. a partially-successful 2022 attempt) can never cause a
        # "Does not match the generator used previously" error on this one.
        if (Test-Path $buildDir) {
            Remove-Item -Recurse -Force $buildDir
        }
        # Run with ErrorActionPreference=Continue for just this call -- with
        # the script-wide "Stop" setting, a non-zero-exit native command's
        # stderr lines get surfaced as a terminating NativeCommandError,
        # which aborts the whole script on the FIRST generator attempt
        # instead of falling through to try the next one (and hides the
        # real CMake error behind "Out-Null" in the process). Capturing
        # output into a variable instead lets us both keep trying
        # generators AND print each one's real failure reason as it happens
        # -- not just whichever attempt happens to run last.
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $lastOutput = & $cmake -G $gen -A Win32 -S $nativeDir -B $buildDir 2>&1
        $ErrorActionPreference = $prevEap
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Configured with: $gen"
            $configured = $true
            break
        } else {
            Write-Host "  $gen failed:"
            $lastOutput | ForEach-Object { Write-Host "    $_" }
            Write-Host ""
        }
    }
}

if (-not $configured) {
    Write-Error @"
No usable Visual Studio installation/toolset found by CMake -- see the
per-attempt output above for the exact reason from each one. Common causes:
  - Visual Studio is installed but without the "Desktop development with
    C++" workload's x86 build tools.
  - The C++ workload is installed on a DIFFERENT Visual Studio instance
    than the one CMake is looking at (if you have more than one VS
    install -- e.g. a newer Build Tools install alongside an older
    Community/Professional/Enterprise one -- CMake needs the workload on
    whichever instance it actually picks, not just on one of them).
Install/repair via the Visual Studio Installer: https://visualstudio.microsoft.com/downloads/
and make sure the "Desktop development with C++" workload is checked, including
the MSVC x86/x64 build tools component, on the instance you intend to build with
(this project targets Win32/x86).
"@
    exit 1
}

& $cmake --build $buildDir --config Release
if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed."
    exit 1
}

Write-Host ""
Write-Host "Done. Outputs copied to: $nativeDir"
Write-Host "  LocaleHook.dll"
Write-Host "  PacketWarden.dll"
