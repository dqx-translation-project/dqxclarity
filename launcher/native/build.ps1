<#
.SYNOPSIS
    Builds LocaleHook.dll (x86) using CMake + MSVC.
    Run from anywhere; output lands in launcher/native/.

.NOTES
    Requires Visual Studio Build Tools with the "Desktop development with C++"
    workload (any of 2017, 2019, 2022, 2026).  MinGW is not supported because the
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
    "Visual Studio 18 2026",
    "Visual Studio 17 2022",
    "Visual Studio 16 2019",
    "Visual Studio 15 2017"
)

$configured = $false
foreach ($gen in $vsGenerators) {
    Write-Host "Trying generator: $gen"
    & $cmake -G $gen -A Win32 -S $nativeDir -B $buildDir 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Configured with: $gen"
        $configured = $true
        break
    }
}

if (-not $configured) {
    Write-Error @"
No supported Visual Studio installation found.
Install VS Build Tools from https://visualstudio.microsoft.com/downloads/
and select the "Desktop development with C++" workload.
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
