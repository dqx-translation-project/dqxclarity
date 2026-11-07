<#
.SYNOPSIS
    Builds wanakana.dll (x86_64) from the rust crate in this directory.
    Output lands in native/ alongside LocaleHook.dll + ClarityHook.dll.

.NOTES
    Requires rustup with the x86_64-pc-windows-msvc target:
        rustup target add x86_64-pc-windows-msvc
    The launcher is x64; this dll runs in the launcher process (NOT injected
    into the 32-bit game), so x86_64 is what we want.
#>

$ErrorActionPreference = "Stop"
$crateDir = $PSScriptRoot
$nativeDir = Split-Path -Parent $crateDir

$cargo = (Get-Command cargo -ErrorAction SilentlyContinue)
if (-not $cargo) {
    Write-Error @"
cargo not found. Install rustup from https://rustup.rs/ and then run:
    rustup target add x86_64-pc-windows-msvc
"@
    exit 1
}

Push-Location $crateDir
try {
    & cargo build --release --target x86_64-pc-windows-msvc
    if ($LASTEXITCODE -ne 0) {
        Write-Error "cargo build failed."
        exit 1
    }
}
finally {
    Pop-Location
}

$built = Join-Path $crateDir "target/x86_64-pc-windows-msvc/release/wanakana.dll"
if (-not (Test-Path $built)) {
    Write-Error "Expected output not found at $built"
    exit 1
}

Copy-Item -Force $built (Join-Path $nativeDir "wanakana.dll")
Write-Host "Built $nativeDir\wanakana.dll"
