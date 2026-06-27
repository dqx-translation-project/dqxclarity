param(
    [switch] $NoBuild,
    [switch] $SkipNative
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$OutRoot = Join-Path $RepoRoot "local-build"
$PackageDir = Join-Path $OutRoot "dqxclarity"
$ZipPath = Join-Path $OutRoot "dqxclarity-mod.zip"
$LauncherExe = Join-Path $RepoRoot "launcher\bin\Release\net9.0-windows\win-x64\publish\dqxclarity.exe"

if (-not $NoBuild) {
    $BuildScript = Join-Path $PSScriptRoot "build-launcher.ps1"
    if ($SkipNative) {
        & $BuildScript -SkipNative
    }
    else {
        & $BuildScript
    }
}

if (-not (Test-Path $LauncherExe)) {
    throw "Launcher exe not found. Run local-tools\build-launcher.ps1 first."
}

if (Test-Path $PackageDir) {
    $resolvedPackage = (Resolve-Path $PackageDir).Path
    $resolvedOut = if (Test-Path $OutRoot) { (Resolve-Path $OutRoot).Path } else { $OutRoot }
    if (-not $resolvedPackage.StartsWith($resolvedOut, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to clean unexpected path: $resolvedPackage"
    }
    Remove-Item -LiteralPath $PackageDir -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $PackageDir | Out-Null

$AppDir = Join-Path $RepoRoot "app"
Get-ChildItem -LiteralPath $AppDir -Force | Where-Object {
    $_.Name -notin @("tests", "__pycache__")
} | ForEach-Object {
    Copy-Item -LiteralPath $_.FullName -Destination $PackageDir -Recurse -Force
}

foreach ($file in @("version.update", "pyproject.toml", "user_settings.ini")) {
    Copy-Item -LiteralPath (Join-Path $RepoRoot $file) -Destination $PackageDir -Force
}

Copy-Item -LiteralPath $LauncherExe -Destination (Join-Path $PackageDir "dqxclarity.exe") -Force

$MiscDir = Join-Path $PackageDir "misc_files"
New-Item -ItemType Directory -Force -Path $MiscDir | Out-Null
Copy-Item -LiteralPath (Join-Path $RepoRoot "clarity_dialog.db") -Destination $MiscDir -Force

$PackageModsDir = Join-Path $PackageDir "mods"
New-Item -ItemType Directory -Force -Path $PackageModsDir | Out-Null

$SourceModsDir = Join-Path $RepoRoot "mods"
$copiedSourceMods = $false
if (Test-Path $SourceModsDir) {
    Get-ChildItem -LiteralPath $SourceModsDir -Filter "*.zip" -File | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination $PackageModsDir -Force
        $copiedSourceMods = $true
    }
}

$BundledModsDir = Join-Path (Split-Path -Parent $LauncherExe) "mods"
if (-not $copiedSourceMods -and (Test-Path $BundledModsDir)) {
    Get-ChildItem -LiteralPath $BundledModsDir -Filter "*.zip" -File | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination $PackageModsDir -Force
    }
}

if (Test-Path $ZipPath) {
    Remove-Item -LiteralPath $ZipPath -Force
}
Compress-Archive -LiteralPath $PackageDir -DestinationPath $ZipPath -Force

Write-Host ""
Write-Host "Package folder:"
Write-Host $PackageDir
Write-Host "Zip:"
Write-Host $ZipPath
