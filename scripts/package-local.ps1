param(
    [switch] $NoBuild,
    [switch] $SkipNative,
    [switch] $SkipWanakana
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$OutRoot = Join-Path $RepoRoot "local-build"
$PackageDir = Join-Path $OutRoot "dqxclarity"
$ZipPath = Join-Path $OutRoot "dqxclarity-mod.zip"
$Exe = Join-Path $RepoRoot "DqxClarity\bin\Release\net9.0-windows\win-x64\publish\dqxclarity.exe"

if (-not $NoBuild) {
    $BuildScript = Join-Path $PSScriptRoot "build-launcher.ps1"
    $buildArgs = @{}
    if ($SkipNative) { $buildArgs["SkipNative"] = $true }
    if ($SkipWanakana) { $buildArgs["SkipWanakana"] = $true }
    & $BuildScript @buildArgs
}

if (-not (Test-Path $Exe)) {
    throw "dqxclarity.exe not found. Run scripts\build-launcher.ps1 first."
}

if (Test-Path $PackageDir) {
    $resolvedPackage = (Resolve-Path $PackageDir).Path
    $resolvedOut = if (Test-Path $OutRoot) { (Resolve-Path $OutRoot).Path } else { $OutRoot }
    if (-not $resolvedPackage.StartsWith($resolvedOut, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to clean unexpected path: $resolvedPackage"
    }
    Remove-Item -LiteralPath $PackageDir -Recurse -Force
}

# Same layout the release workflow zips: dqxclarity/{dqxclarity.exe, version.update, misc_files/clarity_dialog.db}.
# user_settings.ini is created by the app on first run, so it is not packaged.
New-Item -ItemType Directory -Force -Path $PackageDir | Out-Null

Copy-Item -LiteralPath $Exe -Destination (Join-Path $PackageDir "dqxclarity.exe") -Force
Copy-Item -LiteralPath (Join-Path $RepoRoot "version.update") -Destination $PackageDir -Force

$MiscDir = Join-Path $PackageDir "misc_files"
New-Item -ItemType Directory -Force -Path $MiscDir | Out-Null
Copy-Item -LiteralPath (Join-Path $RepoRoot "clarity_dialog.db") -Destination $MiscDir -Force

if (Test-Path $ZipPath) {
    Remove-Item -LiteralPath $ZipPath -Force
}
Compress-Archive -LiteralPath $PackageDir -DestinationPath $ZipPath -Force

Write-Host ""
Write-Host "Package folder:"
Write-Host $PackageDir
Write-Host "Zip:"
Write-Host $ZipPath
