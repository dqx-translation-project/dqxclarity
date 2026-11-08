param(
    [switch] $SkipNative,
    [switch] $SkipWanakana,
    [switch] $NoRestore,
    [ValidateSet("Debug", "Release")]
    [string] $Configuration = "Release"
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$AppDir = Join-Path $RepoRoot "DqxClarity"
$Project = Join-Path $AppDir "DqxClarity.csproj"

if (-not (Test-Path $Project)) {
    throw "Project not found: $Project"
}

if (-not $SkipNative) {
    $NativeBuild = Join-Path $AppDir "native\build.ps1"
    Write-Host "Building native LocaleHook.dll + PacketWarden.dll..."
    try {
        & pwsh -ExecutionPolicy Bypass -File $NativeBuild
        if ($LASTEXITCODE -ne 0) { throw "native build exited with code $LASTEXITCODE" }
    }
    catch {
        Write-Warning "Native build failed. Re-run with -SkipNative for UI-only work, or install CMake + Visual Studio Build Tools C++ workload."
        throw
    }
}
else {
    Write-Host "Skipping native LocaleHook.dll / PacketWarden.dll build."
}

if (-not $SkipWanakana) {
    $WanakanaBuild = Join-Path $AppDir "native\wanakana\build.ps1"
    Write-Host "Building wanakana.dll (needs Rust: rustup target add x86_64-pc-windows-msvc)..."
    try {
        & pwsh -ExecutionPolicy Bypass -File $WanakanaBuild
        if ($LASTEXITCODE -ne 0) { throw "wanakana build exited with code $LASTEXITCODE" }
    }
    catch {
        Write-Warning "wanakana build failed. Re-run with -SkipWanakana to build without romaji support (names will not be romanized)."
        throw
    }
}
else {
    Write-Host "Skipping wanakana.dll build."
}

Write-Host "Publishing..."
$publishArgs = @(
    "publish",
    $Project,
    "-c", $Configuration,
    "-r", "win-x64",
    "--self-contained", "true",
    "-p:PublishSingleFile=true"
)
if ($NoRestore) {
    $publishArgs += "--no-restore"
}

dotnet @publishArgs
if ($LASTEXITCODE -ne 0) {
    throw "dotnet publish failed with exit code $LASTEXITCODE"
}

$Exe = Join-Path $AppDir "bin\$Configuration\net9.0-windows\win-x64\publish\dqxclarity.exe"
if (-not (Test-Path $Exe)) {
    throw "Publish completed but exe was not found: $Exe"
}

Write-Host ""
Write-Host "Done:"
Write-Host $Exe
