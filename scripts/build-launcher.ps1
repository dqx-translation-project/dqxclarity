param(
    [switch] $SkipNative,
    [switch] $NoRestore,
    [ValidateSet("Debug", "Release")]
    [string] $Configuration = "Release"
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$LauncherDir = Join-Path $RepoRoot "launcher"
$Project = Join-Path $LauncherDir "DqxClarity.Launcher.csproj"

if (-not (Test-Path $Project)) {
    throw "Launcher project not found: $Project"
}

if (-not $SkipNative) {
    $NativeBuild = Join-Path $LauncherDir "native\build.ps1"
    if (Test-Path $NativeBuild) {
        Write-Host "Building native LocaleHook.dll..."
        try {
            & pwsh -ExecutionPolicy Bypass -File $NativeBuild
        }
        catch {
            Write-Warning "Native build failed. Re-run with -SkipNative for UI-only work, or install CMake + Visual Studio Build Tools C++ workload."
            throw
        }
    }
}
else {
    Write-Host "Skipping native LocaleHook.dll build."
}

Write-Host "Publishing launcher..."
$publishArgs = @(
    "publish",
    $Project,
    "-c", $Configuration,
    "-r", "win-x64",
    "--self-contained", "false",
    "-p:PublishSingleFile=true"
)
if ($NoRestore) {
    $publishArgs += "--no-restore"
}

dotnet @publishArgs
if ($LASTEXITCODE -ne 0) {
    throw "dotnet publish failed with exit code $LASTEXITCODE"
}

$Exe = Join-Path $LauncherDir "bin\$Configuration\net9.0-windows\win-x64\publish\dqxclarity.exe"
if (-not (Test-Path $Exe)) {
    throw "Publish completed but exe was not found: $Exe"
}

Write-Host ""
Write-Host "Done:"
Write-Host $Exe
