# ensure we're in the appropriate working directory in case it's overwritten
# by the user's profile.
Set-Location (Split-Path $MyInvocation.MyCommand.Path)

$PythonVersion   = "3.11.3"
$PythonArch      = "32"
$PythonInstaller = "python-$PythonVersion.exe"
$PythonUrl       = "https://www.python.org/ftp/python/$PythonVersion/$PythonInstaller"
$PythonMD5Hash   = "691232496E346CE0860AEF052DD6844F"  # pragma: allowlist secret
$PythonRegKey    = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Python\PythonCore\3.11-$PythonArch\InstallPath"
$HelpMessage     = "If you need help, please join the DQX Discord and post your question in the #clarity-questions channel. https://discord.gg/dragonquestx"

function LogWrite($string) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    Write-Host "$timestamp | $("{0,-8}" -f "INFO") | $string" -ForegroundColor "White"
}

function LogWarning($string) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    Write-Host "$timestamp | $("{0,-8}" -f "WARNING") | $string" -ForegroundColor "Yellow"
}

function PythonExePath() {
    # Because of the pymem lib, required to install Python for all users.
    # No longer supporting "Install for Me" installations, just "Install for all users"
    $ErrorActionPreference = "SilentlyContinue"
    try { (Get-ItemProperty -Path $PythonRegKey -Name "ExecutablePath").ExecutablePath }
    catch { "" }
    $ErrorActionPreference = "Continue"
}

function RemoveFile($path) {
    if (Test-Path $path) {
        Remove-Item $path -Recurse
    }
}

function PromptForInputAndExit() {
    Read-Host "Press ENTER to close"
    Exit
}

# disables quickedit mode on the console window. quickedit is enabled by default on windows
# consoles and pauses the running process the moment a user clicks anywhere in the window.
# since this script is spawned from dqxclarity.exe, a user clicking the console would silently
# stall the program with no indication of why. disabling it prevents this.
function DisableQuickEdit() {
    $Kernel32 = Add-Type -MemberDefinition @"
        [DllImport("kernel32.dll")] public static extern IntPtr GetStdHandle(int nStdHandle);
        [DllImport("kernel32.dll")] public static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);
        [DllImport("kernel32.dll")] public static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);
"@ -Name Kernel32 -Namespace Win32 -PassThru

    $handle = [Win32.Kernel32]::GetStdHandle(-10)  # STD_INPUT_HANDLE
    $mode = 0
    [Win32.Kernel32]::GetConsoleMode($handle, [ref]$mode) | Out-Null
    $mode = ($mode -band (-bnot 0x0040)) -bor 0x0080  # clear ENABLE_QUICK_EDIT, set ENABLE_EXTENDED_FLAGS
    [Win32.Kernel32]::SetConsoleMode($handle, $mode) | Out-Null
}

function DownloadPythonInstaller() {
    $ProgressPreference = "SilentlyContinue"  # workaround to faster download speeds using IWR
    LogWrite "Downloading Python executable from the internet."
    Invoke-WebRequest -Uri $PythonUrl -OutFile $PythonInstaller

    $FileHash = Get-FileHash .\$PythonInstaller -Algorithm MD5
    if ($FileHash.Hash -ne $PythonMD5Hash) {
        LogWarning "File download did not complete successfully. Please re-run this script and try again. $HelpMessage"
        RemoveFile $PythonInstaller
        PromptForInputAndExit
    }
}

function InstallPython() {
    LogWrite "Launching Python 3.11 installer and installing Python for you. Please wait."
    .\$PythonInstaller /passive InstallAllUsers=1 PrependPath=1 Include_doc=0 Include_tcltk=1 Include_test=0 Shortcuts=0 SimpleInstallDescription="Installing necessary components for dqxclarity." | Out-Null
    $PythonInstallPath = PythonExePath

    if (!$PythonInstallPath) {
        LogWarning "Failed to install Python. Please try again. $HelpMessage"
        PromptForInputAndExit
    }

    RemoveFile $PythonInstaller
}

function FindOrphanedPythonInstall() {
    # Returns true if Python 3.11 32-bit appears to be installed on the system but
    # not in the all-users location that dqxclarity expects (e.g. installed for current
    # user only, or installed via a different method that skips the standard registry key).
    $ErrorActionPreference = "SilentlyContinue"

    $UserRegKey = "Registry::HKEY_CURRENT_USER\SOFTWARE\Python\PythonCore\3.11-32\InstallPath"
    $UserInstall = try { Get-ItemProperty -Path $UserRegKey -ErrorAction SilentlyContinue } catch { $null }
    if ($UserInstall) {
        $ErrorActionPreference = "Continue"
        return $true
    }

    $UninstallRoots = @(
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    foreach ($root in $UninstallRoots) {
        $found = Get-ChildItem $root -ErrorAction SilentlyContinue |
            Get-ItemProperty -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like "Python 3.11*(32-bit)*" }
        if ($found) {
            $ErrorActionPreference = "Continue"
            return $true
        }
    }

    $ErrorActionPreference = "Continue"
    return $false
}

function CheckNotInOneDrive() {
    # OneDrive syncs files in the background and can interfere with dqxclarity's database
    # and venv. check all three env vars OneDrive sets so both personal and business
    # installations are caught. StartsWith with a trailing slash prevents false positives
    # where e.g. "C:\Users\joey\OneDrive" would match "C:\Users\joey\OneDrive - Work".
    $OneDrivePaths = @($env:OneDrive, $env:OneDriveConsumer, $env:OneDriveCommercial) | Where-Object { $_ }
    foreach ($path in $OneDrivePaths) {
        if ($PSScriptRoot.StartsWith($path + "\")) {
            LogWarning "WARNING: dqxclarity is installed inside a OneDrive folder ($PSScriptRoot). This is known to cause issues. Consider moving dqxclarity to a non-OneDrive location."
        }
    }
}

# spins a braille animation until the given background job finishes.
function ShowSpinner($job) {
    $spinner = @([char]0x28FE, [char]0x28FD, [char]0x28FB, [char]0x28BF, [char]0x287F, [char]0x28DF, [char]0x28EF, [char]0x28F7)
    $i = 0
    while ($job.State -eq 'Running') {
        # write directly to the console to keep spinner frames out of the transcript.
        $prev = [Console]::ForegroundColor
        [Console]::ForegroundColor = [ConsoleColor]::Green
        [Console]::Write("`r$($spinner[$i % 8])")
        [Console]::ForegroundColor = $prev
        $i++
        Start-Sleep -Milliseconds 100
    }
    [Console]::Write("`r   `r")
}

function CheckForRunningInstallers() {
    $MsiExecRunning = Get-Process -Name msiexec.exe -ErrorAction SilentlyContinue
    if ($MsiExecRunning) {
        $Message = "We found a running process on your machine that will cause the Python installer to fail (msiexec.exe). This process is generally used when installing/uninstalling software. Are you OK with us stopping the process to continue?"
        LogWrite $Message
        $Result = $Shell.popup($Message, 0, "Question", 4 + 32)

        if ($Result -eq 6) {
            Stop-Process -Name msiexec.exe -ErrorAction SilentlyContinue
        }
        else {
            LogWrite "No problem. You will need to either terminate the process yourself or reboot your computer. Launch dqxclarity again when you're ready."
            PromptForInputAndExit
        }
    }
}

$LockFile = "dqxclarity.lock"

if (Test-Path $LockFile) {
    $OldPid = Get-Content $LockFile -ErrorAction SilentlyContinue
    if ($OldPid) {
        $OldProcess = Get-Process -Id ([int]$OldPid) -ErrorAction SilentlyContinue
        if ($OldProcess) {
            LogWrite "A previous dqxclarity instance was found running. Stopping it."
            taskkill /PID $OldPid /T /F 2>$null | Out-Null
        }
    }
}
Set-Content $LockFile $PID

$ErrorActionPreference = "SilentlyContinue"
Stop-Transcript | Out-Null
$ErrorActionPreference = "Continue"
New-Item -ItemType Directory -Force -Path logs/ | Out-Null
Start-Transcript -path logs/startup.log
DisableQuickEdit
[Console]::CursorVisible = $false

$Shell = New-Object -comobject "WScript.Shell"
CheckNotInOneDrive

$PythonInstallPath = PythonExePath

# install Python if missing
if (!$PythonInstallPath) {
    if (FindOrphanedPythonInstall) {
        $Message = "Python 3.11 32-bit was found on your system, but wasn't installed in a way dqxclarity can use. Please uninstall Python 3.11 32-bit from Settings > Apps, then relaunch dqxclarity."
        LogWrite $Message
        $Shell.popup($Message, 0, "Action Required", 0 + 48) | Out-Null
        PromptForInputAndExit
    }

    LogWrite "Could not find Python installation for Python 3.11-32."

    $Result = $Shell.popup("Could not find Python 3.11 installation. Do you want to install it?", 0, "Question", 4 + 32)

    if ($Result -eq 6) {
        CheckForRunningInstallers
        DownloadPythonInstaller
        InstallPython
        $PythonInstallPath = PythonExePath
    }
    else {
        LogWrite "You selected 'No'. Python 3.11 is required to use dqxclarity. Exiting."
        PromptForInputAndExit
    }
}

# check if the user already has a usable virtual environment.
# checking for the executables (not just the directory) guards against a partial
# delete left behind by the updater when files were locked during rmtree.
if (-not (Test-Path -Path "venv\Scripts\python.exe") -or -not (Test-Path -Path "venv\Scripts\activate")) {
    RemoveFile "venv"
    LogWrite "Creating virtual environment."
    $venvJob = Start-Job -ScriptBlock {
        param($pythonPath, $dir)
        Set-Location $dir
        $output = & $pythonPath -m venv venv 2>&1 | Out-String
        [PSCustomObject]@{ Output = $output; ExitCode = $LASTEXITCODE }
    } -ArgumentList $PythonInstallPath, (Get-Location).Path

    ShowSpinner $venvJob

    $venvResult = Receive-Job $venvJob
    Remove-Job $venvJob

    if ($venvResult.ExitCode -ne 0) {
        LogWarning $venvResult.Output
        if ($venvResult.Output -match "'--default-pip']' returned non-zero exit status 1.") {
            LogWarning "It's highly likely that your antivirus is blocking Python from executing. You will need to add a folder exclusion to your anti-virus to exclude 'C:\Program Files (x86)\Python311-32' and '$PSScriptRoot'. Restart dqxclarity once these exclusions have been added."
        }
        else {
            LogWarning "An error occurred during virtual environment initialization. Please try again. $HelpMessage"
        }
        RemoveFile "venv"
        PromptForInputAndExit
    }
}

$PyprojectHash = (Get-FileHash .\pyproject.toml -Algorithm MD5).Hash
$HashFile = ".\venv\.requirements_hash"
$StoredHash = if (Test-Path $HashFile) { Get-Content $HashFile } else { "" }

if ($PyprojectHash -ne $StoredHash) {
    LogWrite "Installing dqxclarity dependencies. This may take a few minutes on first run or after an update."

    # run pip in a background job so we can animate a spinner while it installs.
    # the job returns $LASTEXITCODE so we can check whether pip succeeded.
    $workingDir = (Get-Location).Path
    $pipJob = Start-Job -ScriptBlock {
        param($dir)
        Set-Location $dir
        & .\venv\Scripts\pip.exe install --disable-pip-version-check . --quiet 2>&1 | Out-Null
        return $LASTEXITCODE
    } -ArgumentList $workingDir

    ShowSpinner $pipJob

    $pipExitCode = Receive-Job $pipJob
    Remove-Job $pipJob

    if ($pipExitCode -ne 0) {
        LogWarning "An error occurred during dependency installation. Please try again. $HelpMessage"
        RemoveFile "venv"
        PromptForInputAndExit
    }

    # verify dependencies installed correctly by attempting to import something that was installed.
    & .\venv\Scripts\python.exe -c "import pykakasi" 2> $null
    if ($? -eq $False) {
        LogWarning "An error occurred while verifying dependency installation. Please try again. $HelpMessage"
        RemoveFile "venv"
        PromptForInputAndExit
    }

    Set-Content $HashFile $PyprojectHash
    LogWrite "Dependencies ready."
}

LogWrite "Python install location: $PythonInstallPath"
LogWrite "Clarity installation path: $PSScriptRoot"
LogWrite "Clarity args: $args"

LogWrite "Running dqxclarity."
# the cryptography package warns when running on 32-bit python, but dqxclarity requires
# 32-bit python due to its dependency on pymem. the warning is expected and not actionable.
& .\venv\Scripts\python.exe -W "ignore:You are using cryptography on a 32-bit Python:UserWarning" -m main @args
RemoveFile $LockFile
