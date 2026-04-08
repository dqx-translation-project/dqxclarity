# ensure we're in the appropriate working directory in case it's overwritten
# by the user's profile.
Set-Location (Split-Path $MyInvocation.MyCommand.Path)

$PythonVersion   = "3.11.3"
$PythonArch      = "32"
$PythonInstaller = "python-$PythonVersion.exe"
$PythonUrl       = "https://www.python.org/ftp/python/$PythonVersion/$PythonInstaller"
$PythonMD5Hash   = "691232496E346CE0860AEF052DD6844F"  # pragma: allowlist secret
$PythonRegKey    = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Python\PythonCore\3.11-$PythonArch\InstallPath"

function LogWrite($string) {
    Write-Host $string -ForegroundColor "Yellow"
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

function DownloadPythonInstaller() {
    $ProgressPreference = "SilentlyContinue"  # workaround to faster download speeds using IWR
    LogWrite "Downloading Python executable from the internet."
    Invoke-WebRequest -Uri $PythonUrl -OutFile $PythonInstaller

    $FileHash = Get-FileHash .\$PythonInstaller -Algorithm MD5
    if ($FileHash.Hash -ne $PythonMD5Hash) {
        LogWrite "File download did not complete successfully. Please re-run this script and try again. $HelpMessage"
        RemoveFile $PythonInstaller
        PromptForInputAndExit
    }
}

function InstallPython() {
    LogWrite "Launching Python 3.11 installer and installing Python for you. Please wait."
    .\$PythonInstaller /passive InstallAllUsers=1 PrependPath=1 Include_doc=0 Include_tcltk=1 Include_test=0 Shortcuts=0 SimpleInstallDescription="Installing necessary components for dqxclarity." | Out-Null
    $PythonInstallPath = PythonExePath

    if (!$PythonInstallPath) {
        LogWrite "Failed to install Python. Please try again. $HelpMessage"
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

$ErrorActionPreference = "SilentlyContinue"
Stop-Transcript | Out-Null
$ErrorActionPreference = "Continue"
New-Item -ItemType Directory -Force -Path logs/ | Out-Null
Start-Transcript -path logs/startup.log

$HelpMessage = "If you need help, please join the DQX Discord and post your question in the #clarity-questions channel. https://discord.gg/dragonquestx"
$Shell = New-Object -comobject "WScript.Shell"

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

# check if the user already has a virtual environment folder
if (-not (Test-Path -Path "venv")) {
    LogWrite "Creating virtual environment."
    $CreateVenvOutput = & $PythonInstallPath -m venv venv 2>&1
    if ($? -eq $False) {
        LogWrite $CreateVenvOutput
        if ($CreateVenvOutput -match "'--default-pip']' returned non-zero exit status 1.") {
            LogWrite "It's highly likely that your antivirus is blocking Python from executing. You will need to add a folder exclusion to your anti-virus to exclude 'C:\Program Files (x86)\Python311-32' and '$PSScriptRoot'. Restart dqxclarity once these exclusions have been added."
        }
        else {
            LogWrite "An error occurred during virtual environment initialization. Please try again. $HelpMessage"
        }
        RemoveFile "venv"
        PromptForInputAndExit
    }
}

$RequirementsHash = (Get-FileHash .\requirements.txt -Algorithm MD5).Hash
$HashFile = ".\venv\.requirements_hash"
$StoredHash = if (Test-Path $HashFile) { Get-Content $HashFile } else { "" }

if ($RequirementsHash -ne $StoredHash) {
    LogWrite "Installing dqxclarity dependencies. This may take a few minutes on first run or after an update."
    & .\venv\Scripts\pip.exe install --disable-pip-version-check -r requirements.txt --quiet --use-pep517
    if ($? -eq $False) {
        LogWrite "An error occurred during dependency installation. Please try again. $HelpMessage"
        RemoveFile "venv"
        PromptForInputAndExit
    }

    # verify dependencies installed correctly by attempting to import something that was installed.
    & .\venv\Scripts\python.exe -c "import pykakasi" 2> $null
    if ($? -eq $False) {
        LogWrite "An error occurred while verifying dependency installation. Please try again. $HelpMessage"
        RemoveFile "venv"
        PromptForInputAndExit
    }

    Set-Content $HashFile $RequirementsHash
}

LogWrite "Python install location: $PythonInstallPath"
LogWrite "Clarity installation path: $PSScriptRoot"
LogWrite "Clarity args: $args"

LogWrite "Running dqxclarity."
& .\venv\Scripts\python.exe -m main @args
