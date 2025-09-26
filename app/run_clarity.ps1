param(
    [Parameter(Mandatory = $false)]
    [string]$LaunchArgs
)

# ensure we're in the appropriate working directory in case it's overwritten
# by the user's profile.
Set-Location (Split-Path $MyInvocation.MyCommand.Path)

function LogWrite($string) {
    Write-Host $string -ForegroundColor "Yellow"
}

function PythonExePath() {
    # Because of the pymem lib, required to install Python for all users.
    # No longer supporting "Install for Me" installations, just "Install for all users"
    $PythonRegKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Python\PythonCore\3.11-32\InstallPath"
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
    Invoke-WebRequest -Uri https://www.python.org/ftp/python/3.11.3/python-3.11.3.exe -OutFile python-3.11.3.exe

    $PythonMD5 = Get-FileHash .\python-3.11.3.exe -Algorithm MD5
    if ($PythonMD5.Hash -ne "691232496E346CE0860AEF052DD6844F") { # pragma: allowlist secret
        LogWrite "File download did not complete successfully. Please re-run this script and try again. $HelpMessage"
        RemoveFile "python-3.11.3.exe"
        Read-Host "Press ENTER to close."
        Exit
    }
}

function InstallPython() {
    LogWrite "Launching Python 3.11 installer and installing Python for you. Please wait."
    .\python-3.11.3.exe /passive InstallAllUsers=1 PrependPath=1 Include_doc=0 Include_tcltk=1 Include_test=0 Shortcuts=0 SimpleInstallDescription="Installing necessary components for dqxclarity." | Out-Null
    $PythonInstallPath = PythonExePath

    if (!$PythonInstallPath) {
        LogWrite "Failed to install Python. Please try again. $HelpMessage"
        Read-Host "Press ENTER to close."
        Exit
    }
}

function UninstallPython() {
    LogWrite "Uninstalling Python."
    .\python-3.11.3.exe /uninstall | Out-Null
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
            Read-Host "Press ENTER to close."
            Exit
        }
    }
}

$ErrorActionPreference = "SilentlyContinue"
Stop-Transcript | Out-Null
$ErrorActionPreference = "Continue"
New-Item -ItemType Directory -Force -Path logs/ | Out-Null
Start-Transcript -path logs/startup.log

$HelpMessage = "If you need help, please join the DQX Discord and post your question in the #clarity-questions channel. https://discord.gg/dragonquestx"

$PythonInstallPath = PythonExePath

# install Python if missing
if (!$PythonInstallPath) {
    LogWrite "Could not find Python installation for Python 3.11-32."

    $Shell = New-Object -comobject "WScript.Shell"
    $Result = $Shell.popup("Could not find Python 3.11 installation. Do you want to install it?", 0, "Question", 4 + 32)

    if ($Result -eq 6) {
        CheckForRunningInstallers
        DownloadPythonInstaller
        InstallPython
        $PythonInstallPath = PythonExePath
    }
    else {
        LogWrite "You selected 'No'. Python 3.11 is required to use dqxclarity. Exiting."
        Read-Host "Press ENTER to close."
        Exit
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

# try to activate the found virtual environment
& .\venv\Scripts\activate
if ($? -eq $False) {
    LogWrite "Could not activate virtual environment. Please try again. $HelpMessage"
    RemoveFile "venv"
    PromptForInputAndExit
}

# install tkinter if it's missing.
# we used to automate installations without tkinter enabled, so we now need to check
# if it's installed. when we upgrade Python versions again, we can remove this block
# and install tkinter by default.
& .\venv\Scripts\python.exe -c "import tkinter" 2> $null
if ($? -eq $False) {
    $Shell = New-Object -comobject "WScript.Shell"
    $Result = $Shell.popup("Python installation must be uninstalled and reinstalled to support a new feature Clarity requires. Install now?", 0, "Question", 4 + 32)
    if ($Result -eq 6) {
        DownloadPythonInstaller
        UninstallPython
        InstallPython
        Write-Host "Clarity must be restarted to use the new changes. Please close Clarity and relaunch."
        RemoveFile "venv"
        PromptForInputAndExit
    }
    else {
        LogWrite "You selected 'No'. Clarity will not function correctly without this installation. Exiting."
        PromptForInputAndExit
    }
}

LogWrite "Installing dqxclarity dependencies."
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

LogWrite "Python install location: $PythonInstallPath"
LogWrite "Clarity installation path: $PSScriptRoot"
LogWrite "Clarity args: $LaunchArgs"

LogWrite "Running dqxclarity."
& .\venv\Scripts\python.exe -m main $LaunchArgs
