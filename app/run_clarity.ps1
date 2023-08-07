$ClarityFlags = "-pnvcl"

function LogWrite($string) {
   Write-Host $string -ForegroundColor "Yellow"
}

function PythonExePath() {
    # Because of the pymem lib, required to install Python for all users.
    # No longer supporting "Install for Me" installations, just "Install for all users"
    $PythonRegKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Python\PythonCore\3.11-32\InstallPath"
    $ErrorActionPreference="SilentlyContinue"
    try { (Get-ItemProperty -Path $PythonRegKey -Name "ExecutablePath").ExecutablePath }
    catch { "" }
    $ErrorActionPreference="Continue"
}

function RemoveFile($path) {
    if (Test-Path $path) {
        Remove-Item $path -Recurse
    }
}

$ErrorActionPreference="SilentlyContinue"
Stop-Transcript | Out-Null
$ErrorActionPreference = "Continue"
Start-Transcript -path console.log

$HelpMessage = "If you need help, please join the DQX Discord and post your question in the #clarity-questions channel. https://discord.gg/dragonquestx"

$PythonInstallPath = PythonExePath

if (!$PythonInstallPath) {
    LogWrite "Could not find Python installation for Python 3.11-32."

    $Shell = New-Object -comobject "WScript.Shell"
    $Result = $Shell.popup("Could not find Python 3.11 installation. Do you want to install it?",0,"Question",4+32)

    if ($Result -eq 6) {
        $ProgressPreference = "SilentlyContinue"  # workaround to faster download speeds using IWR
        LogWrite "Downloading Python executable from the internet."
        Invoke-WebRequest -Uri https://www.python.org/ftp/python/3.11.3/python-3.11.3.exe -OutFile python-3.11.3.exe
        $PythonMD5 = Get-FileHash .\python-3.11.3.exe -Algorithm MD5
        if ($PythonMD5.Hash -ne "691232496E346CE0860AEF052DD6844F") {
            LogWrite "File download did not complete successfully. Please re-run this script and try again. $HelpMessage"
            RemoveFile "python-3.11.3.exe"
            Read-Host "Press ENTER to close."
            Exit
        } else {
            LogWrite "Launching Python 3.11 installer and installing Python for you. Please wait."
            .\python-3.11.3.exe /passive InstallAllUsers=1 PrependPath=1 Include_doc=0 Include_tcltk=1 Include_test=0 Shortcuts=0 SimpleInstallDescription="Installing necessary components for dqxclarity." | Out-Null
            $PythonInstallPath = PythonExePath

            if (!$PythonInstallPath) {
                LogWrite "Failed to install Python. Please try again. $HelpMessage"
                Read-Host "Press ENTER to close."
                Exit
            }
        }
    } else {
        LogWrite "You selected 'No'. Python 3.11 is required to use dqxclarity. Exiting."
        Read-Host "Press ENTER to close."
        Exit
    }
}

if (Test-Path -Path "venv") {
    try {
		& .\venv\Scripts\activate
        & .\venv\Scripts\python.exe -c "import click"
    }
    catch {
        LogWrite "Virtual environment did not install correctly. Re-open dqxclarity to try again. $HelpMessage"
        RemoveFile "venv"
        Read-Host "Press ENTER to close"
        Exit
    }
} else {
    LogWrite "Creating virtual environment."
    & $PythonInstallPath -m venv venv
	& .\venv\Scripts\activate
    LogWrite "Updating pip and installation dependencies."
    & .\venv\Scripts\python.exe -m pip install --upgrade pip setuptools wheel --quiet
    LogWrite "Installing dqxclarity dependencies."
    & .\venv\Scripts\pip.exe install -r requirements.txt --quiet
}

LogWrite "Python install location: $PythonInstallPath"
LogWrite "Clarity installation path: $PSScriptRoot"
LogWrite "Clarity flags: $ClarityFlags"

LogWrite "Running dqxclarity."
& .\venv\Scripts\python.exe -m main $ClarityFlags
