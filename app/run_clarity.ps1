$ClarityFlags = "-pnmvc" 

$ErrorActionPreference="SilentlyContinue"
Stop-Transcript | Out-Null
$ErrorActionPreference = "Continue"
Start-Transcript -path console.log -append

function LogWrite($string) {
   Write-Host $string -ForegroundColor "Yellow"
   $TimeStamp = (Get-Date -Format yyyy-MM-dd) + " " + (Get-Date -Format HH:MM:ss) 
   $TimeStamp + " " + $string | Out-File -Filepath "out.log" -Append -Force -Encoding utf8
}

function GetPythonInstall() {
    # Determines the location of where the user installed Python.
    # If the user installs Python for all users, but doesn't choose a
    # custom install path, any other user on the system won't have Python
    # available to them as the default installation is
    # C:\users\<user>\AppData\..., which another user on the system
    # wouldn't have access to.

    # Users that install with the default settings use this key
    $PythonRegKey = "Registry::HKEY_CURRENT_USER\SOFTWARE\Python\PythonCore\3.9-32\InstallPath"
    # Users that install for all users, but with a custom install path settings use this key
    $PythonRegKeyCustomInstall = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Python\PythonCore\3.9-32\InstallPath"

    $ErrorActionPreference="SilentlyContinue"
    if ((Get-ItemProperty -Path $PythonRegKey -Name "(default)")."(default)") {
        (Get-ItemProperty -Path $PythonRegKey -Name "(default)")."(default)"
    } elseif ((Get-ItemProperty -Path $PythonRegKeyCustomInstall -Name "(default)")."(default)") {
        (Get-ItemProperty -Path $PythonRegKeyCustomInstall -Name "(default)")."(default)"
    }
    $ErrorActionPreference="Continue"
}

$PythonInstallPath = GetPythonInstall

if (!$PythonInstallPath) {
    LogWrite "Could not find Python installation for Python 3.9-32."

    $Shell = new-object -comobject "WScript.Shell"
    $Result = $Shell.popup("Could not find Python installation. Do you want to install it?",0,"Question",4+32)

    if ($Result -eq 6) {
        $ProgressPreference = 'SilentlyContinue'  # workaround to faster download speeds using IWR
        LogWrite "Downloading Python executable from the internet."
        Invoke-WebRequest -Uri https://www.python.org/ftp/python/3.9.7/python-3.9.7.exe -OutFile python-3.9.7.exe
        $PythonMD5 = Get-FileHash .\python-3.9.7.exe -Algorithm MD5
        if ($PythonMD5.Hash -ne "0d949bdfdbd0c8c66107a980a95efd85") {  # pragma: allowlist secret
            LogWrite "File download did not complete successfully. Please re-run this script and try again. Alternatively, you can install it yourself with this link."
            LogWrite "https://www.python.org/ftp/python/3.9.7/python-3.9.7.exe"

            if (Test-Path "python-3.9.7.exe" = True) {
                Remove-Item "python-3.9.7.exe"
            }

            Read-Host "Press ENTER to close."
            Exit
        } else {
            LogWrite "Launching Python installer. Make sure you check 'Add Python 3.9 to PATH' before clicking 'Install Now'."
            & .\python-3.9.7.exe
            Read-Host "When you are COMPLETELY finished with the install, press ENTER to continue. If ENTER does nothing, click inside this box first and make sure 'Select:' is not in the title bar of this window."

            $PythonInstallPath = GetPythonInstall

            if (!$PythonInstallPath) {
                LogWrite "Failed to install Python automatically. Please try downloading the installer manually and walking through the setup using the README on dqxclarity's Github page."
                LogWrite "Github: https://github.com/dqxtranslationproject/dqxclarity"
                LogWrite "Python: https://www.python.org/ftp/python/3.9.7/python-3.9.7.exe"
                Read-Host "Press ENTER to close."
                Exit
            }
        }

    } else {
        LogWrite "No problem. I get it - you want to be in control. You will need to download Python in order to use dqxclarity. Here's a link to the download in case you want to grab it yourself."
        LogWrite "https://www.python.org/ftp/python/3.9.7/python-3.9.7.exe"
        Read-Host "Press ENTER to close."
        Exit
    }
}

if (Test-Path -Path "venv") {
    $CheckIfPythonModulesExist = & .\venv\Scripts\python.exe -c "import click"
    if ($LASTEXITCODE -eq 0) {
        LogWrite "Virtual environment exists. Activating."
        & .\venv\Scripts\activate
    } else {
        LogWrite "Virtual environment doesn't look quite right. Deleting local venv folder. Re-open dqxclarity to re-install."
        Remove-Item 'venv' -Recurse
        Read-Host "Press ENTER to close."
        Exit
    }
} else {
    LogWrite "Creating virtual environment (venv)."
    $PythonExe = "$PythonInstallPath" + "python.exe"
    & $PythonExe -m venv venv
    LogWrite "Activating virtual environment."
    & .\venv\Scripts\activate

    $AreWeInAVirtualEnvironment = & .\venv\Scripts\python.exe -c "import sys; print('False') if sys.prefix == sys.base_prefix else print('True')"

    if ("$AreWeInAVirtualEnvironment" -eq "False") {
        LogWrite "Failed to activate virtual environment. Try deleting the 'venv' folder and running this again. Exiting."
        Read-Host "Press ENTER to close."
        Exit
    }

    if (Test-Path -Path "requirements.txt") {
        LogWrite "Installing requirements."
        & .\venv\Scripts\pip.exe install -r requirements.txt --quiet
    }
}

if (Test-Path -Path "requirements.txt") {
    .\venv\Scripts\pip.exe config set global.disable-pip-version-check true | Out-Null
    LogWrite "Checking requirements."
    & .\venv\Scripts\pip.exe install -r requirements.txt | findstr /V /C:"Requirement already satisfied"
}

LogWrite "Python install location: $PythonInstallPath"

LogWrite "Running clarity."
& .\venv\Scripts\python.exe main.py $ClarityFlags
