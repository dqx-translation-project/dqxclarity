#Requires AutoHotkey v2.0
#SingleInstance force
#Include <json>
#Include <image>

; read ini
ini := {}
ini.enabledeepl := IniRead(".\user_settings.ini", "translation", "enabledeepltranslate", "False")
ini.deeplkey := IniRead(".\user_settings.ini", "translation", "deepltranslatekey", "")
ini.enablegoogletranslate := IniRead(".\user_settings.ini", "translation", "enablegoogletranslate", "False")
ini.googletranslatekey := IniRead(".\user_settings.ini", "translation", "googletranslatekey", "")
ini.enablegoogletranslatefree := IniRead(".\user_settings.ini", "translation", "enablegoogletranslatefree", "False")
ini.communitylogging := IniRead(".\user_settings.ini", "launcher", "communitylogging", "False")
ini.nameplates := IniRead(".\user_settings.ini", "launcher", "nameplates", "False")
ini.updategamefiles := IniRead(".\user_settings.ini", "launcher", "updategamefiles", "False")
ini.disableupdates := IniRead(".\user_settings.ini", "launcher", "disableupdates", "False")
ini.debuglogging := IniRead(".\user_settings.ini", "launcher", "debuglogging", "False")

; main window
Launcher := Gui()
Launcher.Opt("-MaximizeBox")

Launcher.AddPicture("YP+1 w150 h-1 vImage", LoadImageFromResource("img/rosie.png"))

; configuration group
Launcher.AddGroupBox("ys+10 w200 h120 c0B817C", "Configuration")
Launcher.AddCheckBox("XP+10 YP+20 vCommunityLogging Checked" . ConvertBoolToState(ini.communitylogging), "Community Logging")
Launcher.AddCheckBox("vNameplates Checked" . ConvertBoolToState(ini.nameplates), "Nameplates")
Launcher.AddCheckBox("vUpdateGameFiles Checked" . ConvertBoolToState(ini.updategamefiles), "Update Game Files")
Launcher.AddCheckBox("vDisableUpdates Checked"  . ConvertBoolToState(ini.disableupdates), "Disable Updates")
Launcher.AddCheckBox("vDebugLogging Checked" . ConvertBoolToState(ini.debuglogging), "Enable Debug Logging")
Launcher.AddStatusBar("vStatusBar", "")

; api group
Launcher.AddGroupBox("Section YP+30 XP-10 w200 h170 c0B817C", "API Settings")
Launcher.AddCheckBox("XP+10 YP+20 vUseDeepL Checked" . ConvertBoolToState(ini.enabledeepl), "Use DeepL")
Launcher.AddEdit("YP+20 W180 r1 vDeepLKey", ini.deeplkey).Opt("+Password")
Launcher.AddCheckBox("XP vUseGoogleTranslate Checked" . ConvertBoolToState(ini.enablegoogletranslate), "Use Google Translate")
Launcher.AddEdit("YP+20 W180 r1 vGoogleTranslateKey", ini.googletranslatekey).Opt("+Password")
Launcher.AddButton("YP+30 w180 vValidateKey", "Validate Enabled Key").OnEvent("Click", ValidateKey)
Launcher.AddCheckBox("XP vUseGoogleTranslateFree Checked" . ConvertBoolToState(ini.enablegoogletranslatefree), "Use Free Google Translate")

; launch
Launcher.AddButton("YP+60 XS+10 w80 h30 vRunProgram", "Run").Opt("+Default")
Launcher.AddButton("x+20 vGitHub w80 h30", "GitHub").OnEvent("Click", OpenGitHub)

; tooltips
Launcher["CommunityLogging"].ToolTip := "Enables logging of internal game files to a text file."
Launcher["Nameplates"].ToolTip := "Transliterates Japanese nameplates to English."
Launcher["UpdateGameFiles"].ToolTip := "Downloads/updates the modded DAT/IDX files."
Launcher["DisableUpdates"].ToolTip := "Don't check for dqxclarity updates on launch."
Launcher["DebugLogging"].ToolTip := "Enables more verbose logging."
Launcher["UseDeepL"].ToolTip := "Enable DeepL as your choice of external translation."
Launcher["UseGoogleTranslate"].ToolTip := "Enable Google Translate as your choice of external translation."
Launcher["UseGoogleTranslateFree"].ToolTip := "Uses the 'free' version of Google Translate. Rate limiting may ensue under use."
Launcher["DeepLKey"].ToolTip := "Paste your DeepL API Key here."
Launcher["GoogleTranslateKey"].ToolTip := "Paste your Google Translate API Key here."
Launcher["ValidateKey"].ToolTip := "Validate that the selected API key works. Check here for status."
Launcher["Run"].ToolTip := "Run the program."
Launcher["GitHub"].ToolTip := "View the source code in your default browser."

; function handlers
Launcher["CommunityLogging"].OnEvent("Click", CommunityLoggingWarning)
Launcher["UseDeepL"].OnEvent("Click", CheckedDeepL)
Launcher["UseGoogleTranslate"].OnEvent("Click", CheckedGoogleTranslate)
Launcher["RunProgram"].OnEvent("Click", RunProgram)

; show launcher
Launcher.Show("AutoSize Center")
OnMessage(0x0200, On_WM_MOUSEMOVE)


CheckedDeepL(*) {
    ; Behavior when the "Use DeepL" checkbox is checked.
    Launcher["UseGoogleTranslate"].value := 0
    Launcher["GoogleTranslateKey"].Opt("+Disabled")
    Launcher["DeepLKey"].Opt("-Disabled")
}


CheckedGoogleTranslate(*) {
    ; Behavior when the "Use Google Translate" checkbox is checked.
    Launcher["UseDeepL"].value := 0
    Launcher["DeepLKey"].Opt("+Disabled")
    Launcher["GoogleTranslateKey"].Opt("-Disabled")
}


ValidateKey(*) {
    ; Validates the enabled API key by reaching out to whichever
    ; API service is checked.
    if (Launcher["UseDeepL"].value = 1) {
        DeepLKey := Launcher["DeepLKey"].value
        if (DeepLKey) {
            if (SubStr(DeepLKey, "-3") = ":fx")
                url := "https://api-free.deepl.com/v2/usage"
            else
                url := "https://api.deepl.com/v2/usage"

            web := ComObject('WinHttp.WinHttpRequest.5.1')
            web.Open("GET", url)
            web.SetRequestHeader("Authorization", "DeepL-Auth-Key " . DeepLKey)
            web.Send()
            web.WaitForResponse()
            Response := JSON.parse(web.ResponseText)

            try {
                PercentageUsed := Round(Response["character_count"] / Response["character_limit"] * 100, 2)
                UpdateStatusBar(Response["character_count"] . "/" . Response["character_limit"] . " characters used, or approximately " . PercentageUsed . "%.")
            } catch {
                UpdateStatusBar("Failed to validate key.")
            }
        } else {
            UpdateStatusBar("Enter a key before attempting to validate.")
        }
    } else if (Launcher["UseGoogleTranslate"].value = 1){
        GoogleTranslateKey := Launcher["GoogleTranslateKey"].value
        if (GoogleTranslateKey) {
            url := "https://translation.googleapis.com/language/translate/v2?q=a&target=es&source=en&key=" . GoogleTranslateKey
            web := ComObject('WinHttp.WinHttpRequest.5.1')
            web.Open("GET", url)
            web.Send()
            web.WaitForResponse()
            Response := JSON.parse(web.ResponseText)
            try {
                if (Response["data"]["translations"]){
                    UpdateStatusBar("Key successfully validated.")
                }
            } catch {
                UpdateStatusBar(Response["error"]["message"])
            }
        }
    } else {
        UpdateStatusBar("Enable an API service before validating.")
    }
}


UpdateStatusBar(text) {
    ; Updates the status bar at the bottom of the GUI.
    ;; @param text Text to update the status bar.
    Launcher["StatusBar"].SetText(text)
}


CommunityLoggingWarning(*) {
    ; Send a warning if community logging is enabled as it can be buggy.
    if Launcher["CommunityLogging"].value = 1 {
        Result := MsgBox("You have enabled community logging.`n`nThis feature is unstable and may result in unexpected behavior while playing, up to and including crashes. Do not report issues of crashing if you have this enabled.`n`nIf you still want to enable this to help with the project, click `"Yes.`" Otherwise, click `"No.`"", "Community Logging", "YN Icon! Default2 0x1000")
        if (Result = "No") {
            Launcher["CommunityLogging"].value := 0
        }
    }
}


OpenGitHub(*) {
    ; Opens the dqxclarity repository in the user's browser.
    Run("https://github.com/dqx-translation-project/dqxclarity")
}


ConvertBoolToState(value) {
    ; Used for interpreting the values of the user_settings.ini file.
    ;; @param value Value to convert to a state.
    if (value = "True")
        return 1
    else
        return 0
}


ConvertStateToBool(value) {
    ; Used for interpreting the values of the user_settings.ini file.
    ;; @param value Value to convert to a bool.
    if (value = "1")
        return "True"
    else
        return "False"
}


On_WM_MOUSEMOVE(wParam, lParam, msg, Hwnd) {
    ; Updates the status bar at the bottom of the GUI
    ; based on what control the user has their mouse
    ; hovered over.
    static PrevHwnd := 0
    if (Hwnd != PrevHwnd)
    {
        CurrControl := GuiCtrlFromHwnd(Hwnd)
        if CurrControl
        {
            if !CurrControl.HasProp("ToolTip")
                return
            UpdateStatusBar(CurrControl.ToolTip)
        }
        PrevHwnd := Hwnd
    }
}


FakeFileInstall(*) {
    ; This is necessary to exist during compile. This tells Ahk2exe to
    ; include the file during compilation, but since we never call the
    ; function, it won't extract the image
    FileInstall("img/rosie.png", "*")
}


SaveToIni(*) {
    ; Saves all of the user settings to user_settings.ini.
    IniWrite(ConvertStateToBool(Launcher["CommunityLogging"].value), ".\user_settings.ini", "launcher", "communitylogging")
    IniWrite(ConvertStateToBool(Launcher["Nameplates"].value), ".\user_settings.ini", "launcher", "nameplates")
    IniWrite(ConvertStateToBool(Launcher["UpdateGameFiles"].value), ".\user_settings.ini", "launcher", "updategamefiles")
    IniWrite(ConvertStateToBool(Launcher["DisableUpdates"].value), ".\user_settings.ini", "launcher", "disableupdates")
    IniWrite(ConvertStateToBool(Launcher["DebugLogging"].value), ".\user_settings.ini", "launcher", "debuglogging")
    IniWrite(ConvertStateToBool(Launcher["UseDeepL"].value), ".\user_settings.ini", "translation", "enabledeepltranslate")
    IniWrite(Launcher["DeepLKey"].value, ".\user_settings.ini", "translation", "deepltranslatekey")
    IniWrite(ConvertStateToBool(Launcher["UseGoogleTranslate"].value), ".\user_settings.ini", "translation", "enablegoogletranslate")
    IniWrite(Launcher["GoogleTranslateKey"].value, ".\user_settings.ini", "translation", "googletranslatekey")
    IniWrite(ConvertStateToBool(Launcher["UseGoogleTranslateFree"].value), ".\user_settings.ini", "translation", "enablegoogletranslatefree")
}


GetClarityArgs(*) {
    ; Read the GUI to see which arguments we need to pass to dqxclarity.
    ; Returns the appropriate arguments.
    args := ""
    if (Launcher["CommunityLogging"].value = 1)
        args := args . "--community-logging"
    if (Launcher["Nameplates"].value = 1)
        args := args . " " . "--nameplates"
    if (Launcher["UpdateGameFiles"].value = 1)
        args := args . " " . "--update-dat"
    if (Launcher["DisableUpdates"].value = 1)
        args := args . " " . "--disable-update-check"
    if (Launcher["DebugLogging"].value = 1)
        args := args . " " . "--debug"
    if (Launcher["UseDeepL"].value = 1 or Launcher["UseGoogleTranslate"].value = 1 or Launcher["UseGoogleTranslateFree"].value = 1)
        args := args . " " . "--communication-window"

    if (args)
        return args
    else
        return ""
    return args
}


CheckScriptPath(*) {
    ; Ensure the user doesn't run dqxclarity from Program Files, as this is known
    ; to cause issues saving user settings and writing to the clarity db.
    program_files := EnvGet("programfiles(x86)")
    if InStr(A_ScriptDir, program_files) {
        MsgBox(Format("You placed this folder in {1}. This is known to cause issues with dqxclarity. Please move the directory somewhere else (Desktop, Documents, etc.)", program_files),, "OK Iconx 0x1000")
        ExitApp
    }
}


RunProgram(*) {
    CheckScriptPath
    SaveToIni
    if (FileExist("run_clarity.ps1")) {
        ; When users download clarity, Windows tends to mark the ps1 script as unsafe, which can trigger
        ; a security warning when launching run_clarity.ps1. Run this in the same Run() call so that a window
        ; doesn't flicker when it executes.
        windows_root := EnvGet("SystemRoot")
        cmd_path := Format("{1}\System32\cmd.exe", windows_root)
        powershell_path := Format("{1}\System32\WindowsPowerShell\v1.0\powershell.exe", windows_root)

        Run(Format("{1} /c {2} Unblock-File -Path .\run_clarity.ps1; {1} /c {2} -ExecutionPolicy Bypass -File run_clarity.ps1 {3}", cmd_path, powershell_path, GetClarityArgs()))
    }
    else
        MsgBox("Did not find run_clarity.ps1 in this directory.`n`nEnsure you didn't move dqxclarity.exe outside of the directory.",, "OK Iconx 0x1000")
    ExitApp
}
