; Inno Setup script - builds installer\USBThreatAnalyzer_Setup.exe
; The installer copies the EXE, adds a Start Menu entry and (by default) a
; DESKTOP ICON. No administrator rights needed: it installs per-user.
; Get Inno Setup (free): https://jrsoftware.org/isdl.php

#define AppName "USB Threat Analyzer"
#define AppExe  "USBThreatAnalyzer.exe"

[Setup]
AppId={{FD46B2F0-E49A-44AD-8363-B986AEF90CE5}
AppName={#AppName}
AppVersion=1.0.0
AppPublisher=USB Threat Analyzer
DefaultDirName={localappdata}\Programs\{#AppName}
DefaultGroupName={#AppName}
PrivilegesRequired=lowest
OutputDir=.
OutputBaseFilename=USBThreatAnalyzer_Setup
SetupIconFile=..\assets\app.ico
UninstallDisplayIcon={app}\{#AppExe}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; Asks the user to close a running copy before upgrading/uninstalling.
AppMutex=Local\USBThreatAnalyzer.SingleInstance

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop icon"; GroupDescription: "Shortcuts:"

[Files]
Source: "..\dist\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"

[Registry]
; Uninstall also removes the optional "Start with Windows" entry (if the user enabled it).
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: none; ValueName: "USBThreatAnalyzer"; Flags: dontcreatekey uninsdeletevalue

[Run]
Filename: "{app}\{#AppExe}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent
; Scan history, quarantine and reports in %LOCALAPPDATA%\USBThreatAnalyzer are deliberately
; kept on uninstall (quarantine may hold files the user still needs).
