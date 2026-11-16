; WireForge installer (Inno Setup 6). Per-user: no administrator rights needed.
; The data folder (%LOCALAPPDATA%\WireForge: settings, usage history, device
; names, speed-test history) is never touched by Setup and is left in place by
; the uninstaller.

#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif

[Setup]
AppId={{C8E41B7A-2D95-4F3C-B6A0-91D7E5F2A3C4}
AppName=WireForge
AppVersion={#AppVersion}
AppVerName=WireForge {#AppVersion}
AppPublisher=Zheer Khalid
AppPublisherURL=https://zheer.dev
AppSupportURL=https://github.com/zheerkhalid/wireforge
AppUpdatesURL=https://github.com/zheerkhalid/wireforge/releases
DefaultDirName={autopf}\WireForge
DefaultGroupName=WireForge
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=WireForge-Setup
SetupIconFile=..\target\wireforge.ico
UninstallDisplayIcon={app}\WireForge.exe
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no
LicenseFile=..\LICENSE
VersionInfoVersion={#AppVersion}
VersionInfoCompany=Zheer Khalid (zheer.dev)
VersionInfoDescription=WireForge Setup

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "startup"; Description: "Start WireForge when I sign in (hidden in the notification area)"; GroupDescription: "Startup:"; Flags: unchecked

[Files]
Source: "..\target\release\WireForge.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion
Source: "..\NOTICE"; DestDir: "{app}"; DestName: "NOTICE.txt"; Flags: ignoreversion
Source: "..\PRIVACY.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\WireForge"; Filename: "{app}\WireForge.exe"
Name: "{group}\Uninstall WireForge"; Filename: "{uninstallexe}"
Name: "{autodesktop}\WireForge"; Filename: "{app}\WireForge.exe"; Tasks: desktopicon

[Registry]
; The same per-user startup entry the "Start with Windows" switch in Settings writes.
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "WireForge"; ValueData: """{app}\WireForge.exe"" --minimized"; Tasks: startup
; Whether it was set here or in Settings, the entry is removed on uninstall.
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: none; ValueName: "WireForge"; Flags: dontcreatekey uninsdeletevalue

[Run]
Filename: "{app}\WireForge.exe"; Description: "{cm:LaunchProgram,WireForge}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{cmd}"; Parameters: "/C taskkill /IM WireForge.exe /F"; Flags: runhidden; RunOnceId: "KillWireForge"
