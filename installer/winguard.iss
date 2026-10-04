; WinGuard — Inno Setup 6 script (PLAN.md §13)
; Build: ISCC.exe /DMyAppVersion=1.2.3 installer\winguard.iss
; Expects the published binaries staged in ..\dist\ (winguard-svc.exe,
; winguard-gui.exe, appsettings.json). The icon is optional.

#define MyAppName "WinGuard"
#ifndef MyAppVersion
  #define MyAppVersion "0.1.0"
#endif
#define MyAppPublisher "WinGuard contributors"
#define MyAppUrl "https://github.com/winguard/winguard"
#define MyAppExeName "winguard-gui.exe"
#define MyAppServiceExe "winguard-svc.exe"
#define MyAppServiceName "WinGuardService"
#define MyAppServiceDisplayName "WinGuard Service"
#define MyAppServiceDescription "WinGuard - blocks brute-force attackers in the firewall"

#define IconFile SourcePath + "\assets\icon.ico"

[Setup]
; A fixed AppId keeps upgrades/uninstalls working across versions.
AppId={{2F2C9A5E-7C4B-4E2A-9E3D-6B1A0C7D5F42}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppUrl}
AppSupportURL={#MyAppUrl}
AppUpdatesURL={#MyAppUrl}
DefaultDirName={autopf}\WinGuard
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
LicenseFile=assets\license.txt
OutputDir=Output
OutputBaseFilename=WinGuard-Setup-{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
UninstallDisplayName={#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExeName}

#if FileExists(IconFile)
SetupIconFile={#IconFile}
#endif

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "auditpolicy"; Description: "Enable Windows logon failure auditing (recommended for RDP detection)"; GroupDescription: "Additional tasks:"; Flags: checkedonce
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "..\dist\{#MyAppServiceExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\appsettings.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "assets\license.txt"; DestDir: "{app}"; Flags: ignoreversion
#if FileExists(IconFile)
Source: "{#IconFile}"; DestDir: "{app}"; DestName: "icon.ico"; Flags: ignoreversion
#endif

[Dirs]
Name: "{commonappdata}\WinGuard"
Name: "{commonappdata}\WinGuard\Logs"

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; Register the service. "binPath=" and "DisplayName=" need a space before the quoted value.
Filename: "{sys}\sc.exe"; Parameters: "create {#MyAppServiceName} binPath= ""{app}\{#MyAppServiceExe}"" start= delayed-auto DisplayName= ""{#MyAppServiceDisplayName}"""; Flags: runhidden; StatusMsg: "Registering {#MyAppServiceDisplayName}..."
Filename: "{sys}\sc.exe"; Parameters: "description {#MyAppServiceName} ""{#MyAppServiceDescription}"""; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "failure {#MyAppServiceName} reset= 86400 actions= restart/5000/restart/5000/restart/5000"; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "start {#MyAppServiceName}"; Flags: runhidden; StatusMsg: "Starting {#MyAppServiceDisplayName}..."
; Optional prerequisites.
Filename: "{sys}\auditpol.exe"; Parameters: "/set /subcategory:""Logon"" /success:enable /failure:enable"; Flags: runhidden; Tasks: auditpolicy; StatusMsg: "Enabling logon failure auditing..."
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{sys}\sc.exe"; Parameters: "stop {#MyAppServiceName}"; Flags: runhidden; RunOnceId: "StopWinGuardService"
Filename: "{sys}\sc.exe"; Parameters: "delete {#MyAppServiceName}"; Flags: runhidden; RunOnceId: "DeleteWinGuardService"
Filename: "{app}\{#MyAppServiceExe}"; Parameters: "--clear-firewall"; Flags: runhidden waituntilterminated; RunOnceId: "ClearWinGuardFirewallRules"

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Code]
function InitializeUninstall(): Boolean;
var
  Response: Integer;
begin
  Response := MsgBox('Delete WinGuard data (database and logs) from ' +
    ExpandConstant('{commonappdata}\WinGuard') + '?'#13#10 +
    'Choose No to keep your ban history and settings.',
    mbConfirmation, MB_YESNO);

  if Response = IDYES then
  begin
    DelTree(ExpandConstant('{commonappdata}\WinGuard'), True, True, True);
  end;

  Result := True;
end.