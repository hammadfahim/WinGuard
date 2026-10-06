; WinGuard — Inno Setup 6 script (PLAN.md §13)
; Build: ISCC.exe /DMyAppVersion=1.2.3 installer\winguard.iss
; Expects the published binaries staged in ..\dist\ (winguard-svc.exe,
; winguard-gui.exe, appsettings.json). The icon is optional.

#define MyAppName "WinGuard"
#ifndef MyAppVersion
  #define MyAppVersion "0.1.0"
#endif
#define MyAppPublisher "WinGuard contributors"
#define MyAppUrl "https://github.com/hammadfahim/WinGuard"
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
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
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
; The executable path is passed with escaped inner quotes (\"...\") so the stored ImagePath is
; itself quoted: a bare path with spaces ("C:\Program Files\...") is an unquoted service path.
; On upgrade the service already exists (and was stopped in PrepareToInstall), so the
; create step is skipped; the config step below always runs and also re-quotes the path of a
; service registered by an older installer.
Filename: "{sys}\sc.exe"; Parameters: "create {#MyAppServiceName} binPath= ""\""{app}\{#MyAppServiceExe}\"""" start= delayed-auto DisplayName= ""{#MyAppServiceDisplayName}"""; Flags: runhidden; StatusMsg: "Registering {#MyAppServiceDisplayName}..."; Check: not ServiceExistsFlag
Filename: "{sys}\sc.exe"; Parameters: "config {#MyAppServiceName} binPath= ""\""{app}\{#MyAppServiceExe}\"""""; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "description {#MyAppServiceName} ""{#MyAppServiceDescription}"""; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "failure {#MyAppServiceName} reset= 86400 actions= restart/5000/restart/5000/restart/5000"; Flags: runhidden
; Lock down the data folder (created by [Dirs]) before the service starts, so no
; local standard user can pre-create/poison the DB: remove inherited ACEs and grant
; only SYSTEM + Administrators full control. The accounts are given as SIDs
; (S-1-5-18 = SYSTEM, S-1-5-32-544 = Administrators) because their names are localized.
Filename: "{sys}\icacls.exe"; Parameters: """{commonappdata}\WinGuard"" /inheritance:r /grant:r ""*S-1-5-18:(OI)(CI)F"" ""*S-1-5-32-544:(OI)(CI)F"""; Flags: runhidden; StatusMsg: "Securing {#MyAppName} data folder..."
Filename: "{sys}\sc.exe"; Parameters: "start {#MyAppServiceName}"; Flags: runhidden; StatusMsg: "Starting {#MyAppServiceDisplayName}..."
; Optional prerequisites. The subcategory GUID is locale-independent (the English name
; "Logon" silently fails on non-English Windows).
Filename: "{sys}\auditpol.exe"; Parameters: "/set /subcategory:""{{0CCE9215-69AE-11D9-BED3-505054503030}"" /success:enable /failure:enable"; Flags: runhidden; Tasks: auditpolicy; StatusMsg: "Enabling logon failure auditing..."
; The console requires elevation (its manifest says requireAdministrator). A postinstall entry
; is started as the ORIGINAL, non-elevated user by default, which fails with "CreateProcess
; failed; code 740". runascurrentuser starts it with Setup's own (already elevated) rights.
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent runascurrentuser

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Code]
var
  { User's answer to the uninstall data-folder prompt; DelTree happens in
    usPostUninstall, after the service is stopped/deleted and the DB is unlocked. }
  DeleteDataOnUninstall: Boolean;

{ --- Service helpers ------------------------------------------------------- }

{ True when the WinGuard service is registered. Used by [Run]'s create step
  (Check:) to stay idempotent across upgrades, and by the uninstaller. }
function ServiceExistsFlag(): Boolean;
var
  ResultCode: Integer;
begin
  Result := Exec(ExpandConstant('{sys}\sc.exe'),
    'query {#MyAppServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode)
    and (ResultCode = 0);
end;

{ Run `sc query` and return its combined output (captured via cmd redirection,
  since Exec alone cannot capture stdout). }
function QueryServiceState(): string;
var
  ResultCode: Integer;
  TempFile: string;
  Contents: AnsiString;
begin
  Result := '';
  TempFile := ExpandConstant('{tmp}\winguard-svc-state.txt');
  if Exec(ExpandConstant('{cmd}'),
    '/c ' + ExpandConstant('{sys}\sc.exe') + ' query {#MyAppServiceName} > "' +
    TempFile + '" 2>&1', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    if LoadStringFromFile(TempFile, Contents) then
      Result := Contents;
  end;
end;

{ Request a stop and poll `sc query` until the state reports STOPPED, for up to
  ~30 seconds. Returns True once stopped (or if the query is unreadable). }
function StopServiceAndWait(): Boolean;
var
  Attempts: Integer;
  ResultCode: Integer;
  State: string;
begin
  Result := False;
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop {#MyAppServiceName}', '',
    SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Attempts := 0;
  while Attempts < 30 do
  begin
    State := QueryServiceState();
    if (State = '') or (Pos('STOPPED', Uppercase(State)) > 0) then
    begin
      Result := True;
      Exit;
    end;
    Sleep(1000);
    Attempts := Attempts + 1;
  end;
end;

{ --- Install --------------------------------------------------------------- }

{ Stop any existing service before [Files] overwrites the running EXE. }
function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  if ServiceExistsFlag then
    StopServiceAndWait();
end;

{ --- Uninstall ------------------------------------------------------------- }

function InitializeUninstall(): Boolean;
var
  Response: Integer;
begin
  DeleteDataOnUninstall := False;
  { Never show a prompt during a silent uninstall; keep the data by default. }
  if not UninstallSilent then
  begin
    Response := MsgBox('Delete WinGuard data (database and logs) from ' +
      ExpandConstant('{commonappdata}\WinGuard') + '?'#13#10 +
      'Choose No to keep your ban history and settings.',
      mbConfirmation, MB_YESNO);
    DeleteDataOnUninstall := (Response = IDYES);
  end;
  Result := True;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
  ClearFwWarning: String;
begin
  ClearFwWarning := 'Some WinGuard firewall rules could not be removed. ' +
    'Remove them manually via wf.msc (rules named WinGuard_Block_*).';

  if CurUninstallStep = usUninstall then
  begin
    { Stop the service and wait for STOPPED before deleting it, so clear-firewall
      runs against a quiet firewall and the binary can still be started here. }
    if ServiceExistsFlag then
    begin
      StopServiceAndWait();
      Exec(ExpandConstant('{sys}\sc.exe'), 'delete {#MyAppServiceName}', '',
        SW_HIDE, ewWaitUntilTerminated, ResultCode);
    end;

    { Remove WinGuard_Block_* rules while winguard-svc.exe is still on disk.
      A non-zero exit means some rules remain; warn (non-fatal). Silent uninstalls
      never show a modal — the outcome goes to the uninstall log instead. }
    if Exec(ExpandConstant('{app}\{#MyAppServiceExe}'), '--clear-firewall', '',
      SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    begin
      if ResultCode <> 0 then
      begin
        Log('WinGuard: --clear-firewall reported failure (exit code ' + IntToStr(ResultCode) + ').');
        if not UninstallSilent then
          MsgBox(ClearFwWarning, mbError, MB_OK);
      end;
    end
    else
    begin
      Log('WinGuard: could not launch --clear-firewall.');
      if not UninstallSilent then
        MsgBox(ClearFwWarning, mbError, MB_OK);
    end;
  end
  else if CurUninstallStep = usPostUninstall then
  begin
    { Data is deleted only after the service/DB are gone, and only if the user
      answered Yes (or would have been prompted; silent mode keeps data). }
    if DeleteDataOnUninstall then
      DelTree(ExpandConstant('{commonappdata}\WinGuard'), True, True, True);
  end;
end;