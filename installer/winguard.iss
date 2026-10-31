; WinGuard — Inno Setup 6 script (PLAN.md §13)
; Build: ISCC.exe /DMyAppVersion=1.2.3 installer\winguard.iss
; Expects the published binaries staged in ..\dist\ (winguard-svc.exe,
; winguard-gui.exe, appsettings.json). The icon is optional.

#define MyAppName "WinGuard"
#ifndef MyAppVersion
  #define MyAppVersion "0.3.0"
#endif
#define MyAppPublisher "WinGuard contributors"
#define MyAppUrl "https://github.com/hammadfahim/WinGuard"
#define MyAppExeName "winguard-gui.exe"
#define MyAppServiceExe "winguard-svc.exe"
#define MyAppServiceName "WinGuardService"
#define MyAppServiceDisplayName "WinGuard Service"
#define MyAppServiceDescription "WinGuard - blocks brute-force attackers in the firewall"
; Longer than the service host's own 30 s shutdown timeout, so a slow stop is not called a failure.
#define MyAppStopTimeoutSeconds 60

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
WizardImageFile=assets\wizard-large-100.bmp,assets\wizard-large-200.bmp
WizardSmallImageFile=assets\wizard-small-100.bmp,assets\wizard-small-200.bmp
; The release workflow defines these when signing secrets are configured, so that the uninstaller
; embedded in the setup is signed as well. Unsigned builds skip them.
#ifdef EnableSigning
SignTool=winguardsign
SignedUninstaller=yes
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
; The data folder and Logs are created and locked down in PrepareToInstall, before anything else
; happens. These entries find them there and change nothing.
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

{ Stop the service and poll `sc query` until it reports STOPPED or the service is
  gone. The stop is requested again on every poll that does not show it in
  progress: a service that is still starting refuses the request, and one request
  would then be waited out in vain. Returns False when it did not stop in time, or
  when its state cannot be read: the caller must not assume it is stopped. }
function StopServiceAndWait(): Boolean;
var
  Attempts: Integer;
  ResultCode: Integer;
  State: string;
begin
  Result := False;
  Attempts := 0;
  while Attempts < {#MyAppStopTimeoutSeconds} do
  begin
    if not ServiceExistsFlag() then
    begin
      Result := True;
      Exit;
    end;
    State := Uppercase(QueryServiceState());
    if Pos('STOPPED', State) > 0 then
    begin
      Result := True;
      Exit;
    end;
    if Pos('STOP_PENDING', State) = 0 then
      Exec(ExpandConstant('{sys}\sc.exe'), 'stop {#MyAppServiceName}', '',
        SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(1000);
    Attempts := Attempts + 1;
  end;
  Log('WinGuard: the service did not stop within {#MyAppStopTimeoutSeconds} seconds. Last state: ' + State);
end;

{ --- Data folder ----------------------------------------------------------- }

{ Leave the data folder to SYSTEM + Administrators alone, whoever created it, so no
  local standard user can pre-create it and poison the database. All the logic is in
  one tested place, the hidden verb "winguard-svc --harden-data", which --install
  runs as well (DataFolderHardener). It walks the folder without following a link,
  and moves aside what is a link or not owned by SYSTEM or Administrators before
  anything takes ownership of it.
  The installed program may be an older one, or not there yet, so the new one is
  unpacked to run it: it is the first file in [Files], and with solid compression
  that takes no time. Its output comes back through a file, as Exec cannot capture
  it. Exit codes: 0 secured, 3 secured with content moved aside, anything else not
  secured.
  Returns the reason it could not, or an empty string. }
function SecureDataFolder(): String;
var
  Dir: String;
  Tool: String;
  OutputFile: String;
  Contents: AnsiString;
  Details: String;
  ResultCode: Integer;
begin
  Result := '';
  Dir := ExpandConstant('{commonappdata}\WinGuard');
  Tool := ExpandConstant('{tmp}\{#MyAppServiceExe}');
  OutputFile := ExpandConstant('{tmp}\winguard-harden-data.txt');

  ExtractTemporaryFile('{#MyAppServiceExe}');
  if not Exec(ExpandConstant('{cmd}'), '/c ""' + Tool + '" --harden-data > "' + OutputFile + '" 2>&1"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    Result := 'Setup could not run ' + Tool + ' to secure the data folder ' + Dir +
      '. Nothing was installed.';
    Exit;
  end;

  Details := '';
  if LoadStringFromFile(OutputFile, Contents) then
    Details := Contents;
  Log('WinGuard: --harden-data exited with code ' + IntToStr(ResultCode) + ': ' + Details);

  if ResultCode = 3 then
    SuppressibleMsgBox('Setup found content in ' + Dir + ' that it could not trust, and moved it ' +
      'aside. Nothing was deleted. If it is yours, check it before you put it back:'#13#10#13#10 +
      Details, mbInformation, MB_OK, IDOK)
  else if ResultCode <> 0 then
    Result := 'Setup could not secure the data folder ' + Dir + '. Nothing was installed.'#13#10#13#10 +
      Details;
end;

{ --- Install --------------------------------------------------------------- }

{ A non-empty result stops Setup with that message before anything is installed
  (exit code 7 in silent mode). The data folder is secured once the service has
  stopped: a running service keeps its database and log open, and what is open
  cannot be moved aside, so a bad file there would stop every upgrade. If it fails,
  the service is started again, so protection stays as it was. }
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  { Close a running console first. It lives in the tray and turns a normal close
    request into "hide", so without this an upgrade can leave the OLD console
    running: its EXE cannot be replaced, and starting WinGuard afterwards only
    brings that old window back. taskkill returns non-zero when nothing is
    running, which is fine. }
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#MyAppExeName}', '',
    SW_HIDE, ewWaitUntilTerminated, ResultCode);

  { Stop any existing service before [Files] overwrites the running EXE. A service
    that will not stop keeps that EXE locked, so go no further and say so. }
  if ServiceExistsFlag() and not StopServiceAndWait() then
  begin
    Result := 'The {#MyAppServiceDisplayName} could not be stopped, so its files cannot be replaced. ' +
      'Nothing was installed. Stop it with "sc stop {#MyAppServiceName}" and run Setup again.';
    Exit;
  end;

  Result := SecureDataFolder();
  if (Result <> '') and ServiceExistsFlag() then
    Exec(ExpandConstant('{sys}\sc.exe'), 'start {#MyAppServiceName}', '',
      SW_HIDE, ewWaitUntilTerminated, ResultCode);
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
    { The console may still be running in the tray; close it so its EXE can be removed. }
    Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#MyAppExeName}', '',
      SW_HIDE, ewWaitUntilTerminated, ResultCode);

    { Stop the service and wait for STOPPED before deleting it, so clear-firewall
      runs against a quiet firewall and the binary can still be started here. }
    if ServiceExistsFlag then
    begin
      if not StopServiceAndWait() then
      begin
        Log('WinGuard: uninstalling while the service is still running.');
        if not UninstallSilent then
          MsgBox('The {#MyAppServiceDisplayName} could not be stopped. It is removed once it stops or ' +
            'after a restart; until then its firewall rules and files may remain.', mbError, MB_OK);
      end;
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