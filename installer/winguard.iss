; WinGuard — Inno Setup 6 script (PLAN.md §13)
; Build: ISCC.exe /DMyAppVersion=1.2.3 installer\winguard.iss
; Expects the published binaries staged in ..\dist\ (winguard-svc.exe,
; winguard-gui.exe, appsettings.json). The icon is optional.

#define MyAppName "WinGuard"
#ifndef MyAppVersion
  #define MyAppVersion "0.2.0"
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
; The data folder itself is created and locked down in PrepareToInstall, before anything else
; happens; Logs is created here and inherits from it.
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

{ True when the path is a junction or symbolic link ($400 is
  FILE_ATTRIBUTE_REPARSE_POINT). }
function IsReparsePoint(Path: String): Boolean;
var
  FindRec: TFindRec;
begin
  Result := False;
  if FindFirst(Path, FindRec) then
  begin
    Result := (FindRec.Attributes and $400) <> 0;
    FindClose(FindRec);
  end;
end;

function RunIcacls(Arguments: String): Boolean;
var
  ResultCode: Integer;
begin
  Result := Exec(ExpandConstant('{sys}\icacls.exe'), Arguments, '', SW_HIDE,
    ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
  if not Result then
    Log('WinGuard: icacls ' + Arguments + ' failed (code ' + IntToStr(ResultCode) + ').');
end;

{ Leave the data folder to SYSTEM + Administrators alone, whoever created it, so no
  local standard user can pre-create it and poison the database. The service's
  --install runs the same steps (Program.DataFolderHardeningSteps).
  - The owner goes first: an owner can always grant itself access again, whatever
    the ACL says.
  - /reset then removes explicit entries, which /grant:r would leave in place for
    every account it does not name. The accounts are given as SIDs (S-1-5-18 =
    SYSTEM, S-1-5-32-544 = Administrators) because their names are localized.
  - The second ownership pass also covers everything inside, including whatever
    was created until the ACL closed, and the last step makes all of it inherit.
  No /C: with it icacls exits 0 even when it failed.
  Returns the reason it could not, or an empty string. }
function SecureDataFolder(): String;
var
  Dir: String;
  Failure: String;
  Steps: array[0..4] of String;
  I: Integer;
begin
  Result := '';
  Dir := ExpandConstant('{commonappdata}\WinGuard');
  Failure := 'Setup could not secure the data folder ' + Dir + '. Nothing was installed. ' +
    'See the setup log for details.';

  { Hardening a link would change its target, and the service would write through it. }
  if DirExists(Dir) then
  begin
    if IsReparsePoint(Dir) then
    begin
      Result := Dir + ' is a link, not a folder, which may mean another user prepared it. ' +
        'Nothing was installed. Remove it and run Setup again.';
      Exit;
    end;
  end
  else if not ForceDirectories(Dir) then
  begin
    Result := Failure;
    Exit;
  end;

  Steps[0] := '"' + Dir + '" /setowner *S-1-5-32-544';
  Steps[1] := '"' + Dir + '" /reset';
  Steps[2] := '"' + Dir + '" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"';
  Steps[3] := '"' + Dir + '" /setowner *S-1-5-32-544 /T /L';
  Steps[4] := '"' + Dir + '\*" /reset /T /L';
  for I := 0 to 4 do
  begin
    if not RunIcacls(Steps[I]) then
    begin
      Result := Failure;
      Exit;
    end;
  end;
end;

{ --- Install --------------------------------------------------------------- }

{ A non-empty result stops Setup with that message before anything is changed
  (exit code 7 in silent mode). The data folder comes first, while a service that
  is being upgraded is still running: if this fails, protection stays as it was. }
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Result := SecureDataFolder();
  if Result <> '' then
    Exit;

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
    Result := 'The {#MyAppServiceDisplayName} could not be stopped, so its files cannot be replaced. ' +
      'Nothing was installed. Stop it with "sc stop {#MyAppServiceName}" and run Setup again.';
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