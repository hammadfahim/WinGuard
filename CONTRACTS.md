# WinGuard — Component Contracts (binding for all implementation agents)

This document pins the **public API surface** of every component so they can be built
in parallel. `PLAN.md` is the functional spec; this file is the coordination contract.
If your component CONSUMES another component, code against exactly these signatures.
If your component PROVIDES one, implement exactly these signatures (add private
helpers freely; add public members only if nothing else depends on the shape).

**Already implemented (do NOT edit):** `WinGuard.Core/Model/*`, `Abstractions/*`
(`IDetector`, `IFirewall`, `IStore`), `Config/*` (`WinGuardSettings`, `Defaults`),
`Ipc/Contracts.cs`, all `.csproj` files, `samples/logs/*`.

Conventions: file-scoped namespaces, nullable enabled, XML doc comments on public
members, all persistence/transport timestamps UTC, use `Microsoft.Extensions.Logging`
(`ILogger<T>`), no new NuGet packages beyond those already in the csproj files.

Time control: components that read "now" accept an optional
`TimeProvider? timeProvider = null` constructor parameter (default `TimeProvider.System`)
so tests can fake time.

---

## Agent A — `WinGuard.Core/Engine` + `WinGuard.Core/Store`

### `WinGuard.Core.Engine.IpMatcher` (Engine/IpMatcher.cs)

```csharp
public sealed class IpMatcher
{
    // Static helpers (used by detectors, engine, firewall, service):
    public static bool TryNormalize(string? raw, out string normalized);
        // accepts "1.2.3.4", "1.2.3.4:5678", "[::1]", "[2001:db8::1]:3389", "::1",
        // rejects "-", "", null, hostnames, firewall tokens ("LocalSubnet");
        // output: bare IP, IPv6 lowercased, no brackets/port. Uses IPAddress.TryParse
        // plus explicit port/bracket stripping. NEVER resolves DNS names.
    public static bool IsValid(string ip);                    // TryNormalize succeeds
    public static bool IsInternal(string normalizedIp);       // loopback, RFC1918, 169.254/16,
                                                              // IPv6 ::1/unique-local fc00::/7/link-local fe80::/10
    public static bool TryParseCidr(string cidr, out System.Net.IPNetwork network); // "1.2.3.0/24" or bare IP (/32, /128)
    public static IReadOnlyList<string> GetLocalAddresses();  // this machine's unicast IPs (auto-whitelist, PLAN §5)

    // Instance: list matching (entries are single IPs or CIDRs; invalid entries ignored):
    public IpMatcher(IEnumerable<string> whitelist, IEnumerable<string> blacklist);
    public bool IsWhitelisted(string normalizedIp);
    public bool IsBlacklisted(string normalizedIp);
    public static void AddRange(IPMatcher? matcher);          // NOT part of contract — ignore
}
```
Whitelist always wins over blacklist (PLAN §5). Matching supports IPv4 + IPv6.

### `WinGuard.Core.Engine.BanEngine` (Engine/BanEngine.cs)

```csharp
public sealed class BanEngine
{
    public BanEngine(IStore store, IFirewall firewall,
                     Func<WinGuardSettings> settingsAccessor,
                     ILogger<BanEngine> logger,
                     TimeProvider? timeProvider = null);

    public Task StartAsync(CancellationToken ct);
        // startup: if ClearBansOnStartup -> firewall.ClearAll() + store ban cleanup;
        // else firewall.SyncRules(await store.GetActiveBansAsync())  (self-heal, PLAN §11);
        // auto-whitelist IpMatcher.GetLocalAddresses() into the in-memory whitelist;
        // starts the housekeeping periodic timer (settings().HousekeepingInterval).

    public Task ProcessAsync(FailedLogin failed, CancellationToken ct = default);
        // PLAN §5 steps 1-7 exactly. De-dup: if failed.Source == Rdp and the store has a
        // previous Rdp FailedLogin for the same ip within 2 seconds (either direction),
        // skip (4625 + RdpCoreTS 140 double-count, PLAN §4.2).

    public Task RunAsync(ChannelReader<FailedLogin> reader, CancellationToken ct);
        // await foreach over reader -> ProcessAsync; swallow+log per-item exceptions.

    public Task HousekeepOnceAsync(CancellationToken ct = default);
        // expire due bans (unblock+remove+event "UNBANNED"), prune failed_logins older
        // than ExpireTime, reconcile firewall vs active bans (PLAN §5 housekeeping).

    public Task BanNowAsync(string ip, TimeSpan? duration, bool permanent, string? note,
                            CancellationToken ct = default);   // manual block via IPC
    public Task UnbanAsync(string ip, CancellationToken ct = default); // manual unblock
    public Task<int> GetActiveBanCountAsync(CancellationToken ct = default);
    public Task StopAsync(CancellationToken ct = default);    // stop timer
}
```
Events recorded to the store (via `IStore.AddEventAsync`) with messages starting with
stable prefixes: `"BLOCKED {ip} for {duration} (offense #{n})"`, `"UNBANNED {ip}"`,
`"SKIPPED {ip} (whitelist)"`, `"MANUAL BLOCK {ip}"`, `"MANUAL UNBLOCK {ip}"`.

### `WinGuard.Core.Store.SqliteStore` (Store/SqliteStore.cs)

```csharp
public sealed class SqliteStore : IStore, IAsyncDisposable
{
    public SqliteStore(string databasePath, ILogger<SqliteStore> logger);
    // Implements IStore exactly as declared. Schema per PLAN §3. Serializes access with
    // a SemaphoreSlim(1,1); connection per operation or one guarded connection.
    // Settings: single row key "engine" holding the whole WinGuardSettings JSON blob
    // (GetAllSettingsAsync returns that row; SetSettingAsync upserts key/value).
}
```

---

## Agent B — `WinGuard.Core/Detection`

All detectors: `[SupportedOSPlatform("windows")]` where they touch EventLogWatcher;
`StartAsync` subscribes/loops and returns promptly; failures are written with
`sink.Writer.TryWrite(failed)`; every detector logs and never throws out of StartAsync
on subscription failure (channel may not exist, e.g. no RDP role) — degrade gracefully
and record why via logger.

Shared file-tailing infrastructure may live in `Detection/LogFileTailer.cs`;
exclusion-rule evaluation in `Detection/ExclusionEvaluator.cs`.

### Static parser APIs (pure — unit-tested against `samples/logs/`, see its README.md)

```csharp
public sealed class RdpSecurityLogDetector : IDetector   // Detection/RdpSecurityLogDetector.cs
{
    public RdpSecurityLogDetector(Func<WinGuardSettings> settingsAccessor,
                                  ILogger<RdpSecurityLogDetector> logger,
                                  TimeProvider? timeProvider = null);
    public static bool TryParse(string eventXml, WinGuardSettings settings, out FailedLogin? failed);
        // XPath/XmlDocument parse of the 4625 record; EventID must be 4625; IP from
        // EventData/Data[@Name='IpAddress']; drop when '-' / empty / invalid; user from
        // TargetUserName; ts from System/TimeCreated/@SystemTime; applies
        // settings.Rdp.ExclusionRules via ExclusionEvaluator; RawLog = compact one-line summary.
}

public sealed class RdpCoreTsDetector : IDetector        // Detection/RdpCoreTsDetector.cs
{
    public static bool TryParse(string eventXml, out FailedLogin? failed);
        // EventID 140, IP from Data[@Name='IPString'], user null, Source Rdp.
}

public sealed class MsSqlDetector : IDetector            // Detection/MsSqlDetector.cs
{
    public static bool TryParse(string eventXml, string? formattedMessage,
                                WinGuardSettings settings, out FailedLogin? failed);
        // Provider name contains "MSSQL"; EventID 18456; user = EventData/Data[0];
        // IP via regex \[CLIENT:\s*(?<ip>[^\]]+)\] on formattedMessage (fall back to
        // searching eventXml if message null); skip when formattedMessage contains any
        // settings.MsSql.IgnoreMessagePatterns substring.
}

public sealed class FtpLogDetector : IDetector           // Detection/FtpLogDetector.cs
{
    public FtpLogDetector(Func<WinGuardSettings> settingsAccessor,
                          ILogger<FtpLogDetector> logger, TimeProvider? timeProvider = null);
    public static bool TryParseIisLine(string line, string? fieldsHeaderLine, out FailedLogin? failed);
        // fieldsHeaderLine = the latest "#Fields:" line (may be null -> assume default
        // W3C order). Flag cs-method == "PASS" && sc-status == "530"; ip = c-ip;
        // user = cs-username when not "-".
    public static bool TryParseFileZillaLine(string line, out FailedLogin? failed);
        // line contains "530 Login or password incorrect!" -> IP = last "(x.x.x.x)" or
        // "(ipv6)" token before '>' ; user from "(name (ip)>" when not "not logged in".
    // Polling: settings().Ftp.Sources (folder for IIS: *.log files; file-or-folder for
    // FileZilla), PollInterval, byte-offset tracking + rotation (file shrank -> reset),
    // never re-emit lines already counted in this process run.
}

public sealed class CustomLogDetector : IDetector        // Detection/CustomLogDetector.cs
{
    public static bool TryParseLine(string line, string regexPattern, out FailedLogin? failed);
        // regex with named groups ipaddress (required) / username (optional);
        // one match per line max; Source = Custom; tailing like FtpLogDetector over
        // settings().CustomSources (PathGlob = file or folder+glob).
}
```

Event-log subscription XPath queries: exactly the ones in PLAN §4.1/§4.2/§4.3.
For MSSQL, if the provider `contains()` XPath fails at runtime, subscribe on EventID
only and filter provider in code (PLAN §4.3 fallback). Timestamps: parse
`SystemTime` as UTC round-trip.

### `WinGuard.Core.Detection.ExclusionEvaluator`

```csharp
public static class ExclusionEvaluator
{
    // rules: OR between entries, AND between ',' conditions, "Field=value" /
    // "Field!=value", '*' wildcard in value, case-insensitive field lookup over
    // 4625 EventData Name->value pairs. PLAN §6.
    public static bool IsExcluded(IReadOnlyDictionary<string, string> eventData, IEnumerable<string> rules);
    public static bool MatchesWildcard(string input, string pattern); // '*' = any run
}
```

---

## Agent C — `WinGuard.Core/Firewall` + `WinGuard.Service`

### `WinGuard.Core.Firewall.WindowsFirewall` (Firewall/WindowsFirewall.cs)

```csharp
[SupportedOSPlatform("windows")]
public sealed class WindowsFirewall : IFirewall
{
    public WindowsFirewall(ILogger<WindowsFirewall> logger, int maxAddressesPerRule = Defaults.MaxAddressesPerRule);
    // COM interop via Type.GetTypeFromProgID("HNetCfg.FwPolicy2") + dynamic
    // (no interop assembly, no netsh). Rules: name WinGuard_Block_0001..., Direction=In,
    // Action=Block, Enabled=true, Profiles=All (0x7FFFFFFF), Protocol=Any (256),
    // RemoteAddresses = comma-joined batch (<= maxAddressesPerRule). Validate every IP
    // with IpMatcher.IsValid before adding (PLAN §11 - reject "LocalSubnet" injection).
    // IsServiceRunning(): check MpsSvc service status.
}
```

### `WinGuard.Service` (owns whole project; Program.cs, GuardWorker.cs, Ipc/PipeServer.cs, appsettings.json)

- `Program.cs`: CLI verbs (PLAN §13): `--install` (sc create delayed-auto + description +
  failure restart actions + start), `--uninstall` (stop + delete), `--console`
  (run host in console), `--clear-firewall` (WindowsFirewall.ClearAll then exit 0),
  no args = `UseWindowsService()` host. Logging to
  `%ProgramData%\WinGuard\Logs\winguard-*.log` (simple file logger provider of your own,
  or console+EventLog; no new packages).
- DI: `SqliteStore` (path from appsettings `DatabasePath`, default `Defaults.DatabasePath`)
  as singleton `IStore`; `WindowsFirewall` as singleton `IFirewall`; a mutable
  `SettingsHolder` singleton exposing `Func<WinGuardSettings> Current` (loaded from store
  "engine" JSON at startup, else Defaults; `UpdateSettings` replaces + persists it);
  all five detectors registered as `IDetector`; `BanEngine` singleton; `GuardWorker` +
  `PipeServer` as `IHostedService`.
- `GuardWorker.cs`: creates `Channel.CreateUnbounded<FailedLogin>()`, starts enabled
  detectors (`StartAsync(sink/channel, ct)`), runs `engine.StartAsync` then
  `engine.RunAsync(channel.Reader, ct)`.
- `Ipc/PipeServer.cs`: `NamedPipeServerStream` on `PipeConstants.PipeName`,
  PipeDirection.InOut, async accept loop, PipeSecurity Administrators+LocalSystem only,
  JSON-lines per `Core/Ipc/Contracts.cs`; dispatch all `IpcMethods`; `GetStatus` builds
  `ServiceStatusDto` (version = assembly version, per-engine enabled from settings +
  DetectionsToday from `IStore.CountFailedLoginsSinceAsync(localMidnightUtc)`, ActiveBans
  per engine from store bans); `CheckPrereqs` fills `PrereqsDto` (auditpol query via
  reading `auditpol /get /subcategory:"Logon" /r` output or event-log probe — document
  choice; firewall via `IFirewall.IsServiceRunning()`; RdpCoreTS channel via
  `EventLogSession`/`EventLogConfiguration` enabled check).
- `appsettings.json`: `{ "DatabasePath": null, "PipeName": "WinGuard", "Logging": { "LogLevel": { "Default": "Information" } } }`
  (null DatabasePath = Defaults.DatabasePath).

---

## Agent D — `WinGuard.Gui` (owns whole project)

WPF + CommunityToolkit.Mvvm (MVVM). `net10.0-windows`, `UseWPF` + `UseWindowsForms`
(tray `NotifyIcon` only). Files: `App.xaml(.cs)`, `MainWindow.xaml(.cs)`,
`Views/{Dashboard,BlockedIps,EventLogView,SettingsView,ListsView}.xaml(.cs)` (UserControls),
`ViewModels/*`, `Services/PipeClient.cs`, `Services/TrayIconService.cs`,
`Themes/{Dark,Light}.xaml` (ResourceDictionaries) with a toggle.

- `PipeClient`: connects `\\.\pipe\WinGuard` (`PipeConstants.PipeName`), JSON-lines per
  `Core/Ipc/Contracts.cs`, `Task<TResponse> CallAsync(string method, object? params,
  CancellationToken)` with 5 s timeout + auto-reconnect; `bool IsConnected`;
  surfaces "service not running" state (Dashboard shows Start-service button that
  launches an elevated `sc start WinGuardService` via `ProcessStartInfo` Verb=runas).
- Polling: `DispatcherTimer` ~2 s for GetStatus/ListEvents/ListBans refresh (only while
  connected and window visible). All display times converted UTC -> local.
- Views per PLAN §9 (Dashboard tiles + toggles, Blocked IPs grid + context menu
  Unblock / Unblock & Whitelist / Promote to permanent + filter + CSV export via
  SaveFileDialog, Event Log live feed + level/source filters + auto-scroll, Settings
  editor bound to WinGuardSettings incl. 24h/7d/30d tier presets, Lists editor for
  whitelist/blacklist add/remove).
- Tray: closing window hides to tray; tray menu Show / Exit. Icon: draw a simple
  shield at runtime with System.Drawing (no binary assets committed).
- GUI is NOT elevated; all privileged ops go through the service pipe (PLAN §8/§9).

---

## Agent E — tests + installer + CI + docs

- `tests/WinGuard.Core.Tests` (owns csproj too): xUnit, no admin needed.
  - `Fakes/FakeFirewall.cs` (in-memory IFirewall, records calls), `Fakes/FakeTimeProvider.cs`
    (subclass TimeProvider, settable UtcNow), `Fakes/FakeStore.cs` (in-memory IStore).
  - Parser tests read fixtures from `samples/` next to the test assembly (already
    configured in csproj via Content/Link) — assert exactly the table in
    `samples/logs/README.md`.
  - `IpMatcherTests`: IPv4/IPv6/CIDR membership, port/bracket stripping, reject
    non-IP tokens (`LocalSubnet`, hostnames, `-`), IsInternal cases.
  - `BanEngineTests`: threshold crossing, rolling window, tier escalation 24h->7d->30d
    (FakeTimeProvider), whitelist/blacklist precedence, counter reset after ban,
    Rdp de-dup within 2 s, expiry auto-unblock, permanent blacklist ban,
    internal-IP skip (ProcessInternalIPs=false).
  - `WindowsFirewallIntegrationTests` with `[Trait("Category","Integration")]`
    (`[SupportedOSPlatform("windows")]`, skipped in CI by filter).
- `installer/winguard.iss` per PLAN §13 (Inno Setup 6; service create/start delayed-auto,
  failure actions, audit policy checkbox, shortcuts, uninstall incl.
  `--clear-firewall`, `PrivilegesRequired=admin`, `ArchitecturesInstallIn64BitMode=x64`,
  version via `/DMyAppVersion=`). `installer/assets/license.txt` = MIT.
  `installer/assets/icon.ico` OPTIONAL — do not commit binary; script must tolerate
  its absence (`#if FileExists`).
- `.github/workflows/ci.yml` + `release.yml` exactly per PLAN §14 (checkout@v5,
  setup-dotnet@v5 10.0.x, test filter `Category!=Integration`, publish single-file
  self-contained win-x64, ISCC build, portable zip, softprops/action-gh-release@v2).
- `README.md` per PLAN §17 outline + `LICENSE` (MIT).

---

## Cross-cutting rules

1. **Never edit files you don't own.** If something you need is missing from Core
   contracts/csproj, WORK AROUND locally if possible and REPORT it in your final
   summary — the integrator will reconcile.
2. **Do not run `dotnet build`/`dotnet test`/`git`** — parallel agents share this
   working tree; the integrator builds after everyone finishes. Write code carefully.
3. Match the fixture expectations in `samples/logs/README.md` exactly.
4. No new NuGet packages; no TODO stubs in public behavior — implement fully.
