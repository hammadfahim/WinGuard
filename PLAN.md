# WinGuard — RdpGuard-style Intrusion Prevention for Windows (.NET 10)

An execution plan for building a minimal, open-source **fail2ban-for-Windows**: a
background Windows **service** that reads failed-login events and **blocks attacker
IPs in the firewall** for a configurable duration, plus a **desktop GUI** to watch
and manage it. Built on **.NET 10**, shipped as an **EXE + installer** via **GitHub
Actions**.

This document is self-contained. Hand it to any competent .NET developer (or an AI
coding agent) and it can be executed step by step without further research.

---

## 0. Scope

### In scope (MVP main functions)
1. **Detect** failed logins for four protocols:
   - **RDP** (Remote Desktop) — Security log event **4625** + RdpCoreTS **140** fallback.
   - **MS SQL Server** — Application log event **18456**.
   - **FTP** — IIS FTP / FileZilla Server log files.
   - A generic **custom-log** source so other services can be added without code.
2. **Block** the offending IP in the Windows firewall after N failed attempts within a
   rolling window.
3. **Time-based blocking** with presets: **24 hours, 7 days, 30 days**, plus custom and
   permanent (blacklist).
4. **Auto-unblock** when the ban expires.
5. **Whitelist / Blacklist** of IPs, CIDR ranges.
6. **Desktop GUI** showing status, blocked IPs, and a live event log; manual
   block/unblock; edit settings.
7. **Windows Service** doing all detection/blocking, running headless at boot.
8. **Build pipeline**: single-file self-contained EXEs + an installer, produced by
   **GitHub Actions**, attached to a **GitHub Release**.

### Explicitly out of scope for MVP (leave hooks, don't build)
- IP Cloud / shared threat intelligence.
- Geo-IP country blocking.
- IMAP/POP3/SMTP/SSH/VNC/RRAS/HTTP engines (the architecture supports them; ship later).
- Licensing/activation, auto-update, email/Telegram notifications.
- Traffic sniffing (WinPcap/Npcap). MVP is **log/event based only**.

### Design reference
This is a clean-room reimplementation modeled on **RdpGuard**'s observable behavior
(detection sources, block durations, whitelist/blacklist, service+GUI split). The
detection details below are verified against public Microsoft event documentation and
the MIT-licensed **DigitalRuby/IPBan** project, which uses the same event sources. Do
**not** copy RdpGuard's proprietary code, assets, or trademarked name — this is an
independent implementation.

---

## 1. Target platform & tech choices

| Concern | Decision | Notes |
|---|---|---|
| Runtime | **.NET 10** (LTS) | Latest servicing release at build time (10.0.10+ as of Oct 2026). |
| Language | C# 14 | `<LangVersion>latest` |
| OS support | **Windows Server 2016+ / Windows 10+ (x64)** | 4625 + RdpCoreTS reliable here; NLA works. Don't promise Server 2012/2008. |
| Service host | `Microsoft.Extensions.Hosting.WindowsServices` | `BackgroundService`, DI, config, logging out of the box. |
| GUI | **WPF** (`net10.0-windows`, `<UseWPF>true`) | Mature, designer-free XAML; WinUI 3 is heavier for an MVP. |
| Event reading | `System.Diagnostics.Eventing.Reader` (`EventLogWatcher`) | Push-based subscription per channel — near-instant, low CPU. |
| Firewall | **Windows Firewall COM API** (`FirewallAPI.dll`, `INetFwPolicy2`) via COM interop | Create block rules with `RemoteAddresses`. No external deps. |
| Config/state store | **SQLite** (`Microsoft.Data.Sqlite`) | Single file in `%ProgramData%`. Survives restarts; easy export. |
| IPC (GUI↔service) | **Named pipe** JSON-RPC (`System.IO.Pipes`) | Localhost, admin-only ACL. |
| Installer | **Inno Setup 6** | Free, scriptable, installs+starts the service, preinstalled on GitHub runners. |
| CI/CD | **GitHub Actions** (`windows-latest`) | `dotnet publish` → `iscc` → upload to Release. |
| Packaging | Self-contained, single-file, `win-x64` | No .NET install required on target servers. |

> **CPU model note:** event-log reads are push-based, not polled; file-based (FTP) logs
> are polled on an interval. This matches how real tools behave — see §4.3.

---

## 2. Solution layout

```
winguard/
├─ WinGuard.sln
├─ Directory.Build.props              # shared props: TFM vars, version, nullable, langversion
├─ global.json                        # pin SDK 10.0.x
├─ src/
│  ├─ WinGuard.Core/                  # class lib, net10.0 — all logic, no UI/host
│  │  ├─ Model/
│  │  │  ├─ FailedLogin.cs            # IP, user, source, timestampUtc, rawLog
│  │  │  ├─ BanEntry.cs               # IP, source, bannedAtUtc, expiresUtc, offenseCount, isPermanent
│  │  │  ├─ ProtocolSource.cs         # enum: Rdp, MsSql, Ftp, Custom
│  │  │  └─ LogEvent.cs               # for the GUI event feed
│  │  ├─ Abstractions/
│  │  │  ├─ IDetector.cs              # StartAsync(Channel<FailedLogin> sink, CancellationToken)
│  │  │  ├─ IFirewall.cs              # Block(ip)/Unblock(ip)/SyncRules(IEnumerable<BanEntry>)/ListBlocked()
│  │  │  └─ IStore.cs                 # persistence contract
│  │  ├─ Detection/
│  │  │  ├─ RdpSecurityLogDetector.cs # Security 4625
│  │  │  ├─ RdpCoreTsDetector.cs      # RdpCoreTS/Operational 140 (TLS/NLA fallback)
│  │  │  ├─ MsSqlDetector.cs          # Application 18456
│  │  │  ├─ FtpLogDetector.cs         # IIS/FileZilla log files
│  │  │  └─ CustomLogDetector.cs      # generic regex log tail
│  │  ├─ Engine/
│  │  │  ├─ BanEngine.cs              # counting, thresholds, windows, escalation, expiry
│  │  │  └─ IpMatcher.cs              # IP/CIDR parse + whitelist/blacklist match (IPv4+IPv6)
│  │  ├─ Firewall/
│  │  │  └─ WindowsFirewall.cs        # COM INetFwPolicy2 implementation of IFirewall
│  │  ├─ Store/
│  │  │  └─ SqliteStore.cs            # bans, failed-login counters, settings, event log
│  │  └─ Config/
│  │     ├─ WinGuardSettings.cs       # strongly-typed settings
│  │     └─ Defaults.cs
│  ├─ WinGuard.Service/               # exe, net10.0, Windows Service host
│  │  ├─ Program.cs                   # Host builder, DI, UseWindowsService()
│  │  ├─ GuardWorker.cs               # BackgroundService: wires detectors→engine→firewall
│  │  ├─ Ipc/
│  │  │  ├─ PipeServer.cs             # named-pipe JSON-RPC server
│  │  │  └─ Contracts.cs              # request/response DTOs (shared w/ GUI via Core or a shared lib)
│  │  └─ appsettings.json
│  ├─ WinGuard.Gui/                   # exe, net10.0-windows, WPF
│  │  ├─ App.xaml / App.xaml.cs
│  │  ├─ MainWindow.xaml              # dashboard + tabs
│  │  ├─ Views/ (Dashboard, BlockedIps, EventLog, Settings, Lists)
│  │  ├─ ViewModels/
│  │  └─ Services/PipeClient.cs       # talks to the service
│  └─ WinGuard.Shared/                # (optional) IPC DTOs shared by Service + Gui
├─ tests/
│  └─ WinGuard.Core.Tests/           # xUnit: parsers, ban engine, IP matcher
├─ installer/
│  ├─ winguard.iss                    # Inno Setup script
│  └─ assets/ (icon.ico, license.txt)
├─ samples/
│  └─ logs/                           # sample 4625 XML, 18456, IIS FTP, FileZilla lines for tests
└─ .github/workflows/
   ├─ ci.yml                          # build + test on push/PR
   └─ release.yml                     # tag → publish → installer → GitHub Release
```

---

## 3. Data model

### `FailedLogin`
```
string  IpAddress        // normalized (no port), IPv4 or IPv6
string? UserName          // may be null
ProtocolSource Source     // Rdp | MsSql | Ftp | Custom
DateTime TimestampUtc
string  RawLog            // the matched log/event text, for the UI feed
```

### `BanEntry`
```
string   IpAddress        // primary key
ProtocolSource Source     // which engine first triggered it
DateTime BannedAtUtc
DateTime ExpiresUtc       // = BannedAtUtc + current tier; for permanent, DateTime.MaxValue
int      OffenseCount     // how many times this IP has crossed threshold (for escalation)
bool     IsPermanent      // from blacklist
string?  Note
```

### SQLite schema
```sql
CREATE TABLE IF NOT EXISTS failed_logins (
  ip TEXT NOT NULL, source INTEGER NOT NULL, ts_utc TEXT NOT NULL,
  user TEXT, raw TEXT
);
CREATE INDEX IF NOT EXISTS ix_fl_ip_ts ON failed_logins(ip, ts_utc);

CREATE TABLE IF NOT EXISTS bans (
  ip TEXT PRIMARY KEY, source INTEGER NOT NULL,
  banned_at_utc TEXT NOT NULL, expires_utc TEXT NOT NULL,
  offense_count INTEGER NOT NULL DEFAULT 1,
  is_permanent INTEGER NOT NULL DEFAULT 0, note TEXT
);

CREATE TABLE IF NOT EXISTS lists (
  value TEXT NOT NULL,            -- ip or CIDR
  kind  INTEGER NOT NULL          -- 0 = whitelist, 1 = blacklist
);

CREATE TABLE IF NOT EXISTS events (
  ts_utc TEXT NOT NULL, level INTEGER NOT NULL,
  source INTEGER, ip TEXT, message TEXT
);

CREATE TABLE IF NOT EXISTS settings ( key TEXT PRIMARY KEY, value TEXT NOT NULL );
```

Location: `%ProgramData%\WinGuard\winguard.db`. Logs: `%ProgramData%\WinGuard\Logs\`.

---

## 4. Detection engines

All detectors implement `IDetector` and push `FailedLogin` objects into a single
`System.Threading.Channels.Channel<FailedLogin>` that the `BanEngine` consumes. This
decouples "how we noticed" from "what we do about it."

### 4.1 RDP — Security log event 4625 (primary)
- **Channel:** `Security`. **Event ID:** `4625` (an account failed to log on).
- **Subscription query** (XPath), audit-failure keyword included:
  ```xml
  <QueryList>
    <Query Id="0" Path="Security">
      <Select Path="Security">
        *[System[(EventID=4625) and (band(Keywords,0x8010000000000000))]]
      </Select>
    </Query>
  </QueryList>
  ```
- **Extract IP** from EventData node `IpAddress`. If `IpAddress` is `-` or empty, drop
  the event (can't block an unknown IP) and let the RdpCoreTS detector catch the TLS case.
- **Fields available in 4625 EventData** (for exclusions): `TargetUserName`,
  `IpAddress`, `IpPort`, `LogonType`, `Status`, `SubStatus`, `FailureReason`,
  `WorkstationName`, `ProcessName`, `AuthenticationPackageName`, etc.
- **Note:** 4625 fires for *all* failed logons (RDP, network shares, scheduled tasks,
  local elevation). MVP treats any 4625-with-IP as a failed attempt. Exclusions (§6)
  let the admin filter out noise (e.g. local accounts).
- **Prerequisite:** audit of logon failures must be enabled:
  `auditpol /set /subcategory:"Logon" /success:enable /failure:enable`
  The installer and the GUI "Audit check" both run/verify this.

### 4.2 RDP — RdpCoreTS/Operational event 140 (TLS/NLA fallback)
- **Channel:** `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational`.
- **Event ID:** `140` — "A connection ... failed; bad username or password" (logs the
  client IP even when 4625 has an empty source over TLS).
- **Query:**
  ```xml
  <QueryList>
    <Query Id="0" Path="Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational">
      <Select Path="Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational">
        *[System[(EventID=140)]]
      </Select>
    </Query>
  </QueryList>
  ```
- **Extract IP** from EventData `Data[@Name='IPString']` (field name is `IPString` on
  RdpCoreTS 140).
- **De-dup:** the same failed attempt can appear as both 4625 and 140. Dedup in the
  engine by `(ip, source=Rdp, timestamp±2s)` so one attempt counts once.

### 4.3 MS SQL Server — Application event 18456
- **Channel:** `Application`. **Event ID:** `18456`. **Provider name** contains `MSSQL`
  (e.g. `MSSQLSERVER` or `MSSQL$INSTANCE`).
- **Query:**
  ```xml
  <QueryList>
    <Query Id="0" Path="Application">
      <Select Path="Application">
        *[System[(EventID=18456)]] and *[System[Provider[contains(@Name,'MSSQL')]]]
      </Select>
    </Query>
  </QueryList>
  ```
  (If the XPath `contains()` on Provider is rejected by the channel, subscribe on
  EventID only and filter the provider in code.)
- **Extract IP:** the client IP is in the event message as `[CLIENT: a.b.c.d]`.
  Regex: `\[CLIENT:\s*(?<ip>[^\]]+)\]`. Username is `Data[0]`.
- **Ignore** non-bruteforce 18456 reasons such as "Failed to open the explicitly
  specified database" (legit app pointing at a missing DB). Default ignore-regex on the
  reason text; configurable.
- **Prerequisite:** SQL Server login auditing must include failed logins —
  SSMS → Server Properties → Security → Login auditing → *Failed logins only* (or both),
  then restart the instance. The GUI surfaces this requirement; it cannot be toggled
  remotely without SQL permissions, so just document + detect absence of events.

### 4.4 FTP — log files
IIS FTP and FileZilla don't write failed logins to the event log, so this engine
**tails log files**.

- **IIS FTP (FTPSVC):** W3C logs under e.g. `C:\inetpub\logs\LogFiles\FTPSVC1\`.
  A failed password is status **530** on the `PASS` command. W3C log lines are
  space-separated with a `#Fields:` header that declares column order — parse the header,
  find `c-ip` and `sc-status` and `cs-method`, flag lines where method=`PASS` and
  status=`530`. Extract `c-ip`.
- **FileZilla Server:** text log; a failed login line contains `530 Login or password
  incorrect!` preceded by the session's IP. Parse the IP token and the 530 marker.
- **Config:** list of log folders (IIS) or a log file/folder (FileZilla), plus which
  server type. Poll interval default **3 s**; track file offset + handle rotation
  (reset offset when file shrinks / new dated file appears). Cap re-read at a max file
  size, re-open on rotation.
- **FTPS note:** encrypted sessions still log to the server's own file, so log-based
  detection works for FTPS too (unlike traffic sniffing).

### 4.5 Custom log source (generic)
- A configurable entry: `{ folder/glob, regex-with-named-groups(ipaddress,username) }`.
- Lets the admin add any service that writes an IP to a text log without new code.
- Same tailing machinery as the FTP file detector.

---

## 5. Ban engine (the fail2ban core)

`BanEngine` consumes the `FailedLogin` channel and owns all policy.

### Algorithm (per incoming failed login)
```
1. Normalize IP (strip port, lowercase IPv6, reject invalid).
2. If IP matches Whitelist  -> record event "skipped (whitelist)", return.
3. If IP matches Blacklist  -> ensure permanent ban exists, return.
4. If IP already actively banned -> record event, return (rule already in firewall).
5. Append to failed_logins(ip, source, tsUtc, user, raw).
6. count = failed_logins for this IP within the rolling CountWindow (default 10 min)
           and newer than the last reset.
7. If count >= FailedLoginThreshold (default 5):
     offense = previous offense_count for this IP + 1
     duration = BanTiers[min(offense-1, BanTiers.Length-1)]   // escalation
     expiresUtc = nowUtc + duration
     upsert bans(ip, source, now, expiresUtc, offense, perm=false)
     firewall.Block(ip)
     clear this IP's failed_logins counter (so it starts fresh next tier)
     record event "BLOCKED ip for {duration} (offense #{offense})"
```

### Expiry / housekeeping (timer, default every 15 s)
```
- For each ban where not permanent and expiresUtc <= nowUtc:
    firewall.Unblock(ip); delete from bans; record "UNBANNED ip".
- Forget stale failed_logins older than ExpireTime (default 24h) -> counter resets.
- Reconcile: ensure every active ban still has a firewall rule (self-heal after reboot).
```

### Settings (defaults chosen to match common tools)
| Setting | Default | Meaning |
|---|---|---|
| `FailedLoginThreshold` | `5` | attempts before a ban |
| `CountWindow` | `00:10:00` | window in which attempts are counted |
| `ExpireTime` | `1.00:00:00` | idle time after which the counter resets |
| `BanTiers` | `[24:00:00, 7.00:00:00, 30.00:00:00]` | **24h → 7d → 30d** escalation |
| `MaxBanDuration` | `365.00:00:00` | cap (permanent is separate via blacklist) |
| `HousekeepingInterval` | `00:00:15` | expiry/reconcile cadence |
| `ClearBansOnStartup` | `false` | if true, flush firewall rules at service start |
| `ProcessInternalIPs` | `false` | ignore RFC1918/loopback/link-local by default |

The three required durations (**24h, 7d, 30d**) are the default `BanTiers`. An admin can
pick a single fixed duration instead (set one tier) or enable escalation (all three).
Per-protocol threshold overrides are allowed (`Rdp.Threshold`, etc.).

### IP matching (`IpMatcher`)
- Parse IPv4, IPv6, and CIDR (`System.Net.IPNetwork` in .NET 10).
- Whitelist always wins over blacklist and over any ban.
- Auto-whitelist the machine's own IPs + loopback at startup to avoid self-lockout.

---

## 6. Exclusions (noise reduction)

Mirror RdpGuard's exclusion feature so legit failures don't cause bans:
- **RDP (4625):** key=value rules over EventData fields with `=` / `!=` and `*`
  wildcards, OR between rules, AND between conditions in a rule. Example:
  `LogonType=2, IpAddress=127.0.0.1` or `TargetUserName=backup-svc`.
- **MS SQL (18456):** literal substring patterns matched against the event message
  (e.g. ignore a known app's reason text).
- Stored in `settings`; evaluated in the detector before handing off to the engine.

---

## 7. Firewall layer

### Approach
Use the **Windows Firewall with Advanced Security COM API** (`INetFwPolicy2`,
`INetFwRule`) via COM interop (`Type.GetTypeFromProgID("HNetCfg.FwPolicy2")`). No
`netsh` shelling, no external packages.

### Rule strategy (important for scale)
- One (or a few) **block rules** named with a fixed prefix: `WinGuard_Block_0001`, etc.
- Each rule's `RemoteAddresses` holds a **batch of up to ~1000 IPs** (Windows firewall
  practical limit per rule is ~1000 addresses). When a batch is full, create the next
  numbered rule. This keeps rule count low and performance high.
- Rule settings: `Direction = In`, `Action = Block`, `Enabled = true`,
  `Profiles = All`, `Protocol = Any`, `RemoteAddresses = csv of IPs/CIDRs`.
- **Block all ports by default** (one condition per IP). Optional "block only these
  ports" mode exists but warn in the UI that it multiplies firewall conditions
  (N ports × IPs) and hurts performance — default stays all-ports.
- Windows Firewall does **not** need to be "on" for the rule object model, but for the
  block to take effect the Windows Defender Firewall service must be running. Detect and
  warn if disabled. (RdpGuard uses WFP directly to bypass this; for MVP the firewall API
  is simpler and sufficient — document the dependency.)

### `IFirewall` operations
```
void Block(string ip)                 // add ip to a batch rule (create if needed)
void Unblock(string ip)               // remove ip from whichever rule holds it
void SyncRules(IEnumerable<BanEntry>)  // rebuild batch rules from DB (startup reconcile)
IReadOnlyList<string> ListBlocked()    // read back from rules
void ClearAll()                        // delete all WinGuard_* rules
```

### Windows Server 2025 note
Server 2025 changed firewall internals; the COM API still works but test explicitly on
2025. (This is the same break that forced IPBan 2.0.1.) Keep the firewall code behind
`IFirewall` so a WFP-based implementation can replace it later without touching the engine.

---

## 8. Service ↔ GUI (IPC)

- Service hosts a **named pipe** `\\.\pipe\WinGuard` with a JSON line protocol.
- Pipe ACL: allow Administrators + LocalSystem only.
- Requests the GUI can send:
  - `GetStatus` → service state, per-protocol enabled/active, counts.
  - `ListBans` / `ListEvents(limit)` / `ListLists`.
  - `Unblock(ip)` / `BlockNow(ip, duration|permanent)` / `WhitelistAdd` / `BlacklistAdd` / `ListRemove`.
  - `GetSettings` / `UpdateSettings(json)` (engine hot-reloads).
  - `CheckPrereqs` → audit policy state, SQL auditing hint, firewall service state.
- The GUI never touches the DB or firewall directly — the **service is the single writer**.
- If the service is stopped, the GUI shows "service not running" with a Start button
  (ask for elevation).

---

## 9. Desktop GUI (WPF)

MVM pattern (CommunityToolkit.Mvvm). Dark/light theme.

**Views**
1. **Dashboard** — service status pill; per-protocol tiles (RDP / MS-SQL / FTP /
   Custom) each showing enabled + today's detections + blocked count; a toggle to
   enable/disable each engine; recent activity strip.
2. **Blocked IPs** — grid: IP · Source · Banned (local) · Expires (local) · Offense ·
   Note. Right-click: *Unblock*, *Unblock & Whitelist*, *Promote to permanent*. Filter
   box; export to CSV.
3. **Event Log** — live feed (level, time, source, IP, message) from the `events`
   table; auto-scroll; filter by level/source.
4. **Settings** — threshold, count window, ban tiers (24h/7d/30d presets + custom),
   housekeeping, internal-IP toggle, per-protocol log paths (FTP folders, custom regex),
   exclusions editor.
5. **Lists** — Whitelist / Blacklist editors (IP or CIDR, add/remove).

**Behavior**
- Requires elevation to change settings or lists (prompts via the service, which is
  already SYSTEM).
- Polls `GetStatus`/`ListEvents` every ~2 s, or subscribes via a push message on the pipe.
- System-tray icon with show/exit; closing the window minimizes to tray.

---

## 10. Configuration & file locations

| Item | Path |
|---|---|
| Database | `%ProgramData%\WinGuard\winguard.db` |
| Service log files | `%ProgramData%\WinGuard\Logs\winguard-*.log` |
| Service binary | `%ProgramFiles%\WinGuard\winguard-svc.exe` |
| GUI binary | `%ProgramFiles%\WinGuard\winguard-gui.exe` |
| Service static config | `%ProgramFiles%\WinGuard\appsettings.json` (bootstrap only; live settings in DB) |

Runtime settings live in the DB so the GUI can change them without file ACL headaches.
`appsettings.json` holds only bootstrap values (DB path, pipe name, log level).

---

## 11. Security & correctness requirements

- Service runs as **LocalSystem** (needs Security log read + firewall write). Document
  the privileges; don't run GUI elevated full-time — elevate operations through the service.
- **Never block a whitelisted or local IP.** Auto-whitelist server's own addresses.
- **Idempotent firewall ops** — adding an already-blocked IP is a no-op; removing a
  missing IP doesn't throw.
- **Self-heal on boot:** on start, `SyncRules` from DB so reboots don't lose bans and
  don't leave orphan rules.
- Validate every IP before it reaches the firewall (defense against log-injection of a
  crafted "IP" that is actually a firewall token like `LocalSubnet`).
- All times stored **UTC**, shown **local** (user TZ).
- Pipe input is untrusted-ish (local admins only) but still validate every field.

---

## 12. Testing

`WinGuard.Core.Tests` (xUnit), no admin needed — parsers and engine are pure:
- **Parsers:** feed sample 4625 XML, RdpCoreTS 140 XML, 18456 messages, IIS FTP W3C
  lines, FileZilla lines (in `samples/logs/`) → assert extracted IP/user/source.
  Include the empty-IP 4625 case (must be dropped) and `[CLIENT: ...]` extraction.
- **BanEngine:** threshold crossing, rolling window expiry, tier escalation
  (24h→7d→30d), whitelist/blacklist precedence, counter reset, de-dup of 4625+140.
- **IpMatcher:** IPv4/IPv6/CIDR membership; reject non-IP tokens.
- **Firewall:** behind `IFirewall`; use a fake in engine tests. A separate,
  `[Trait("Category","Integration")]` test exercises the real COM firewall and is
  excluded from CI (needs admin).

Manual/integration checklist (on a throwaway Windows Server VM):
1. Enable audit policy; RDP-brute from another host → IP blocked after threshold.
2. Confirm `WinGuard_Block_*` rule contains the IP (`wf.msc`).
3. Wait out a short test ban → auto-unblock.
4. SQL `sa` brute → 18456 path blocks.
5. IIS FTP bad password ×N → 530 path blocks.
6. Reboot → bans persist, no orphan rules.

---

## 13. Build & packaging

### Publish profile (per exe)
```
dotnet publish src/WinGuard.Service/WinGuard.Service.csproj -c Release -r win-x64 ^
  -p:PublishSingleFile=true -p:SelfContained=true -p:IncludeNativeLibrariesForSelfExtract=true ^
  -p:PublishTrimmed=false -o publish/service

dotnet publish src/WinGuard.Gui/WinGuard.Gui.csproj -c Release -r win-x64 ^
  -p:PublishSingleFile=true -p:SelfContained=true -o publish/gui
```
Notes: WPF supports single-file but **not trimming** — keep `PublishTrimmed=false`.
Output names set via `<AssemblyName>winguard-svc</AssemblyName>` /
`winguard-gui`. Version from the git tag (`-p:Version=${tag#v}`).

### Inno Setup script (`installer/winguard.iss`) — responsibilities
- Install both EXEs + `appsettings.json` + icon to `%ProgramFiles%\WinGuard`.
- Create `%ProgramData%\WinGuard` and `Logs`.
- **Register + start the service** (post-install):
  ```
  sc.exe create WinGuardService binPath= "...\winguard-svc.exe" start= auto DisplayName= "WinGuard Service"
  sc.exe description WinGuardService "WinGuard - blocks brute-force attackers in the firewall"
  sc.exe failure WinGuardService reset= 86400 actions= restart/5000/restart/5000/restart/5000
  sc.exe start WinGuardService
  ```
  (Prefer `start= delayed-auto` to survive boot races.)
- **Enable audit policy** on install (checkbox, default on):
  `auditpol /set /subcategory:"Logon" /success:enable /failure:enable`
- Start-menu + optional desktop shortcut for the GUI.
- **Uninstall:** `sc stop` + `sc delete WinGuardService`, delete `WinGuard_*` firewall
  rules (call `winguard-svc.exe --clear-firewall`), remove files; offer to keep/delete
  `%ProgramData%\WinGuard` (DB/logs).
- Mark installer `ArchitecturesInstallIn64BitMode=x64`, require admin
  (`PrivilegesRequired=admin`).

Add a `winguard-svc.exe --clear-firewall` and `--install/--uninstall/--console` CLI so
the installer and power users can manage it without the GUI.

---

## 14. GitHub Actions

### `.github/workflows/ci.yml` (push + PR)
```yaml
name: CI
on: [push, pull_request]
jobs:
  build-test:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-dotnet@v5
        with: { dotnet-version: '10.0.x' }
      - run: dotnet restore WinGuard.sln
      - run: dotnet build WinGuard.sln -c Release --no-restore
      - run: dotnet test tests/WinGuard.Core.Tests -c Release --no-build
              --filter "Category!=Integration"
```

### `.github/workflows/release.yml` (on tag `v*`)
```yaml
name: Release
on:
  push:
    tags: ['v*.*.*']
permissions:
  contents: write            # needed to create the release
jobs:
  release:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-dotnet@v5
        with: { dotnet-version: '10.0.x' }

      - name: Compute version
        id: ver
        shell: bash
        run: echo "v=${GITHUB_REF_NAME#v}" >> "$GITHUB_OUTPUT"

      - name: Publish service
        run: dotnet publish src/WinGuard.Service/WinGuard.Service.csproj -c Release -r win-x64
             -p:PublishSingleFile=true -p:SelfContained=true
             -p:IncludeNativeLibrariesForSelfExtract=true
             -p:Version=${{ steps.ver.outputs.v }} -o publish/service
      - name: Publish GUI
        run: dotnet publish src/WinGuard.Gui/WinGuard.Gui.csproj -c Release -r win-x64
             -p:PublishSingleFile=true -p:SelfContained=true
             -p:Version=${{ steps.ver.outputs.v }} -o publish/gui

      - name: Stage installer inputs
        shell: pwsh
        run: |
          New-Item -Type Directory dist -Force | Out-Null
          Copy-Item publish/service/winguard-svc.exe dist/
          Copy-Item publish/gui/winguard-gui.exe dist/
          Copy-Item src/WinGuard.Service/appsettings.json dist/
          Copy-Item installer/assets/* dist/ -Recurse

      - name: Build installer (Inno Setup)
        shell: pwsh
        run: |
          & "$env:ProgramFiles(x86)\Inno Setup 6\ISCC.exe" `
            /DMyAppVersion=${{ steps.ver.outputs.v }} installer/winguard.iss
        # Inno Setup 6 is preinstalled on windows-latest runners.
        # Fallback if a future image drops it:
        #   winget install --id JRSoftware.InnoSetup -e -h
        #   or: uses: Minionguyjpro/Inno-Setup-Action@v1.2.2

      - name: Also zip portable EXEs
        shell: pwsh
        run: Compress-Archive -Path publish/service/*,publish/gui/* -DestinationPath dist/WinGuard-portable-win-x64.zip

      - name: Create GitHub Release + upload assets
        uses: softprops/action-gh-release@v2
        with:
          files: |
            installer/Output/WinGuard-Setup-*.exe
            dist/WinGuard-portable-win-x64.zip
```

Pin actions to commit SHAs for supply-chain safety before going public. Node20-based
action versions are being retired on runners (Sep 2026) — use current major versions
(`checkout@v5`, `setup-dotnet@v5`, `action-gh-release@v2`).

---

## 15. Build order (milestones)

**M1 — skeleton & firewall proof**
- Solution, `Directory.Build.props`, `global.json` (SDK 10.0.x).
- `WindowsFirewall` COM wrapper: Block/Unblock/ClearAll + a console harness that blocks
  a test IP and shows it in `wf.msc`. *This de-risks the hardest part first.*

**M2 — RDP detection + ban engine (end-to-end vertical slice)**
- `RdpSecurityLogDetector` (4625) → `Channel` → `BanEngine` → `WindowsFirewall`.
- SQLite store (bans, failed_logins, events, settings).
- Service host (`UseWindowsService`), install/uninstall/console CLI.
- Verify: brute RDP on a VM → block after threshold → auto-unblock on expiry.

**M3 — remaining detectors**
- RdpCoreTS 140 fallback + 4625/140 de-dup.
- MS SQL 18456. FTP (IIS + FileZilla) file tailer. Custom log source.

**M4 — policy depth**
- Ban-tier escalation (24h/7d/30d), whitelist/blacklist, exclusions, internal-IP skip,
  startup reconcile/self-heal.

**M5 — GUI**
- Named-pipe server + client, all five views, tray icon, settings hot-reload.

**M6 — packaging & CI**
- Single-file publish, Inno Setup script, `ci.yml` + `release.yml`, first tagged release.

**M7 — hardening**
- Tests green, Server 2025 firewall verification, docs/README, SHA-pin actions.

---

## 16. Key facts verified during research (so the implementer doesn't re-check)

- **RDP failed logon:** Security **4625**, audit-failure keyword `0x8010000000000000`;
  IP in EventData `IpAddress` (empty over TLS on older setups).
- **RDP TLS/NLA fallback:** `RemoteDesktopServices-RdpCoreTS/Operational` event **140**;
  IP in `IPString`.
- **MS SQL failed login:** Application **18456**, provider name contains `MSSQL`; client
  IP in message `[CLIENT: x.x.x.x]`; requires SQL "Failed logins" auditing + instance
  restart. Ignore "Failed to open the explicitly specified database" reason.
- **IIS FTP failure:** W3C log, `PASS` command, status **530**, IP in `c-ip`.
- **FileZilla Server:** text log, `530 Login or password incorrect!` + session IP.
- **Audit prerequisite:** `auditpol /set /subcategory:"Logon" /success:enable /failure:enable`.
- **Windows firewall:** ~**1000 IPs per rule** practical limit → batch into numbered
  `WinGuard_Block_*` rules; use COM `INetFwPolicy2` (`HNetCfg.FwPolicy2`); block-all-ports
  = 1 condition/IP (cheapest).
- **Server 2025** changed firewall internals (same issue that required IPBan 2.0.1) —
  test there; keep firewall behind `IFirewall`.
- **.NET 10** is current LTS (10.0.10+ by Oct 2026); WPF single-file OK, **no trimming**.
- **GitHub runners:** `windows-latest` has Inno Setup 6 preinstalled
  (`%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe`); `setup-dotnet@v5` with `10.0.x`.
- **Reference OSS (MIT):** DigitalRuby/IPBan — same event sources; useful for the exact
  XPath/regex shapes. Clean-room your implementation; don't lift proprietary RdpGuard code.

---

## 17. README outline (ship with the repo)
- What it is (fail2ban for Windows; RDP/MSSQL/FTP), screenshot of the dashboard.
- Requirements: Windows Server 2016+/Win10+, admin, audit policy, SQL auditing for MSSQL.
- Install (download Setup .exe from Releases) / portable zip.
- How it works (detect → count → firewall block → auto-expire), the 24h/7d/30d tiers.
- Configuration (thresholds, lists, exclusions, FTP log paths).
- Build from source. License (MIT). Clean-room/trademark disclaimer re: RdpGuard.

---

## 18. Errata (found during implementation)

- **§13 (Build & packaging):** the GUI publish command must also pass
  `-p:IncludeNativeLibrariesForSelfExtract=true` (the service command already does).
  Without it the WPF native libraries stay loose next to the single-file EXE and the
  installed GUI crashes at launch.
- **§14 (GitHub Actions):** the Inno Setup ISCC invocation must be written
  `& "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe" ...` in PowerShell.
  `"$env:ProgramFiles(x86)\..."` expands only `$env:ProgramFiles` and leaves a literal
  `(x86)`, producing a `CommandNotFound` error on every release.
- **§16 (Key facts):** the logon audit subcategory should be set with the
  locale-independent GUID `{0CCE9215-69AE-11D9-BED3-505054503030}` rather than the
  English name `"Logon"`; the English name silently fails on German/French/Japanese/…
  Windows.
