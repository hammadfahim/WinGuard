# WinGuard

**WinGuard is a fail2ban-style intrusion-prevention tool for Windows.** It watches
failed-login events for **RDP**, **MS SQL Server**, **FTP** (IIS and FileZilla) and any
**custom log file**, counts them per source IP, and **blocks the attacker in the Windows
Firewall** after a threshold is reached. Bans expire automatically, with
**24-hour → 7-day → 30-day** escalation for repeat offenders.

It ships as a headless **Windows Service** plus a **WPF desktop dashboard** to watch and
manage blocked IPs, events and settings. No traffic sniffing, no kernel drivers — WinGuard
is **log/event based only** and uses the built-in Windows Firewall API.

<!-- Dashboard screenshot: add docs/dashboard.png and uncomment the line below.
![WinGuard dashboard](docs/dashboard.png)
-->

## Features

| | Feature |
|---|---|
| 🛡️ | **Firewall blocking** of attacker IPs via the Windows Firewall Advanced Security COM API (batched `WinGuard_Block_*` rules, ~1000 addresses per rule). |
| 🔍 | **RDP detection** — Security log event **4625**, plus the **RdpCoreTS/Operational 140** TLS/NLA fallback, de-duplicated so one attempt counts once. |
| 🗄️ | **MS SQL Server detection** — Application log event **18456**, client IP pulled from the `[CLIENT: x.x.x.x]` message. |
| 📄 | **FTP detection** — IIS W3C logs (`PASS` + status `530`) and FileZilla Server text logs, tailed on disk (works for FTPS too). |
| 🧩 | **Custom log sources** — point WinGuard at a file/folder plus a regex with named `ipaddress`/`username` groups, or start from a built-in **recipe** (Windows OpenSSH, hMailServer, IIS HTTP auth, VNC). |
| ⏱️ | **Time-based bans** with **24 h / 7 d / 30 d** escalation, custom durations, and permanent blacklisting. |
| ♻️ | **Auto-unblock** when a ban expires; counters reset after a configurable idle time. |
| ✅ | **Whitelist / blacklist** with single IPs and CIDR ranges (IPv4 + IPv6). Whitelist always wins. Blacklisted **subnets are enforced as whole-range firewall rules**. |
| 🚫 | **Exclusions** to ignore known-benign failures (e.g. `LogonType=2`, `TargetUserName=backup-*`). |
| 🕵️ | **Report-only mode** — count and record would-be bans without touching the firewall (safe trial on production). |
| ⏪ | **Backlog replay** — failures logged while the service was stopped are re-read at startup (default: last 30 minutes). |
| 🧮 | **IPv6 /N aggregate bans** — an attacker rotating a /64 is banned as the whole prefix. |
| 📊 | **Statistics & ban history** — per-day detections/bans chart, top attackers, full ban history (survives restarts and pruning). |
| 🔔 | **Notifications** — webhook (JSON POST), Telegram, SMTP e-mail (opt-in, rate-limited) and Windows Event Log output for SIEM/WEF. |
| 🖥️ | **WPF GUI** — dashboard, blocked-IP grid, live event log, statistics, settings and list editors; talks to the service over a local named pipe. |
| 🔧 | **Service + CLI** — install/uninstall/console/clear-firewall verbs plus `--status`, `--list-bans`, `--ban`, `--unban`, `--doctor` for headless management. |
| 📦 | **Single-file, self-contained x64 EXEs** and an **Inno Setup** installer, built by GitHub Actions. |

## Requirements

- **Windows Server 2016+ or Windows 10+ (x64), or Windows Server 2025.** The 4625 and
  RdpCoreTS 140 events are reliable on these versions; older Server releases are not
  supported.
- **Administrator rights** to install and to read the Security log / write firewall rules.
- **Windows Defender Firewall service (`MpsSvc`)** must be running for rules to take
  effect. The GUI surfaces a warning if it is stopped.
- **Logon-failure auditing** for RDP detection:
  ```powershell
  auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
  ```
  The GUID is the locale-independent audit subcategory ID; the English name `Logon`
  silently fails on German/French/Japanese/… Windows. The installer offers to enable
  this (checked by default) and the GUI verifies it.
- **For MS SQL detection only:** SQL Server *login auditing* must include failed logins
  (SSMS → Server Properties → Security → Login auditing → *Failed logins only* or both),
  then restart the instance. WinGuard cannot toggle this remotely and documents how to
  verify it.

The published releases are self-contained — **you do not need .NET installed** on the
target server. Only building from source needs the .NET 10 SDK.

## Install

### Option 1 — Setup installer (recommended)

1. Download `WinGuard-Setup-<version>.exe` from
   [Releases](https://github.com/hammadfahim/WinGuard/releases).
2. Run it (it requests elevation). It installs to `%ProgramFiles%\WinGuard`, creates
   `%ProgramData%\WinGuard` and `%ProgramData%\WinGuard\Logs`, registers and starts the
   **WinGuardService** service, and — if you leave the task checked — enables logon
   failure auditing.
3. Launch **WinGuard** from the Start menu or desktop to open the dashboard.

Uninstall stops and removes the service and deletes its `WinGuard_Block_*` firewall
rules, then offers to delete or keep the database and logs in `%ProgramData%\WinGuard`.
Silent uninstalls skip the prompt and keep the data folder.

### Option 2 — Portable zip

Download `WinGuard-portable-win-x64.zip`, extract it, and run `winguard-gui.exe`.
Because the portable build does not register a service, start the engine in console mode
from an elevated prompt:

```powershell
.\winguard-svc.exe --console
```

For a persistent install from the portable binaries, register the service with
`.\winguard-svc.exe --install` (elevated) and undo it with `--uninstall`.

### Option 3 — Build from source

Requires the **.NET 10 SDK**.

```powershell
git clone https://github.com/hammadfahim/WinGuard
cd WinGuard

# Build + unit tests
dotnet restore WinGuard.sln
dotnet build WinGuard.sln -c Release
dotnet test tests/WinGuard.Core.Tests -c Release --filter "Category!=Integration"

# Produce single-file, self-contained EXEs
dotnet publish src/WinGuard.Service/WinGuard.Service.csproj -c Release -r win-x64 `
  -p:PublishSingleFile=true -p:SelfContained=true `
  -p:IncludeNativeLibrariesForSelfExtract=true -p:PublishTrimmed=false -o publish/service

dotnet publish src/WinGuard.Gui/WinGuard.Gui.csproj -c Release -r win-x64 `
  -p:PublishSingleFile=true -p:SelfContained=true `
  -p:IncludeNativeLibrariesForSelfExtract=true -p:PublishTrimmed=false -o publish/gui
```

The service executable is `publish/service/winguard-svc.exe`; the GUI is
`publish/gui/winguard-gui.exe`. The build outputs are named `winguard-svc` and
`winguard-gui` via their project `AssemblyName`.

## How it works

```
detect  ──►  count  ──►  block  ──►  expire
```

1. **Detect.** Detectors read Windows event logs (push-based `EventLogWatcher`) or tail
   FTP/custom log files. Every observed failed login becomes a `FailedLogin` (normalized
   IP, user, source, UTC timestamp) and is pushed into one channel. At startup the
   event-log detectors also replay the last `EventBacklogReplayMinutes` minutes of history,
   so failures logged while the service was stopped still count. The service is the
   only writer; the GUI never touches the database or firewall directly.
2. **Count.** The `BanEngine` rejects invalid/non-IP tokens, skips the whitelist, ensures
   permanent bans for the blacklist, and counts attempts **per IP within a rolling
   window** (default 10 minutes). Internal RFC1918/loopback/link-local addresses are
   ignored by default so the server cannot lock itself out.
3. **Block.** When the count reaches the threshold (default 5), WinGuard adds the IP to a
   batched `WinGuard_Block_*` inbound firewall rule and stores the ban in SQLite.
4. **Expire.** A housekeeping timer unblocks and removes bans whose time is up and
   reconciles the firewall with the database on startup (self-heal after reboot). Banned
   IPs lose their pending counters, so the next offense starts a fresh window.

### Ban tiers

The first offense gets **24 hours**. If the same IP offends again (after the previous ban
expires), the second gets **7 days** and the third **30 days**; further offenses stay at
30 days (the cap). Set a single tier to disable escalation, or blacklist an IP for a
permanent ban. `MaxBanDuration` (default 365 days) caps non-permanent tiers.

### Monitoring extras

- **Report-only mode** runs the whole pipeline (detect → count → record) without firewall writes,
  so you can validate thresholds on production before enforcing them. Bans recorded in
  report-only become enforced the moment the flag is switched off.
- **Backlog replay** re-reads the last N minutes (default 30) of the event logs at startup, so
  failures logged during a service restart or patch reboot still count. Only what happened after
  the previous run stopped is counted, so a restart never re-counts failures or undoes a manual
  unban. The very first start replays nothing; after a crash, up to one `HousekeepingInterval` of
  failures can be counted twice.
- **Ban history and daily statistics** are append-only: every ban, expiry and manual unban is
  kept in `ban_history`, and per-day counters survive restarts and event pruning — visible in
  the GUI's Statistics view.
- **Notifications**: block/unblock events can be pushed to a webhook, Telegram or SMTP e-mail
  (rate-limited), and are always available to SIEM tooling through the Windows Application event
  log (source `WinGuard`, toggle in settings).

### De-duplication

A single RDP attempt can appear as both Security **4625** and RdpCoreTS **140**. The engine
counts a repeated RDP failure for the same IP only once when it arrives within **2 seconds**
of the previous one.

## Configuration

Runtime settings live in the SQLite database and are hot-reloaded by the service when the
GUI saves them. The GUI exposes all of the below under **Settings** and **Lists**.

| Setting | Default | Meaning |
|---|---|---|
| `FailedLoginThreshold` | `5` | Attempts before a ban. Per-protocol overrides are supported. |
| `CountWindow` | `00:10:00` | Rolling window in which attempts are counted. |
| `ExpireTime` | `1.00:00:00` | Idle time after which a stale counter is forgotten. |
| `BanTiers` | `[24:00:00, 7.00:00:00, 30.00:00:00]` | **24 h → 7 d → 30 d** escalation. |
| `MaxBanDuration` | `365.00:00:00` | Cap on a non-permanent tier. Permanent bans are separate. |
| `HousekeepingInterval` | `00:00:15` | Expiry/reconcile cadence. |
| `ClearBansOnStartup` | `false` | If true, flush firewall rules at service start instead of reconciling. |
| `ProcessInternalIPs` | `false` | Ignore RFC1918/loopback/link-local addresses by default. |
| `ReportOnly` | `false` | Monitoring mode: record would-be bans, never touch the firewall. Bans recorded while on become enforced when switched off. |
| `EventBacklogReplayMinutes` | `30` | How far back the startup replay looks for failures logged during downtime; 0 = off. |
| `Ipv6AggregatePrefixLength` | `0` (off) | Ban whole IPv6 /N prefixes (e.g. `64`) instead of single addresses. A prefix holding a whitelisted address stays on per-address bans. |
| `MaxAddressesPerRule` | `1000` | Firewall addresses batched per rule. |
| `BlockedPorts` | *empty* | Empty = block all ports (cheapest). Non-empty = block only those ports. |
| `Notifications` | *off* | Webhook URL, Telegram bot/chat, SMTP relay, rate limit; plus `WriteToWindowsEventLog` (default on) for SIEM/WEF. |
| `Rdp.UseRdpCoreTsFallback` | `true` | Also use RdpCoreTS/Operational 140. |
| `Rdp.ExclusionRules` | *empty* | e.g. `LogonType=2`, `TargetUserName=backup-*`. |
| `MsSql.IgnoreMessagePatterns` | `[Failed to open the explicitly specified database]` | 18456 reasons that are not brute force. |
| `Ftp.Sources`, `Ftp.PollInterval` | *empty*, `00:00:03` | IIS log folders / FileZilla file-or-folder. |
| `CustomSources` | *empty* | `{ PathGlob, Regex }` with `(?<ipaddress>…)` / `(?<username>…)`; recipes provided for OpenSSH, hMailServer, IIS HTTP auth and VNC. |
| `CustomSources` | *empty* | `{ PathGlob, Regex }` with `(?<ipaddress>…)` / `(?<username>…)`. |

**Exclusion rules** use `=` / `!=` and `*` wildcards over the 4625 EventData fields.
Conditions inside one rule are **AND**ed; separate rules are **OR**ed. Field names are
case-insensitive. An event is dropped when any rule matches.

**Lists** accept single IPs and CIDR ranges (`10.0.0.0/8`, `2001:db8::/32`). The whitelist
always wins over the blacklist and over any pending ban, including inside a range: Windows
block rules beat allow rules, so a blacklisted range is split into smaller rules around the
whitelisted addresses, and an IPv6 aggregate ban that comes to overlap the whitelist is lifted.
The server's own addresses and loopback are auto-whitelisted at startup to prevent self-lockout.

### Limitations

- **Log sources must be on a local drive.** FTP and custom log paths that point at a
  network share (`\\server\share\…`) are refused: the service runs as SYSTEM and would
  authenticate to whatever host the path names.
- **The "RDP / logon" engine counts every failed Windows logon that carries a client
  address.** Security event 4625 also covers failed SMB and other network logons, not only
  Remote Desktop, and they all count towards a ban.
- **FileZilla Server 1.x support is unverified.** The parser accepts the legacy 0.9.x log
  layout and any line with a `530 Login…` response whose prefix contains the session
  address, but it has only been tested against 0.9.x sample logs.
- **A blacklisted range is enforced as one firewall range rule** covering the whole subnet, or as
  several when it contains whitelisted addresses; addresses inside it are additionally banned
  permanently at their first failed login.
- **Backlog replay covers the event-log engines only** and is capped (default: last 30 minutes,
  5000 records per channel). Failures older than that, logged while the service was down, are
  not counted; file-based tailers skip to end-of-file on first sight by design.
- **IPv4 bans stay per-address.** IPv6 can be aggregated to a /N prefix (recommended: /64) so a
  rotating attacker is banned wholesale; IPv4 attackers do not rotate /24s in practice, so no
  IPv4 aggregation is offered.
- **Custom log sources share the FTP poll interval.** A single `Ftp.PollInterval`
  (default 3 s) drives the IIS/FileZilla tailers and every custom source; there is no
  per-source interval.
- **Notification secrets (SMTP password, Telegram token) are stored in the settings database**
  in plain text, like the rest of the configuration; the data folder is ACL-restricted to
  SYSTEM + Administrators.
- **Very broad list prefixes are rejected.** Whitelist/blacklist entries shorter than `/8`
  for IPv4 (such as `0.0.0.0/0`) or `/32` for IPv6 are refused by the IPC as a self-lockout
  footgun; use an explicit range instead.
- **The GUI requires administrator elevation.** It is an administrative console (like
  `wf.msc`): the service pipe only accepts Administrators + LocalSystem, so the GUI
  manifest requests elevation and Windows shows a UAC prompt at launch (a credential
  prompt for standard-user sessions). Running it non-elevated would just show
  "service not running".

## Command line

`winguard-svc.exe` supports:

| Verb | Action |
|---|---|
| *(none)* | Run as the Windows Service host. |
| `--console` | Run the engine in the foreground (for debugging). |
| `--install` | Register the service (`delayed-auto`), set its description and failure-restart actions, and start it. |
| `--uninstall` | Stop and delete the service. |
| `--clear-firewall` | Delete all `WinGuard_Block_*` rules and exit. Used by the uninstaller. |
| `--status` | Print service status and per-engine counters (needs an elevated console). |
| `--list-bans` | Print the active bans as a table. |
| `--ban <ip> [--permanent] [--duration d.hh:mm:ss] [--note text]` | Manually block an address via the running service. |
| `--unban <ip\|prefix>` | Manually lift a ban, including an IPv6 aggregate ban such as `2001:db8:1:2::/64`. |
| `--doctor` | Health check: service reachability, prerequisites, data/log folders, firewall COM API; non-zero exit when protection-critical checks fail. |

## Project layout

```
winguard/
├─ WinGuard.sln
├─ Directory.Build.props              # shared TFM/version/nullable/langversion props
├─ global.json                        # pins the .NET 10 SDK
├─ src/
│  ├─ WinGuard.Core/                  # logic only: models, detectors, engine, firewall, store, config, notifications
│  │  ├─ Model/  Abstractions/  Detection/  Engine/  Firewall/  Store/  Config/  Notifications/  Ipc/
│  ├─ WinGuard.Service/               # Windows Service host + CLI + named-pipe server
│  └─ WinGuard.Gui/                   # WPF dashboard (net10.0-windows)
├─ tests/WinGuard.Core.Tests/         # xUnit: parsers, engine, IP matcher, store, notifications, integration
├─ installer/
│  ├─ winguard.iss                    # Inno Setup script
│  └─ assets/                         # license.txt (+ optional icon.ico)
├─ samples/logs/                      # parser fixtures and their expected results
├─ CHANGELOG.md                       # release notes
├─ SECURITY.md                        # vulnerability-reporting policy
└─ .github/workflows/                 # ci.yml + release.yml
```

## Testing

Unit tests are pure and need **no administrator rights**:

```powershell
dotnet test tests/WinGuard.Core.Tests -c Release --filter "Category!=Integration"
```

The parser tests assert the exact ground truth documented in
[`samples/logs/README.md`](samples/logs/README.md). The firewall batching logic is covered
by unit tests against an in-memory rule store that returns addresses in the format Windows
reports them. The test against the real Windows Firewall is tagged `Category=Integration`,
requires an **elevated** process (it is reported as *skipped*, not passed, otherwise), and is
excluded from CI; run it explicitly on a throwaway VM:

```powershell
dotnet test tests/WinGuard.Core.Tests -c Release --filter "Category=Integration"
```

Manual end-to-end checklist (throwaway Windows Server VM): enable audit policy, brute-force
RDP from another host and confirm the IP appears in `wf.msc` under `WinGuard_Block_*`; wait
out a short test ban and confirm auto-unblock; exercise the SQL `sa` and IIS FTP 530 paths;
reboot and confirm bans persist with no orphan rules.

## License

[MIT](LICENSE) © 2026 WinGuard contributors.

## Clean-room / trademark notice

WinGuard is an **independent, clean-room implementation**. It is **not affiliated with,
endorsed by, or derived from RdpGuard**, and it shares no code or assets with it. "RdpGuard"
is a trademark of its respective owner and is referenced only to describe WinGuard's
observable feature set (detection sources, block durations, whitelist/blacklist, and the
service + GUI split). Detection details are based on public Microsoft event documentation
and the MIT-licensed [DigitalRuby/IPBan](https://github.com/DigitalRuby/IPBan) project.