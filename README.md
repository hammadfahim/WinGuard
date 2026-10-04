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
| 🧩 | **Custom log sources** — point WinGuard at a file/folder plus a regex with named `ipaddress`/`username` groups. |
| ⏱️ | **Time-based bans** with **24 h / 7 d / 30 d** escalation, custom durations, and permanent blacklisting. |
| ♻️ | **Auto-unblock** when a ban expires; counters reset after a configurable idle time. |
| ✅ | **Whitelist / blacklist** with single IPs and CIDR ranges (IPv4 + IPv6). Whitelist always wins. |
| 🚫 | **Exclusions** to ignore known-benign failures (e.g. `LogonType=2`, `TargetUserName=backup-*`). |
| 🖥️ | **WPF GUI** — dashboard, blocked-IP grid, live event log, settings and list editors; talks to the service over a local named pipe. |
| 🔧 | **Service + CLI** — install/uninstall/console/clear-firewall verbs for automation. |
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
  auditpol /set /subcategory:"Logon" /success:enable /failure:enable
  ```
  The installer offers to enable this (checked by default) and the GUI verifies it.
- **For MS SQL detection only:** SQL Server *login auditing* must include failed logins
  (SSMS → Server Properties → Security → Login auditing → *Failed logins only* or both),
  then restart the instance. WinGuard cannot toggle this remotely and documents how to
  verify it.

The published releases are self-contained — **you do not need .NET installed** on the
target server. Only building from source needs the .NET 10 SDK.

## Install

### Option 1 — Setup installer (recommended)

1. Download `WinGuard-Setup-<version>.exe` from
   [Releases](https://github.com/winguard/winguard/releases).
2. Run it (it requests elevation). It installs to `%ProgramFiles%\WinGuard`, creates
   `%ProgramData%\WinGuard` and `%ProgramData%\WinGuard\Logs`, registers and starts the
   **WinGuardService** service, and — if you leave the task checked — enables logon
   failure auditing.
3. Launch **WinGuard** from the Start menu or desktop to open the dashboard.

Uninstall removes the service and its firewall rules and offers to delete or keep the
database and logs in `%ProgramData%\WinGuard`.

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
git clone https://github.com/winguard/winguard
cd winguard

# Build + unit tests
dotnet restore WinGuard.sln
dotnet build WinGuard.sln -c Release
dotnet test tests/WinGuard.Core.Tests -c Release --filter "Category!=Integration"

# Produce single-file, self-contained EXEs
dotnet publish src/WinGuard.Service/WinGuard.Service.csproj -c Release -r win-x64 `
  -p:PublishSingleFile=true -p:SelfContained=true `
  -p:IncludeNativeLibrariesForSelfExtract=true -p:PublishTrimmed=false -o publish/service

dotnet publish src/WinGuard.Gui/WinGuard.Gui.csproj -c Release -r win-x64 `
  -p:PublishSingleFile=true -p:SelfContained=true -p:PublishTrimmed=false -o publish/gui
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
   IP, user, source, UTC timestamp) and is pushed into one channel. The service is the
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
| `MaxAddressesPerRule` | `1000` | Firewall addresses batched per rule. |
| `BlockedPorts` | *empty* | Empty = block all ports (cheapest). Non-empty = block only those ports. |
| `Rdp.UseRdpCoreTsFallback` | `true` | Also use RdpCoreTS/Operational 140. |
| `Rdp.ExclusionRules` | *empty* | e.g. `LogonType=2`, `TargetUserName=backup-*`. |
| `MsSql.IgnoreMessagePatterns` | `[Failed to open the explicitly specified database]` | 18456 reasons that are not brute force. |
| `Ftp.Sources`, `Ftp.PollInterval` | *empty*, `00:00:03` | IIS log folders / FileZilla file-or-folder. |
| `CustomSources` | *empty* | `{ PathGlob, Regex }` with `(?<ipaddress>…)` / `(?<username>…)`. |

**Exclusion rules** use `=` / `!=` and `*` wildcards over the 4625 EventData fields.
Conditions inside one rule are **AND**ed; separate rules are **OR**ed. Field names are
case-insensitive. An event is dropped when any rule matches.

**Lists** accept single IPs and CIDR ranges (`10.0.0.0/8`, `2001:db8::/32`). The whitelist
always wins over the blacklist and over any pending ban. The server's own addresses and
loopback are auto-whitelisted at startup to prevent self-lockout.

## Command line

`winguard-svc.exe` supports:

| Verb | Action |
|---|---|
| *(none)* | Run as the Windows Service host. |
| `--console` | Run the engine in the foreground (for debugging). |
| `--install` | Register the service (`delayed-auto`), set its description and failure-restart actions, and start it. |
| `--uninstall` | Stop and delete the service. |
| `--clear-firewall` | Delete all `WinGuard_Block_*` rules and exit. Used by the uninstaller. |

## Project layout

```
winguard/
├─ WinGuard.sln
├─ Directory.Build.props              # shared TFM/version/nullable/langversion props
├─ global.json                        # pins the .NET 10 SDK
├─ src/
│  ├─ WinGuard.Core/                  # logic only: models, detectors, engine, firewall, store, config
│  │  ├─ Model/  Abstractions/  Detection/  Engine/  Firewall/  Store/  Config/  Ipc/
│  ├─ WinGuard.Service/               # Windows Service host + CLI + named-pipe server
│  └─ WinGuard.Gui/                   # WPF dashboard (net10.0-windows)
├─ tests/WinGuard.Core.Tests/         # xUnit: parsers, engine, IP matcher, store, integration
├─ installer/
│  ├─ winguard.iss                    # Inno Setup script
│  └─ assets/                         # license.txt (+ optional icon.ico)
├─ samples/logs/                      # parser fixtures and their expected results
└─ .github/workflows/                 # ci.yml + release.yml
```

## Testing

Unit tests are pure and need **no administrator rights**:

```powershell
dotnet test tests/WinGuard.Core.Tests -c Release --filter "Category!=Integration"
```

The parser tests assert the exact ground truth documented in
[`samples/logs/README.md`](samples/logs/README.md). The Windows-Firewall COM test is tagged
`Category=Integration`, requires an **elevated** process, and is excluded from CI; run it
explicitly on a throwaway VM:

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