# Changelog

All notable changes to WinGuard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project versions by tag.

## [Unreleased]

## [0.3.2] — 2026-11-10

### Changed

- Webhook, Telegram and e-mail each send from a queue of their own. A notification that waited more
  than 10 minutes behind a receiver that does not answer is dropped and counted in the
  `SUPPRESSED` summary instead of being sent late.
- SMTP port 465 is refused when settings are saved: it expects TLS from the first byte, which is not
  supported. Use port 587 with TLS on. A setting stored earlier is skipped with one warning in the
  log, where each mail used to wait 30 seconds and time out.

### Fixed

- A Telegram bot token or SMTP password typed into an empty field in Settings was not saved.
- Numbered log archives that move up one name at each rotation (`app.log` to `app.log.1`,
  `app.log.1` to `app.log.2`) were read again from the start by a custom source whose folder or
  glob includes them, which could ban every address in them at each rotation.
- A log folder that could not be listed for a moment (renamed, volume offline, access error) came
  back as new: every file in it was read from its first line. Its files now continue where they
  stopped, and files that turn up with it are treated as history.
- One receiver that is slow or down no longer delays the notifications of the other channels.
- Notifications switched on without any destination no longer produce `SUPPRESSED` summaries.

## [0.3.1] — 2026-11-01

### Added

- **An application icon**: a shield with a keyhole, on the program files, shortcuts, taskbar, window
  and Setup, with images for the installer wizard. Small sizes have their own simpler drawing.
- `POSSIBLE COMPROMISE` alerts have their own stable event ID, 1007, instead of the generic 1900.
  Update any SIEM rule that matched them under 1900.

### Changed

- The tray icon is sharp at any display scaling and shows its state by shape as well as colour:
  solid while protecting, hollow while offline, red with an exclamation mark while bans have no
  effect.
- A blocklist file that shrinks to under half of a list of 100 entries or more is treated as cut
  off: the last good entries stay in force and a warning says so. To accept a shorter list, take the
  file off the list and add it back.
- Setup exits with code 20 and shows an error when the service does not start, where it used to
  report success.

### Fixed

- One failed write no longer ends the Windows Event Log output for the rest of the run.
- CEF messages no longer start with a BOM when the text holds non-ASCII characters, which could stop
  a collector recognising them. RFC 5424 text keeps its BOM.
- A failed save of the blocklist entries is tried again on the next pass.
- When Setup cannot secure the data folder, it no longer starts a service an administrator had
  stopped.
- A TCP syslog receiver that sends something and then disconnects is now noticed before the next
  message is lost.
- A secret saved during a `--console` run now logs a warning that the Windows service cannot read it.

## [0.3.0] — 2026-10-31

### Added

- **Per-engine port profiles**: ban an attacker on the attacked service's ports only, with presets
  for RDP, MS SQL, FTP and SSH. The default stays all ports, and a port-scoped ban widens when the
  same address attacks another engine.
- **Local blocklist files**: block lists the administrator downloaded (Spamhaus DROP format works),
  capped at 50,000 entries, with whitelisted and internal ranges cut out. WinGuard fetches nothing.
- **Detection rules** (all off by default): honeypot usernames, password spraying from one IP, slow
  brute force across engines, `POSSIBLE COMPROMISE` alerts on a successful logon after failures, and
  optional short-lived trust of an administrator's address.
- **Break-glass recovery**: `--disarm [--minutes N]` and `--rearm` work with the service down, are
  bounded to 24 hours and end by themselves. `--doctor` warns when Group Policy makes Windows ignore
  local firewall rules.
- **Encrypted secrets**: the SMTP password, Telegram token and webhook URL are stored with DPAPI.
- **Monitoring**: a Prometheus textfile for windows_exporter and a syslog notification channel (RFC
  5424 or CEF). No listening port.
- **New console**: redesigned shell, dashboard, Blocked IPs, Event log, Statistics, Lists and
  Settings, with in-app toasts, confirmation dialogs, keyboard shortcuts, bulk actions, live
  countdowns, interactive charts and a regex tester for custom sources.
- `OffenseMemory` (default 90 days) and `BanHistoryRetentionDays` (default 365).
- CI fails on vulnerable packages; release builds are signed when `WINGUARD_SIGNING_PFX_BASE64` and
  `WINGUARD_SIGNING_PFX_PASSWORD` are configured.

### Changed

- **Protocol version 5**: use a matching console and service. An older console saving settings could
  reset the new options, so the two are versioned together.
- **Database schema 5**: offense counts move to their own table and bans record their port scope.
  Existing data is migrated in place; downgrading loses escalation counts.
- With `BlockedPorts` set, new manual bans, blacklist bans and blacklisted ranges now block **all**
  ports.
- **Setup now checks the data folder before trusting it.** `--harden-data` walks it without following
  links; links, hard links and items not owned by SYSTEM or Administrators are moved to a
  `Quarantine-*` folder with a `quarantine.txt`, never deleted, and it exits with code 3 when that
  happens. It runs with the service stopped.
- MS SQL events are ignored unless their provider is an installed SQL Server instance.
- `ban_history` is pruned after `BanHistoryRetentionDays` instead of growing forever.
- Report-only mode now never touches the firewall: rules that already exist stay until it is
  switched off, even if their ban is lifted.
- CGNAT (100.64.0.0/10) and benchmarking (198.18.0.0/15) addresses count as internal; a NAT64 address
  is judged by the IPv4 address inside it.
- Manual bans are labelled Manual instead of Custom.
- The console now verifies that the service's pipe is owned by SYSTEM or an elevated administrator,
  and refuses it otherwise.
- Setup now stops with an error if it cannot secure the data folder or stop the service.
- Webhook payloads changed so Slack, Discord, Mattermost and Teams-style receivers accept them.
  Windows events have stable IDs per event type, listed in `SECURITY.md`.

### Fixed

- **The whitelist now wins over range blocks.** Windows block rules beat allow rules, so a
  blacklisted range is split around whitelisted addresses (including the server's own) instead of
  blocking them, and an IPv6 prefix holding a whitelisted address stays on per-address bans. An
  aggregate ban that comes to overlap the whitelist is lifted by housekeeping.
- **Backlog replay no longer re-counts.** Failures the previous run already processed are skipped
  and replayed 4625/140 pairs merge, so a restart cannot ban a user for failures counted before it
  or undo a manual unban. The engine saves its position during housekeeping and on stop. The first
  start after this upgrade replays nothing, because no position has been saved yet.
- **IPv6 aggregate bans can be lifted early**: Unblock, Unblock & Whitelist and Promote work on
  them, as does `--unban <prefix>`, and whitelisting a covering range lifts them.
- **Attacker-chosen user names can no longer pick the banned address.** The Windows OpenSSH recipe
  takes the address from the end of the line; sources saved from the old recipe are upgraded when
  loaded. A FileZilla line counts only when the 530 response directly follows the first session
  marker, so a client command echoing "530 Login" is ignored.
- **A database failure no longer stops blocking.** The firewall block now comes first. While the
  store refuses writes, failures are counted in memory and unsaved bans stay enforced until
  housekeeping can save them.
- Blacklisted ranges stay enforced across a restart; an unreadable database at start-up no longer
  wipes the firewall rules.
- Escalation no longer resets 4 days after a ban ends.
- `--doctor` can now actually fail its firewall check.
- The IIS HTTP recipe matches real W3C logs and counts real logon failures only; the hMailServer
  and VNC recipes were rewritten against their real log formats, and saved sources upgrade on load.
- Two custom sources can share a file; UTF-16 logs are read; rotated logs are not lost; a crafted
  line can no longer hide later attempts through a regex timeout.
- Log forging through newlines in attacker-controlled text, and URLs leaking into logs.
- Expired bans now notify; a suppressed-notification summary shows what the rate limit dropped.
- **Review of the combined work.** A failed ban read is no longer taken for "no ban", which could
  overwrite a ban or demote a permanent one; bans made during a database outage survive expiry
  passes and cancellation; a whitelisted address banned while the lists were unreadable is lifted;
  NAT64 addresses are judged by the IPv4 address inside them and never aggregated, and bans of the
  NAT64 prefix left by older versions are lifted; a manual re-ban keeps a longer existing ban;
  `ClearBansOnStartup` no longer wipes range rules when the lists are unreadable.
- A hanging webhook or mail server no longer holds back the Windows Event Log and syslog outputs.
- Failures logged during the start-up replay are no longer lost.
- Old plaintext secrets are scrubbed from the database files, not only overwritten.
- Saving settings in the console no longer loses the syslog settings or a custom source's ports.

## [0.2.0] — 2026-10-07

### Added

- **Report-only mode** (`ReportOnly`): count failures and record would-be bans without touching
  the firewall — a zero-risk trial run on production servers. The dashboard and the settings page
  show a warning banner; bans recorded while in report-only are enforced the moment the flag is
  switched off.
- **Backlog replay on startup** (`EventBacklogReplayMinutes`, default 30): failed logins recorded
  in the Windows event logs while the service was stopped (patch reboots, crashes) are re-read and
  counted when it starts again. Capped at 5000 records per channel.
- **IPv6 aggregate banning** (`Ipv6AggregatePrefixLength`, e.g. 64): count and ban the attacker's
  whole /N prefix so address rotation inside a /64 cannot evade the threshold. The ban is stored
  and enforced as a firewall range rule.
- **Whole-subnet blacklist enforcement**: a blacklisted CIDR (e.g. `203.0.113.0/24`) is now
  enforced as one firewall *range* rule covering the subnet, instead of banning each address on
  first contact. Range rules participate in the reconcile self-heal pass.
- **Ban history & statistics**: every ban, expiry and manual unban is kept in an append-only
  `ban_history` table; per-day counters (`daily_stats`) survive restarts and event pruning. New
  GUI **Statistics** view: per-day detections/bans chart, per-engine totals, most persistent
  attackers and the full ban history. New IPC methods `GetStatistics` / `ListBanHistory`
  (protocol version 3).
- **Notifications**: opt-in webhook (JSON POST), Telegram and SMTP e-mail delivery of
  block/unblock events, rate-limited (default 20/minute). Plus opt-out Windows **Application
  event log** output under the `WinGuard` source (default on) for SIEM / Windows Event Forwarding
  consumers. WinGuard still never contacts anything but the destinations the administrator
  configures.
- **Management CLI** (elevated console, over the service pipe): `winguard-svc --status`,
  `--list-bans`, `--ban <ip> [--permanent] [--duration d.hh:mm:ss] [--note text]`, `--unban <ip>`,
  and a `--doctor` health check (service, prerequisites, paths, firewall COM API) for headless
  servers and support.
- **Custom-source recipes**: ready-made custom log sources for Windows OpenSSH, hMailServer,
  IIS HTTP 401 auth and VNC, selectable in the settings UI.
- **`SECURITY.md`** with a vulnerability-disclosure policy.

### Changed

- `IFirewall.Block/Unblock` accept a canonical CIDR range in addition to a host IP; the Windows
  implementation parses subnet read-back (prefix or dotted-netmask form) into canonical form.
- IPC list mutations now trigger a full housekeeping pass so new blacklist ranges apply
  immediately.
- SQLite schema version 3 (`ban_history`, `daily_stats`); existing databases are migrated in
  place, no data is transformed.
- Settings UI exposes `MaxAddressesPerRule`, backlog replay, IPv6 aggregation, report-only and
  the notification channels.

### Fixed / hardening

- Statistics and history survive service restarts; "detections today" is no longer lost on reboot
  beyond the failed-logins seed.
- Manual re-ban of an already-banned IP no longer inflates the daily ban counter.

## [0.1.0] … [0.1.9]

Initial MVP releases: RDP/MS SQL/FTP/custom detection, tiered bans with escalation, whitelist /
blacklist with CIDR support, exclusions, WPF dashboard over a secured named pipe, Windows service
host, Inno Setup installer, CI and release automation. See the git history for details.
