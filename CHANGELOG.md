# Changelog

All notable changes to WinGuard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project versions by tag.

## [Unreleased]

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
