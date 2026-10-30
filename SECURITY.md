# Security policy

WinGuard is a Windows intrusion-prevention tool that runs with high privileges (LocalSystem) and
modifies the local firewall. This document describes how we handle security issues in WinGuard
itself. For hardening *your server* with WinGuard, see the README.

## Supported versions

Only the latest tagged release receives security fixes.

## Reporting a vulnerability

Please report vulnerabilities privately:

1. Open a **private security advisory** on GitHub
   (`https://github.com/hammadfahim/WinGuard/security/advisories/new`), or
2. Email the maintainer via the address listed on the GitHub profile.

Please include reproduction steps, affected versions and impact. We aim to respond within 72
hours and to ship a fix for accepted issues within 14 days for critical, 30 days otherwise.
Public disclosure is coordinated with you after a fix is released.

**Please do not open public issues for vulnerabilities.**

## Security model (summary)

- The service runs as **LocalSystem** and is the only writer to the database and the firewall.
- The GUI (and the new management CLI) talk to the service over a local named pipe whose DACL
  admits only **SYSTEM and elevated Administrators**; remote pipe clients are rejected, callers
  are identified from their process token and unauthorized connections are refused (fail-closed).
  When that DACL cannot be built the pipe is not opened at all; there is no fallback to a default
  DACL, and the first instance refuses a pipe name that is already taken.
- The check also runs the other way: while the service is down any local user can create the pipe
  name, so the console and CLI send nothing until they have read the access token of the process
  that owns the pipe. It must be **LocalSystem**, or an **elevated administrator** for a
  `--console` run; anything else, or anything that cannot be verified, is refused with a visible
  reason.
- Every IP reaching the firewall is validated as a literal (or canonical CIDR with a minimum
  prefix length); hostnames and firewall tokens such as `LocalSubnet` can never be injected via
  log text.
- Over-broad list entries (`0.0.0.0/0`-style) are rejected by the IPC layer; the machine's own
  addresses are auto-whitelisted to prevent self-lockout.
- The data directory under `%ProgramData%\WinGuard` is ACL-hardened to SYSTEM + Administrators by
  the setup and by `--install`. A folder a standard user created first loses that user as owner, so
  they cannot grant themselves access again, and setup stops if the folder cannot be secured or
  turns out to be a link. A portable `--console` run does not touch the folder's ACL.
- **Break-glass** (`--disarm [--minutes N]`, `--rearm`) needs no service: it is a drop file,
  `disarm.json` in the data folder, plus an immediate clear of the firewall rules by the command
  itself. Both verbs refuse a prompt that is not elevated. While a window is open the service holds
  no firewall rules and writes none; detection and recording go on, and bans recorded meanwhile
  are enforced when it ends. A window lasts at most **24 hours** and ends by itself, so a forgotten
  disarm cannot leave the server open; a disarm can be renewed, which is reported again.
- The drop file is trusted only as far as it can be checked, and everything fails towards
  protection. It must be owned by SYSTEM or the Administrators group, nobody else may be able to
  write to it, it must not be a link, and it must describe a window of at most 24 hours from
  now: this is checked on the file itself because a portable run leaves the folder's ACL alone,
  and a standard user may be able to create files there. A file that is expired, corrupt,
  over-long or untrusted disarms nothing and is reported once; a file that goes bad during a
  window ends it at once.
- WinGuard makes **no outbound connections** of its own; the only network traffic it can produce
  is to the notification destinations (webhook / Telegram / SMTP) an administrator explicitly
  configures. Webhook URLs and Telegram tokens are secrets and never reach the log; a plain
  `http://` webhook still works but logs a warning.

## Scope notes

- WinGuard reads Windows event logs and local log files; log *content* is treated as untrusted
  input everywhere (regex timeouts, bounded reads, SQL parameters, no DNS resolution). Line breaks
  and control characters are escaped in the log file, so a user name cannot forge a log entry.
- Traffic sniffing, kernel drivers and remote management are out of scope by design.

## Windows Event Log ids

For SIEM rules: entries in the Application log under the source `WinGuard` carry these event ids,
which are stable across releases. An id is never reassigned; new event types get new ids.

| Event ID | Type | Meaning |
|---|---|---|
| 1001 | Warning | An address was banned after repeated failures, or because it is blacklisted. |
| 1002 | Warning | An administrator blocked an address. |
| 1003 | Information | A ban expired and the address was unblocked. |
| 1004 | Warning | An administrator unblocked an address. |
| 1005 | Warning | A range ban was lifted because it came to overlap the whitelist. |
| 1006 | Warning | Notifications were dropped by the rate limit or a full queue; the message gives the count. |
| 1020 | Warning | Break-glass: enforcement was disarmed and all WinGuard firewall rules removed, or an open window was changed. |
| 1021 | Warning | Break-glass: a disarm ended and enforcement resumed. |
| 1022 | Warning | Break-glass: a disarm file was ignored (expired, corrupt or untrusted); the message gives the reason. |
| 1900 | Warning | Any other warning. |
| 1901 | Error | Any error. |
| 1902 | Information | Any other informational event. |
