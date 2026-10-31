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
  the setup and by `--install`, which run the same tested routine. It walks the folder without
  following a link, through handles, so nothing can be swapped under it. A standard user cannot
  make the Administrators group an owner, so the owner is what tells planted content from WinGuard's
  own, and it is read before anything changes: whatever is a link, has more than one hard link, or
  is not owned by SYSTEM or Administrators is **moved aside, never deleted and never made
  trustworthy**, into a `Quarantine-*` folder inside the data folder, with a `quarantine.txt` saying
  what came from where. A data folder that is itself foreign moves as a whole to a
  `WinGuard.quarantine-*` folder next to it, and a new one takes its place. What stays gets
  Administrators as owner and a protected DACL, each item on its own. Setup reports what it moved
  and carries on, because setup that stops at a stray file leaves a machine unprotected. It stops
  only if the folder is a link, or if something cannot be secured or moved; the service is then
  started again as it was. A portable `--console` run does not touch the folder's ACL.
- That check cannot look back. Content an older setup already made Administrators-owned stays
  trusted. Files an administrator's own account created, as opposed to the group, count as foreign;
  to keep one, give it to the group (`icacls <file> /setowner *S-1-5-32-544`) and move it back.
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
- The prerequisite checks and `--doctor` report whether Windows acts on WinGuard's rules at all
  (firewall on in every active profile, local rules honoured by Group Policy). They only read the
  policy: WinGuard never changes firewall policy, profiles or Group Policy settings.
- **Notification secrets** (SMTP password, Telegram token, webhook URL) are encrypted in the
  settings database with **DPAPI in user scope** and a WinGuard-specific entropy value, and marked
  `dpapi:`. Machine scope would let any local process decrypt them; under LocalSystem, user scope
  limits that to SYSTEM. This protects a copied database, a backup or an administrator's casual
  read of the file. It does not protect against code running as SYSTEM, or an administrator who
  can run code as SYSTEM, and the entropy is not a secret. Values stay plaintext in the service's
  memory and over the admin-only pipe, because the channels and the console need them.
- Old plaintext values keep working. The service encrypts them at its next start; a `--console`
  run leaves them alone, because whatever it encrypts only that administrator can read. A value
  that cannot be encrypted is refused, never stored in the clear.
- The old plaintext then has to leave the database files as well. That one write runs with SQLite's
  `secure_delete`, a `VACUUM` drops the copies earlier saves left in free pages and page slack, and
  a checkpoint carries the result into the main file. Windows gives a service 30 seconds to start,
  so the `VACUUM` is skipped above 64 MB, and such a file can keep old copies until SQLite reuses
  those pages. A clean-up that fails is logged and does not stop the start. Backups and copies made
  earlier are out of reach: if that matters, replace a secret that was ever stored in the clear.
- A secret that cannot be decrypted (the database moved to another machine, or `--console` reading
  what the service stored) acts as empty and is reported once, and the channel stays off. Its
  ciphertext stays in the database through every later save, so a console run cannot destroy it;
  only entering a new value replaces it. Moving WinGuard to another machine means entering the
  secrets again.
- WinGuard makes **no outbound connections** of its own; the only network traffic it can produce
  is to the notification destinations (webhook / Telegram / SMTP / syslog) an administrator
  explicitly configures. Webhook URLs and Telegram tokens are secrets and never reach the log; a
  plain `http://` webhook still works but logs a warning.
- **Syslog** is plain UDP or TCP without TLS, so events, including attacker addresses, travel
  unencrypted, and over UDP nothing confirms that a message arrived; use a trusted network or a
  local collector. Control characters in event text are escaped, so a crafted user name cannot
  forge a second message.
- **Metrics** open no port: WinGuard only writes the `.prom` file named in the settings, for
  windows_exporter to read. The path must be a full path on a local drive, because the service
  runs as SYSTEM and a network path would authenticate the machine to whatever host it names. The
  folder should be writable by administrators only; the file holds counts, flags and a timestamp,
  no addresses. Writes go through a randomly named temporary file created fresh, so a file planted
  in the folder cannot be written through.

## Scope notes

- WinGuard reads Windows event logs and local log files; log *content* is treated as untrusted
  input everywhere (regex timeouts, bounded reads, SQL parameters, no DNS resolution). Line breaks
  and control characters are escaped in the log file, so a user name cannot forge a log entry.
- **SQL Server events can be forged on a SQL host.** Interactive users, services and batch jobs may
  write to the Application log under any source name, so event 18456 counts only when its provider
  is a SQL Server instance installed on this machine (`MSSQLSERVER` or `MSSQL$NAME`, read from the
  registry and read again every few minutes). Where no SQL Server is installed these events are
  ignored. On a real SQL host, a local user can still write such events and get a chosen address
  banned: nothing in the event tells a forgery apart, and its `Security UserID` is supplied by the
  caller of `ReportEvent`, with no check Microsoft documents. If untrusted users can log on to a
  SQL host, whitelist the addresses that must stay reachable, or turn the MS SQL engine off.
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
