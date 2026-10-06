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
- Every IP reaching the firewall is validated as a literal (or canonical CIDR with a minimum
  prefix length); hostnames and firewall tokens such as `LocalSubnet` can never be injected via
  log text.
- Over-broad list entries (`0.0.0.0/0`-style) are rejected by the IPC layer; the machine's own
  addresses are auto-whitelisted to prevent self-lockout.
- The data directory under `%ProgramData%\WinGuard` is ACL-hardened to SYSTEM + Administrators.
- WinGuard makes **no outbound connections** of its own; the only network traffic it can produce
  is to the notification destinations (webhook / Telegram / SMTP) an administrator explicitly
  configures.

## Scope notes

- WinGuard reads Windows event logs and local log files; log *content* is treated as untrusted
  input everywhere (regex timeouts, bounded reads, SQL parameters, no DNS resolution).
- Traffic sniffing, kernel drivers and remote management are out of scope by design.
