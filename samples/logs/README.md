# Sample fixtures — expected parser results

These files are the ground truth for `WinGuard.Core.Tests` parser tests
(PLAN.md §12). Each detector's static `TryParse*` method must produce exactly
these results:

| Fixture | Parser | Expected |
|---|---|---|
| `security-4625.xml` | `RdpSecurityLogDetector.TryParse` | FailedLogin: Ip=`203.0.113.45`, User=`administrator`, Source=`Rdp`, Detector=`4625`, TsUtc=`2026-10-04T09:15:32.1234567Z` |
| `security-4625-empty-ip.xml` | `RdpSecurityLogDetector.TryParse` | **false** (IpAddress is `-`; must be dropped, PLAN.md §4.1) |
| `security-4624.xml` | `LogonSuccessDetector.TryParse` | Success: Ip=`203.0.113.45`, User=`administrator`, Source=`Rdp`, Detector=`4624`, LogonType=`10`, TsUtc=`2026-10-04T09:21:47.7654321Z`. Field layout from Microsoft's [event 4624 reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624); not captured from a live server |
| `security-4624-anonymous.xml` | `LogonSuccessDetector.TryParse` | **false** (ANONYMOUS LOGON, a null session: type 3 with a client address, but no password was proven) |
| `rdpcorets-140.xml` | `RdpCoreTsDetector.TryParse` | FailedLogin: Ip=`198.51.100.23`, User=`null`, Source=`Rdp`, Detector=`140`, TsUtc=`2026-10-04T09:20:11.456789Z` |
| `mssql-18456.xml` + `mssql-18456-message.txt` | `MsSqlDetector.TryParse(xml, message, settings)` | FailedLogin: Ip=`203.0.113.77`, User=`sa`, Source=`MsSql`, Detector=`18456` |
| `mssql-18456.xml` + `mssql-18456-message-ignored.txt` | `MsSqlDetector.TryParse` | **false** (matches default IgnoreMessagePatterns, PLAN.md §4.3) |
| `iis-ftp-w3c.log` | `FtpLogDetector.TryParseIisLine` | 3 failures: `203.0.113.9` (×2, user `admin`, TsUtc `09:00:05Z` then `09:00:12Z`) and `198.51.100.44` (user `bob`, TsUtc `09:01:09Z`); Detector=`iis-ftp`; `PASS`+`230` and `USER` lines → false |
| `filezilla-server.log` | `FtpLogDetector.TryParseFileZillaLine` | 3 failures: `203.0.113.44` and `192.0.2.99` (both user `null`, pre-login `(not logged in)`) and `203.0.113.55` (user `bob`, bare-name shape); Detector=`filezilla`; only lines containing `530 Login or password incorrect!` match |
| `custom-app.log` | `CustomLogDetector.TryParseLine` with regex `LOGIN FAILED user=(?<username>\S+) ip=(?<ipaddress>\S+)` | 3 failures: `203.0.113.99` (jsmith), `203.0.113.99` (admin), `192.0.2.15` (root) |
| `hmailserver.log` | `CustomSourceRecipes.HMailServer` | 8 failures: `203.0.113.61` (×2, SMTP), `203.0.113.63`, `.64`, `.65` (POP3), `203.0.113.66`, `2001:db8::66`, `203.0.113.67` (IMAP); user `null`. Successes, `RECEIVED:` lines and outgoing `SMTPC` lines → false |
| `hmailserver_awstats.log` | `CustomSourceRecipes.HMailServer` | no matches: this log records deliveries only, never logins |
| `iis-http-w3c.log` | `CustomSourceRecipes.IisHttpAuth` | 4 failures: `203.0.113.81` (admin), `203.0.113.82` (`EXAMPLE\bob`), `2001:db8::83` (root), `203.0.113.84` (svc). The `401 2 5` challenge, the `401 1 2148074254` NTLM step, other 401.x and non-401 lines → false |
| `realvnc-server.log` | `CustomSourceRecipes.Vnc` | 6 failures: `203.0.113.91`–`.93`, `2001:db8::94` (`[AuthFailure]`), `203.0.113.95`, `.96` (blacklisted). Other disconnects, `[AuthError]`, `authenticated` and `Closed` lines → false |
| `openssh-sshd.log` | `CustomSourceRecipes.WindowsOpenSsh` | 3 failures: `203.0.113.97` (root), `203.0.113.98` (oracle), `203.0.113.99` (user `x from 198.51.100.9 port 1`: the address comes from the end of the line) |

### Where the recipe formats come from

- **hMailServer**: `Logger.cpp`, `SMTPConnection.cpp`, `POP3Connection.cpp` and the IMAP login commands in
  the [hMailServer source](https://github.com/hmailserver/hmailserver). The columns are tab-separated:
  `"SMTPD"`, thread, session, `"time"`, `"client ip"`, `"text"`. `AWStats.cpp` shows that
  `hmailserver_awstats.log` holds delivery results and no authentication data. Commands are split at CRLF and
  the logger only rewrites CRLF, so a bare LF in client text reaches the log: the recipe sets `CrLfRecords`.
- **IIS HTTP**: the default W3C fields; Microsoft's
  [HTTP status code list](https://learn.microsoft.com/en-us/troubleshoot/developer/webapps/iis/health-diagnostic-performance/http-status-code)
  for the 401.x meanings, and Splunk's
  [Decoding IIS Logs](https://www.splunk.com/en_us/blog/tips-and-tricks/decoding-iis-logs.html) for
  `2148074254` on the first access of an integrated login and `2148074252` for credentials that could not be
  verified. Microsoft's
  [IIS support blog](https://techcommunity.microsoft.com/t5/iis-support-blog/401-1-2148074248-in-iis-logs-behind-a-load-balancer-with/ba-p/2428459)
  calls `401 2 5` and `401 1 2148074254` normal (seen in a search excerpt only; the page would not load).
- **RealVNC**: the line published in
  [fail2ban discussion 3034](https://github.com/fail2ban/fail2ban/discussions/3034), and RealVNC's
  [logging article](https://help.realvnc.com/hc/en-us/articles/360002254238-All-About-Logging) for the log
  location. No sample of the Windows file itself was available, so the `vncserver.exe` prefix in the fixture
  is modelled on the published Linux lines; the recipe tolerates a prefix and none.
- **TigerVNC** (the blacklisted line): `common/rfb/VNCServerST.cxx` in the
  [TigerVNC source](https://github.com/TigerVNC/tigervnc). It logs `Closed:` without a reason, which is why
  the recipe no longer treats a closed connection as a failure.

All parsed IPs must be normalized via `IpMatcher.TryNormalize` (strip ports/brackets,
lowercase IPv6). All parsed FailedLogin.Source values: FTP → `Ftp`, custom → `Custom`.

## Timestamps

Failure timestamps come from the **log/event line**, never from the poller clock:

- **Event logs** (`4625`, `140`, `18456`): `System/TimeCreated/@SystemTime` parsed as UTC.
- **IIS W3C FTP**: the `date` + `time` columns (located via the `#Fields:` header; default
  order when absent) are UTC, parsed as `yyyy-MM-dd HH:mm:ss`. In the fixture:
  `2026-10-04 09:00:05` → `2026-10-04T09:00:05Z` and `2026-10-04 09:01:09` →
  `2026-10-04T09:01:09Z`.
- **FileZilla**: the leading `(nnnnnn) yyyy-MM-dd HH:mm:ss` stamp is **local** time and is
  converted with `.ToUniversalTime()`. The fixture's `09:05:20`, `09:06:55` and `09:07:20`
  local stamps therefore map to the machine's local UTC offset; tests compute the expected
  value with the same conversion so they are time-zone independent.
- **Custom log sources**: the regex has no guaranteed timestamp capture, so the failure
  timestamp is the **ingest (poll) time** (`DateTime.UtcNow`).
- Any parser that cannot read a timestamp falls back to `DateTime.UtcNow`.

## Detector discriminator

Every failure is stamped with `FailedLogin.Detector` so the BanEngine can tell apart the two
RDP sources and for diagnostics: `4625` (Security), `140` (RdpCoreTS), `18456` (MS SQL),
`iis-ftp` / `filezilla` (FTP by source kind), and the `CustomLogSource.Name` (or `custom`
when unnamed) for custom sources. Only the cross-detector `4625`/`140` pair describes the
same RDP attempt and is de-duplicated.

## First-sight / restart behavior

`LogFileTailer` positions its cursor at the **end of a file the first time it sees it**
(skip-to-end), so a service restart never replays historical failures already present in an
FTP/custom log — this prevents a mass-ban on a fresh install over a large legacy log.
Rotation/truncation is still detected (the file's identity changes, or it shrinks) and resets
the cursor to 0 so the replacement file is read fully. The old file continues from where it
stopped if it reappears under a watched name, so it is not counted twice. Tests/tooling can opt
into reading existing content by constructing `new LogFileTailer(processExistingContent: true)`.

## Encoding

The BOM at the start of a file selects UTF-8, UTF-16 or UTF-32, also when the first read skips
to the end; a file without a BOM is read as UTF-8.