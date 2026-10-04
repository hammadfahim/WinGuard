# Sample fixtures — expected parser results

These files are the ground truth for `WinGuard.Core.Tests` parser tests
(PLAN.md §12). Each detector's static `TryParse*` method must produce exactly
these results:

| Fixture | Parser | Expected |
|---|---|---|
| `security-4625.xml` | `RdpSecurityLogDetector.TryParse` | FailedLogin: Ip=`203.0.113.45`, User=`administrator`, Source=`Rdp`, Detector=`4625`, TsUtc=`2026-10-04T09:15:32.1234567Z` |
| `security-4625-empty-ip.xml` | `RdpSecurityLogDetector.TryParse` | **false** (IpAddress is `-`; must be dropped, PLAN.md §4.1) |
| `rdpcorets-140.xml` | `RdpCoreTsDetector.TryParse` | FailedLogin: Ip=`198.51.100.23`, User=`null`, Source=`Rdp`, Detector=`140`, TsUtc=`2026-10-04T09:20:11.456789Z` |
| `mssql-18456.xml` + `mssql-18456-message.txt` | `MsSqlDetector.TryParse(xml, message, settings)` | FailedLogin: Ip=`203.0.113.77`, User=`sa`, Source=`MsSql`, Detector=`18456` |
| `mssql-18456.xml` + `mssql-18456-message-ignored.txt` | `MsSqlDetector.TryParse` | **false** (matches default IgnoreMessagePatterns, PLAN.md §4.3) |
| `iis-ftp-w3c.log` | `FtpLogDetector.TryParseIisLine` | 3 failures: `203.0.113.9` (×2, user `admin`, TsUtc `09:00:05Z` then `09:00:12Z`) and `198.51.100.44` (user `bob`, TsUtc `09:01:09Z`); Detector=`iis-ftp`; `PASS`+`230` and `USER` lines → false |
| `filezilla-server.log` | `FtpLogDetector.TryParseFileZillaLine` | 3 failures: `203.0.113.44` and `192.0.2.99` (both user `null`, pre-login `(not logged in)`) and `203.0.113.55` (user `bob`, bare-name shape); Detector=`filezilla`; only lines containing `530 Login or password incorrect!` match |
| `custom-app.log` | `CustomLogDetector.TryParseLine` with regex `LOGIN FAILED user=(?<username>\S+) ip=(?<ipaddress>\S+)` | 3 failures: `203.0.113.99` (jsmith), `203.0.113.99` (admin), `192.0.2.15` (root) |

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
Rotation/truncation is still detected (the file shrinks) and resets the cursor to 0 so the
rotated file is read fully. Tests/tooling can opt into reading existing content by
constructing `new LogFileTailer(processExistingContent: true)`.