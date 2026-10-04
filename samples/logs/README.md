# Sample fixtures — expected parser results

These files are the ground truth for `WinGuard.Core.Tests` parser tests
(PLAN.md §12). Each detector's static `TryParse*` method must produce exactly
these results:

| Fixture | Parser | Expected |
|---|---|---|
| `security-4625.xml` | `RdpSecurityLogDetector.TryParse` | FailedLogin: Ip=`203.0.113.45`, User=`administrator`, Source=`Rdp`, TsUtc=`2026-10-04T09:15:32.1234567Z` |
| `security-4625-empty-ip.xml` | `RdpSecurityLogDetector.TryParse` | **false** (IpAddress is `-`; must be dropped, PLAN.md §4.1) |
| `rdpcorets-140.xml` | `RdpCoreTsDetector.TryParse` | FailedLogin: Ip=`198.51.100.23`, User=`null`, Source=`Rdp`, TsUtc=`2026-10-04T09:20:11.456789Z` |
| `mssql-18456.xml` + `mssql-18456-message.txt` | `MsSqlDetector.TryParse(xml, message, settings)` | FailedLogin: Ip=`203.0.113.77`, User=`sa`, Source=`MsSql` |
| `mssql-18456.xml` + `mssql-18456-message-ignored.txt` | `MsSqlDetector.TryParse` | **false** (matches default IgnoreMessagePatterns, PLAN.md §4.3) |
| `iis-ftp-w3c.log` | `FtpLogDetector.TryParseIisLine` | 2 failures: `203.0.113.9` (×2, user `admin`) and `198.51.100.44` (user `bob`); `PASS`+`230` and `USER` lines → false |
| `filezilla-server.log` | `FtpLogDetector.TryParseFileZillaLine` | 2 failures: `203.0.113.44`, `192.0.2.99`; only lines containing `530 Login or password incorrect!` match |
| `custom-app.log` | `CustomLogDetector.TryParseLine` with regex `LOGIN FAILED user=(?<username>\S+) ip=(?<ipaddress>\S+)` | 3 failures: `203.0.113.99` (jsmith), `203.0.113.99` (admin), `192.0.2.15` (root) |

All parsed IPs must be normalized via `IpMatcher.TryNormalize` (strip ports/brackets,
lowercase IPv6). All parsed FailedLogin.Source values: FTP → `Ftp`, custom → `Custom`.
