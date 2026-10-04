# Integration notes (collected from implementation agents)

## Agent A — Engine + Store (COMPLETED)
Files: `Core/Engine/IpMatcher.cs`, `Core/Engine/BanEngine.cs`, `Core/Store/SqliteStore.cs`

- Contract conformance: clean. Two benign supersets:
  - `IpMatcher.TryParseCidr` masks host bits (`192.168.1.5/24` -> `192.168.1.0/24`) instead of failing.
  - `TryNormalize` rejects legacy short forms (`1.2.3`) — good for §11 anti-injection.
  - IpMatcher ctor params annotated `IEnumerable<string>?` (source-compatible).
- **Tier escalation persistence (REVIEW TOPIC):** PLAN §5 housekeeping says "delete from
  bans" on expiry, which loses `offense_count` → escalation would never progress (step 4
  skips already-banned IPs, so re-offense only happens after expiry). Agent A keeps an
  in-memory offense-count dictionary (seeded from active bans at start) so 24h→7d→30d
  works within a process lifetime; resets on service restart. Durable alternative: keep
  expired ban rows (filter by expires_utc) — deviates from plan's "delete". → Have
  deepseek-v4-pro reviewer (Phase 3) rule on this.
- Counting is per-protocol (`CountFailedLoginsAsync(ip, since, source)`); ban clears all
  sources' counters, per plan.
- Lists hot-reload on every housekeeping pass (15 s). For instant effect after IPC list
  mutations, service can call `engine.HousekeepOnceAsync()` → wire into PipeServer
  (WhitelistAdd/BlacklistAdd/ListRemove/Unblock+AlsoWhitelist handlers).
- `BanNowAsync`: invalid IP → `ArgumentException`; whitelisted → `InvalidOperationException`
  → PipeServer must catch and return `IpcResponse.Fail`. Null duration (non-permanent)
  defaults to tier 1 (24h), capped at MaxBanDuration. `UnbanAsync` idempotent.
- Housekeeping reconciles both directions (re-block missing, orphan-rule cleanup).
- SqliteStore lazily self-initializes; still call `InitializeAsync` at startup.
  `GetActiveBansAsync` uses wall-clock `DateTime.UtcNow` (no TimeProvider in IStore).
- Expected GuardWorker wiring: `store.InitializeAsync` → `engine.StartAsync` →
  `engine.RunAsync(channel.Reader, ct)`; `engine.StopAsync()` on shutdown. BanEngine runs
  its own housekeeping loop.
- Uncompiled (per no-build rule). Likely friction spots: nullable annotation on IpMatcher
  ctor, `System.Net.IPNetwork` host-bit masking path, `IPAddress.IsIPv6UniqueLocal` usage.

## Agent B — Detection (COMPLETED)
Files: `Core/Detection/{ExclusionEvaluator, LogFileTailer, RdpSecurityLogDetector,
RdpCoreTsDetector, MsSqlDetector, FtpLogDetector, CustomLogDetector}.cs`. Parsers match
the fixture table; IPs via IpMatcher.TryNormalize; graceful degradation on missing
channels; MSSQL primary XPath uses TolerateQueryErrors=false so the EventID-only
provider-filter fallback actually engages.

### Deviations/additions (benign)
- `RdpCoreTsDetector` ctor added: `(Func<WinGuardSettings>, ILogger<RdpCoreTsDetector>,
  TimeProvider? = null)` — same shape as others; matches what Agent C was told. ✔
- `MatchesWildcard(string?, string?)` nullable params (source-compatible).
- Custom-source tailing reuses `Defaults.FtpPollInterval` (3 s) — no per-source interval
  setting; acceptable for MVP.
- Static FTP/custom parsers stamp `DateTime.UtcNow`; live loops overwrite with injected
  TimeProvider. Event-log parsers use `SystemTime` (keeps 4625↔140 de-dup accurate).

### ⚠ RECONCILE #3: exclusion value case-sensitivity
- B: wildcard/equality comparisons fully case-INSENSITIVE (fields and values).
- E assumed: case-insensitivity on FIELD NAMES only, values case-sensitive.
- Check E's `ExclusionEvaluatorTests` — if a test asserts case-sensitive value behavior,
  prefer B's case-insensitive semantics and adjust the test.

### Notes for Phase 2/3
- DI: detectors take `(Func<WinGuardSettings>, ILogger<T>, TimeProvider? = null)`.
  MS.DI honors default values; if resolution complains, register `TimeProvider.System`
  or construct detectors explicitly in Program.cs.
- **LogFileTailer first-sight = offset 0** (1 MB/cycle cap): fresh install over big
  legacy FTP logs processes old failures once → possible mass-ban on first run.
  REVIEW TOPIC (Phase 3): consider "skip to end on first sight" option.
- `Rdp.Enabled && Rdp.UseRdpCoreTsFallback` gate for the 140 watcher; FTP/custom
  re-check Enabled each cycle.

## Agent C — Firewall + Service (COMPLETED)
Files: `Core/Firewall/WindowsFirewall.cs`, `Service/{Program.cs, SettingsHolder.cs,
DetectorRuntimeState.cs, GuardWorker.cs, Ipc/PipeServer.cs,
Logging/FileLoggerProvider.cs, appsettings.json}`. Service csproj unchanged; no new
packages. Confirms A's and B's signatures matched its usage exactly (good omen).

### Deviations/additions (benign)
- `WindowsFirewall` ctor: `(ILogger<WindowsFirewall>, int maxAddressesPerRule = 1000,
  Func<WinGuardSettings>? settingsAccessor = null)` — additive optional param for
  BlockedPorts support (TCP+UDP rule pair `WinGuard_Block_NNNN_TCP/_UDP` sharing the
  address batch; stale variants cleaned on mode switch). All-ports mode = exact plan
  naming. E's integration test uses 1-arg ctor → still compiles. ✔
- Pipe ACL: plain `NamedPipeServerStream` + connect-time authorization via
  `RunAsClient` + `WindowsPrincipal` (Admins/LocalSystem/LocalService/NetworkService
  allowed, fail-closed) — NOT a pipe DACL (System.IO.Pipes.AccessControl is a separate
  package; zero-new-packages rule). → **Phase 3 security review topic** (glm-5.3):
  is connect-time impersonation check sufficient vs DACL? (OS default DACL is broader.)
- `--help` verb added; auditpol CSV parse tolerates UTF-16 nulls + localized headers;
  MpsSvc probe via advapi32 P/Invoke; RdpCoreTS channel probe via EventLogConfiguration.

### ⚠ RECONCILE #4: BlacklistAdd does NOT immediately ban
- C followed the literal spec: list value recorded only; permanent ban materializes on
  next detection (PLAN §5 step 3). RdpGuard-style UX = block immediately when admin
  blacklists an active attacker. Proposed Phase 2 fix: in PipeServer.BlacklistAddAsync,
  if the value is a SINGLE IP (not CIDR) → also `engine.BanNowAsync(ip, null,
  permanent: true, "blacklist")`. CIDR entries stay detection-time only (firewall
  batching MVP validates single IPs). Confirm in review.
- WhitelistAdd already unbans + removes from blacklist (per prompt). ✔

### ⚠ RECONCILE #5: detector hot-toggle gap
- Detectors start once (gated by Enabled at startup); UpdateSettings hot-swaps settings
  but does not stop/start watchers. `Enabled` (status) = live settings; `Running` =
  startup success. B's file pollers (FTP/custom) re-check Enabled each cycle ✔;
  event-log detectors may not gate per-event → CHECK B's code in Phase 2; if ungated,
  add cheap `settings().X.Enabled` check in the event handler path so GUI toggles are
  honest without service restart. Document residual: enabling a DISABLED-at-startup
  engine requires service restart (MVP).

### Other notes
- All IFirewall methods try/catch+log — firewall failures never kill engine/IPC.
- Store init + settings load happen before host.RunAsync. ✔
- GuardWorker: channel SingleReader, per-detector failure isolation. ✔

## Agent D — GUI (COMPLETED)
Files: full WPF app under src/WinGuard.Gui/ — App, MainWindow (left nav, 5 views via
ContentControl+DataTemplates, theme toggle, connection pill, close-to-tray),
Views/{Dashboard,BlockedIps,EventLog,Settings,Lists}, ViewModels (12), Services
{PipeClient (JSON-lines, 5 s timeout, 2 s reconnect loop), TrayIconService (runtime-drawn
shield, NotifyIcon), StatusPoller (2 s DispatcherTimer)}, Themes/{Dark,Light}, converters.
csproj edit (sole owner): `<Using Remove>` for WinForms/Drawing implicit usings that
collide with WPF types. **Compiled first try, 0 warnings.**
- Deviations: SendAsync (not CallAsync) — internal only; Custom tile toggles all
  CustomSources[*].Enabled (no global Custom flag — matches settings model);
  SqlAuditingHint not shown in banner (would always display); right-click selects row
  for context commands. All benign.

---

# RESOLUTIONS (Phase 2 integration, commit 6b7b491)

- **RECONCILE #1 (expired-ban visibility): FIXED.** Added `IStore.GetDueBansAsync(nowUtc)`
  (SqliteStore: `is_permanent = 0 AND expires_utc <= $now`; FakeStore mirrors; engine
  housekeeping uses it — engine TimeProvider authoritative). Production auto-unban +
  UNBANNED events + row deletion now work with the real store.
- **RECONCILE #2 (list load timing): OK as built.** StartAsync reloads lists; tests pass.
- **RECONCILE #3 (wildcard semantics): FIXED in test.** Anchored glob semantics kept
  (B correct); test case "a*a" vs "administrator" flipped to false + positive case added.
- **RECONCILE #4 (BlacklistAdd): FIXED.** Single-IP blacklist entries now ban immediately
  (permanent, note "blacklist"); CIDRs apply at detection time; whitelist-wins conflicts
  logged, not errors.
- **RECONCILE #5 (hot-toggle): FIXED.** All three event-log detectors now gate per event
  on Enabled (+ UseRdpCoreTsFallback). Enabling a startup-disabled engine still requires
  service restart (MVP, document in README). List mutations via IPC call
  HousekeepOnceAsync for instant matcher reload.
- Build fixes during integration: NamedPipeServerStream 5-arg overload + PipeTransmissionMode.Byte;
  `using WinGuard.Core.Detection` in PipeServer; MsSqlDetector TryFormatDescription takes
  EventRecord (casts to EventLogRecord); WindowsFirewall dynamic→typed `List<RuleBatch>`
  binding + RuleBatch rule handles as fields (ref-able); nullable fixes (TryRemove KVP
  overload, WindowsIdentity null-guard).
- **Status: `dotnet build WinGuard.sln -c Release` = 0 warnings / 0 errors;
  `dotnet test --filter Category!=Integration` = 92/92 passed; `winguard-svc --help` OK.**

# Phase 3 review topics (open questions for reviewers)
1. Offense-count/escalation durability across service restarts (in-memory map; expired
   ban rows deleted per PLAN §5) — acceptable for MVP or persist offense counts?
2. Pipe authorization = connect-time impersonation check (Admins/LocalSystem/services,
   fail-closed), not a pipe DACL (zero-new-packages constraint) — sufficient?
3. LogFileTailer reads unseen files from offset 0 (1 MB/cycle cap) — mass-ban risk on
   fresh installs over legacy logs; add "skip to end on first sight"?
4. Custom sources reuse FtpPollInterval (no own interval setting).
5. GetStatus `Running` = startup success (enabling at runtime needs restart).

---

# Phase 3 findings log

## Reviewer 2 — deepseek-v4-pro (engine correctness) — DONE
Verdict: no CRITICAL; _gate concurrency model sound; reconcile race-free (i4); expiry
ordering correct + self-healing (i5); ToDb/FromDb "o"-format round-trip sound (i6);
window boundaries correct (i1-i3).

- **M1 (MAJOR): RDP de-dup is a global 1-per-2s rate limit, not 4625↔140 pair merge.**
  Two DISTINCT 4625 attempts ≤2 s apart → second suppressed → attacker needs ~9 real
  attempts to reach threshold 5. Fix plan: add discriminator (FailedLogin.Detector =
  "4625"/"140"), suppress ONLY across different detectors; move de-dup to an in-memory
  recent-events map (no schema change; store rows lack the discriminator). Update the
  two de-dup tests (h.Fail must set Detector; same-detector 1 s apart now counts twice —
  add that case).
- **M2 (MAJOR): _offenseCounts never pruned → unbounded growth.** Fix with ruling (c)
  pruning below.
- **M3 (MAJOR-arch): SqliteStore.GetActiveBansAsync uses wall clock.** Harmless in prod
  (TimeProvider.System); expiry loop already uses GetDueBansAsync and runs BEFORE
  reconcile. ACCEPT option (b): document in IStore XML comment (status/startup/reconcile
  use only).
- **M4 (MAJOR): UnbanAsync doesn't clear _offenseCounts → escalation resumes after
  manual unban.** Fix: remove entry + re-save persisted blob.
- **RULING topic #1 = option (c): persist offense counts in settings table under key
  "offense_counts"** (JSON blob {"ip": {count, lastUtc}}): load+merge (max) at StartAsync,
  save after each ban/unban change, prune entries with no active ban and
  lastUtc < now − ExpireTime×4 during housekeeping. Zero schema changes.
- m1 (MinValue clamp — unreachable): leave; m2 (FakeTimeProvider no CreateTimer):
  document limitation; m3/m4/m5: no action.

## Reviewer 1 — glm-5.3 (security) — DONE
Verdict: NO critical holes (IP validation solid, SQL parameterized, no XXE, pipe writes
OS-restricted). "Not safe to ship as-is; safe as MVP after focused hardening."
Ship conditions: M1, M3, M4, M6 + M2 (Groups-SID/DACL option, keeps GUI non-elevated per
PLAN §9) — then M5, M7, N1-N6 promptly.

### FIX CHECKLIST (Phase 3b)
- **S-M1 (2 lines):** PipeServer.IsAuthorized — DELETE LocalService/NetworkService
  branches; keep SYSTEM + Administrators only (PLAN §8).
- **S-M2:** (a) Authorize: replace IsInRole with identity.Groups contains
  Administrators SID (S-1-5-32-544) or LocalSystem SID (S-1-5-18) — works for
  UAC-filtered tokens (deny-only SID still in Groups); (b) pipe DACL via P/Invoke:
  ConvertStringSecurityDescriptorToSecurityDescriptor SDDL
  `D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)` + CreateNamedPipeW w/ SECURITY_ATTRIBUTES
  + PIPE_REJECT_REMOTE_CLIENTS, wrap handle in NamedPipeServerStream(SafePipeHandle,...)
  — removes Everyone/Anonymous read (kills N2 flood) and lets non-elevated admin GUI
  connect (plan-compliant; NOT the elevate-GUI shortcut).
- **S-M3 (topic #3 ruling = fix):** (1) LogFileTailer: first-sight cursor = end-of-file
  (rotation-shrink still resets to 0); (2) FtpLogDetector.TryParseIisLine: parse
  date+time columns (UTC per W3C convention) into TimestampUtc (fallback now);
  TryParseFileZillaLine: parse leading `(nnnnnn) yyyy-MM-dd HH:mm:ss` as LOCAL →
  ToUniversalTime. Custom keeps now-stamp (skip-to-end covers replay). Engine's rolling
  window then discards any stale replays for free.
- **S-M4:** installer [UninstallRun]/[Code]: wait for service STOPPED (sc query loop)
  BEFORE --clear-firewall; Program.cs --clear-firewall: after ClearAll, verify
  ListBlocked() empty → exit non-zero otherwise; WindowsFirewall.ClearAll: track failure
  (return/throw-flag) so exit code is honest.
- **S-M5:** installer [Run]: icacls "%ProgramData%\WinGuard" /inheritance:r /grant:r
  SYSTEM:F Administrators:F (after [Dirs]); SqliteStore init: best-effort
  SetNamedSecurityInfo P/Invoke same SDDL (try/catch, log).
- **S-M6 (1 line + tests):** IpMatcher.TryNormalize: `if (address.IsIPv4MappedToIPv6)
  address = address.MapToIPv4();` before final ToString. Tests: ::ffff:203.0.113.5,
  0:0:0:0:0:ffff:203.0.113.5 → "203.0.113.5"; whitelist match across forms.
- **S-M7:** PipeServer Unblock+AlsoWhitelist: add whitelist row → HousekeepOnceAsync →
  UnbanAsync (mirror WhitelistAdd). BanEngine.UnbanAsync: also
  _store.ClearFailedLoginsAsync(ip) + _offenseCounts.Remove + persist (clean slate;
  merges with E-M4).
- **S-N1:** CustomLogDetector: cached `new Regex(pattern, CultureInvariant,
  TimeSpan.FromSeconds(2))` per source; catch RegexMatchTimeoutException → skip+warn.
- **S-N2:** rejection logging rate-limited (1/100 + counter summary); FileLoggerProvider:
  delete files >30 d, skip writes past ~10 MB/day-file (log once).
- **S-N3:** PipeServer: max line 1 MB (bounded read loop, disconnect on overflow);
  ListEvents Limit clamp ≤1000; WinGuardSettings.Normalize: BlockedPorts tokens must
  match ^\d+(-\d+)?$ (drop invalid), BanTiers positive-only (drop ≤0).
- **S-N4:** IStore += PruneEventsAsync(olderThanUtc); SqliteStore DELETE events WHERE
  ts_utc < $before; FakeStore mirror; HousekeepCoreAsync prunes events older than 30 d
  (const DefaultEventRetentionDays=30).
- **S-N5 (DEFER):** firewall batch caching — document as known limitation (throughput
  under storm), post-MVP.
- **S-N6:** release.yml: add sha256 assets (Get-FileHash → .sha256 files uploaded);
  SHA-pin actions if verifiable SHAs obtainable, else keep tags + PLAN M7 comment.
- **S-INFO:** persist list values in TryParseCidr-normalized form; remove dead PipeName
  from appsettings.json; reject list prefixes shorter than /8 (footgun: 0.0.0.0/0) with
  clear IPC error; document /0 guard. Topics #4/#5 agreed as built → README: document
  enable-needs-restart + shared custom poll interval.

### Cross-review synthesis
- Topic #1: deepseek ruling (c) persist offense_counts in settings WINS over glm's
  "acceptable for MVP" — implement (c) (also fixes E-M2 growth via pruning).
- Topic #3: both agree → fix per S-M3.

## Reviewer 3 — qwen3.8-max (detection/packaging) — DONE
Verdict: detection fidelity vs real formats verified correct across the board (XPaths,
field extraction, W3C header-driven columns, FileZilla markers, exclusion semantics,
TolerateQueryErrors fallback call). Two CRITICAL release-pipeline bugs + installer gaps.

### FIX CHECKLIST (Phase 3b, detection/packaging)
- **P-C1 (CRITICAL):** release.yml GUI publish += `-p:IncludeNativeLibrariesForSelfExtract=true`
  (else WPF native DLLs stay loose; installer packages exe only → GUI crashes at launch).
- **P-C2 (CRITICAL):** release.yml ISCC path: `"${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"`
  (pwsh doesn't expand `$env:ProgramFiles(x86)` — inherited from PLAN §14).
- **P-M1:** README: document enable-needs-service-restart limitation + custom sources
  share Ftp.PollInterval + /8 list-prefix guard.
- **P-M2:** = S-M3 (tailer skip-to-end + line-timestamp parsing) — consolidated.
- **P-M3:** iss upgrade path: PrepareToInstall stops existing service + waits; sc create
  only when absent; sc start after.
- **P-M4:** auditpol subcategory → locale-independent GUID
  `{0CCE9215-69AE-11D9-BED3-505054503030}` (iss + README).
- **P-m1:** FileZilla "(not logged in)" → UserName null; support bare-name `user (ip)>`
  shape; test asserts.
- **P-m2 (=S-N1):** custom regex: 2 s match timeout, cached per source; invalid pattern
  → LogWarning once/source, skip.
- **P-m3 (topic #4 ruling):** CustomLogDetector honors settings().Ftp.PollInterval
  (fallback Defaults.FtpPollInterval); shared interval accepted for MVP.
- **P-m4:** iss uninstall: silent-mode guard on data prompt; DelTree moved to
  usPostUninstall (after service stopped/deleted).
- **P-m5:** RdpCoreTS 140: positional first-Data fallback when IPString name missing.
- **P-m6:** iss ArchitecturesAllowed/InstallIn64BitMode → x64compatible (Inno 6.3+).
- **S-N6:** release.yml: sha256 checksums for assets; SHA-pin actions before going
  public (PLAN M7) — comment for now.
- **PLAN.md errata (append-only §18):** C1, C2, auditpol GUID.

### Execution split (Phase 3b)
- Fixer agent 1 (deepseek-v4.1-flash): Detection D1-D9 (tailer skip-to-end + option,
  FTP/FileZilla timestamp parsing, FileZilla username, 140 fallback, Detector
  discriminator stamps, custom regex timeout/poll interval, tests, samples README).
- Fixer agent 2 (deepseek-v4.1-flash): installer/CI/docs I1-I10 above.
- Me (integrator): FailedLogin.Detector ✔, IStore.PruneEventsAsync (+Sqlite/Fake),
  IpMatcher mapped-IPv4, BanEngine (detector-aware dedup, offense_counts persistence
  per ruling (c), UnbanAsync clean slate, event pruning), WinGuardSettings.Normalize
  validation, PipeServer (auth SIDs, DACL P/Invoke + reject remote, Unblock ordering,
  line cap, Limit clamp, list normalization + /8 guard), Program/WindowsFirewall honest
  --clear-firewall exit, FileLoggerProvider retention, appsettings PipeName removal,
  BanEngine/IpMatcher test updates. Then: full build + tests + commit.

---

# Phase 3b COMPLETE — all fixes landed

## Integrator additions beyond the checklists
- **IIS #Fields header pre-read** (fixer-agent note #1): skip-to-end would starve the
  W3C column order for existing files → FtpLogDetector now pre-reads the last 64 KB of
  each IIS log once per run to recover the active `#Fields:` header.
- **Escalation quiet-period semantics**: stale-offense pruning (ExpireTime×4) now counts
  from ban END, not ban issue (expiry refreshes _offenseLastUtc) — otherwise 7d/30d bans
  would outlive their own offense record. Caught by Tier_escalation test.
- **auditpol localization** (fixer note #3): PipeServer query switched to the Logon
  subcategory GUID + locale-independent numeric "Setting Value" parse (bit 2 = failure);
  GUI warning text uses the GUID form.
- **Uninstall MsgBox silent-gating** (fixer note #2) + README GUI publish flag (note #4).

## Live smoke-test findings (winguard-svc --console, non-elevated)
- ✅ Pipe server (P/Invoke secured DACL) listens; firewall COM enumeration works; all
  detectors subscribe or degrade gracefully; engine starts; 105/105 tests green.
- 🐛 FIXED: `Host.CreateApplicationBuilder(Args = [])` dropped CLI config →
  `--DatabasePath` now honored (verb filtered out before the command-line provider).
- 🐛 FIXED (silent no-op!): `SetNamedSecurityInfo` was passed the whole security
  descriptor instead of the extracted DACL (returned 0, changed nothing). Now via
  `GetSecurityDescriptorDacl`; SDDL hardened to `D:PAI(...)` (protected, no inheritance,
  mirrors installer icacls /inheritance:r); failure paths raised Debug→Warning.
  Verified live: explicit SY+BA ACEs applied.

## Deferred (documented, post-MVP)
- S-N5 firewall batch caching (throughput under distributed storm).
- Action SHA-pinning (PLAN M7, before repo goes public) — comment added in release.yml;
  sha256 checksum assets ARE generated now.
- Offense-count regex-cache pruning in CustomLogDetector (harmless growth on edits).

## Agent E — Tests + Installer + CI (COMPLETED)
Files: tests/WinGuard.Core.Tests/** (Fakes, TestData, Detection/*, Engine/*, Store/*,
Firewall integration test), installer/winguard.iss + assets/license.txt,
.github/workflows/{ci,release}.yml, README.md, LICENSE. No csproj edits.

### ⚠ RECONCILE #1 (critical, Phase 2): expired-ban visibility
- E's `FakeStore.GetActiveBansAsync` returns **ALL bans incl. expired** — because
  `BanEngine.HousekeepOnceAsync` must discover due bans via the store to unblock them.
- A's `SqliteStore.GetActiveBansAsync` follows the IStore doc ("permanent or not yet
  expired", wall-clock filter). If A's engine relies on the store to surface
  expired-but-undeleted bans, production expiry would silently fail (row invisible the
  moment it expires; only A's orphan-rule cleanup would eventually pull the firewall
  rule, without UNBANNED event or row deletion → DB leak).
- FIX OPTIONS: (a) change IStore semantics: GetActiveBansAsync = all rows, engine
  filters by its TimeProvider (also update PipeServer status counts to filter); or
  (b) add `GetDueBansAsync(DateTime nowUtc)`/`GetExpiredBansAsync` to IStore + both
  stores + FakeStore. Decide after reading A's BanEngine.cs/SqliteStore.cs.

### ⚠ RECONCILE #2: whitelist/blacklist load timing
- E's tests seed lists in FakeStore BEFORE `engine.StartAsync` and expect them honored
  on the first `ProcessAsync` (no housekeeping pass yet). A reloads lists on every
  housekeeping pass — verify A's StartAsync ALSO loads store lists into the in-memory
  IpMatcher synchronously (A's note only mentions GetLocalAddresses at startup).
  If not: make StartAsync load lists (+ local IPs) before returning.

### E's other assumptions (verify vs A/B code in Phase 2)
- BanEngine persists offense counts across expiry/unban within process (A: in-memory
  map — consistent).
- Wildcard `*` = anchored greedy, case-insensitivity on FIELD NAMES only, not values
  (B's ExclusionEvaluator must match — B was told case-insensitive field lookup;
  value-case unspecified in contracts → check B's impl aligns with E's tests).
- Engine tests use MsSql source for threshold/window/tier scenarios (avoids RDP 2 s
  de-dup); RDP de-dup tested separately.
- Integration firewall test: early-return admin/OS guard, constructs WindowsFirewall
  with `(ILogger<WindowsFirewall>)` only.
- SqliteStore ctor `(string, ILogger<SqliteStore>)` — matches A.
- Installer icon: script-relative `assets\icon.ico` behind `#if FileExists`; CI stages
  `installer/assets/*` into `dist\` per PLAN §14 (no binary icon committed — OK).
