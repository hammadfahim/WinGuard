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

## Agent D — GUI (pending)

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
