using System.Globalization;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using WinGuard.Core.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Model;

namespace WinGuard.Core.Engine;

/// <summary>
/// The fail2ban core (PLAN.md §5). Consumes normalized <see cref="FailedLogin"/> records,
/// counts them in a rolling window, escalates through the configured ban tiers and applies
/// firewall blocks; a housekeeping loop expires bans, prunes stale counters and self-heals
/// the firewall from the database.
/// <para>
/// The engine never blocks a whitelisted or (by default) an internal IP. It is the only
/// component that interprets policy; detectors only report failures.
/// </para>
/// </summary>
public sealed partial class BanEngine
{
    private readonly IStore _store;
    private readonly IFirewall _firewall;
    private readonly Func<WinGuardSettings> _settingsAccessor;
    private readonly ILogger<BanEngine> _logger;
    private readonly TimeProvider _timeProvider;

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly object _lifecycle = new();

    // Offense counts drive tier escalation (24h -> 7d -> 30d). They survive expired-then-
    // deleted ban rows in memory AND across service restarts via a settings-table blob
    // (key "offense_counts") — review ruling: escalation must survive monthly reboots.
    private const string OffenseCountsSettingKey = "offense_counts";
    private const int DefaultEventRetentionDays = 30;

    private readonly OffenseTracker _offenses = new();

    // Recent RDP failures per IP for detector-aware 4625/140 de-dup (accessed under _gate).
    private readonly RdpDeduplicator _rdpDedup = new();

    // Per-IP throttle for "SKIPPED" events so an attack on a banned IP cannot flood the events table.
    private static readonly TimeSpan SkipEventInterval = TimeSpan.FromMinutes(5);
    private readonly Dictionary<string, DateTime> _lastSkipEventUtc = new(StringComparer.Ordinal);

    // Firewall reconciliation enumerates the live firewall, so the timer loop does it at most this often.
    private static readonly TimeSpan ReconcileInterval = TimeSpan.FromSeconds(60);
    private DateTime _lastReconcileUtc = DateTime.MinValue;

    // "Detections today" per protocol for the dashboard (own lock: read by IPC without the gate).
    private readonly object _statsLock = new();
    private readonly int[] _detectionsToday = new int[Enum.GetValues<ProtocolSource>().Length];
    private DateOnly _detectionsDay;

    private IpMatcher _matcher = new(Array.Empty<string>(), Array.Empty<string>());
    private bool _listsLoaded;

    private CancellationTokenSource? _housekeepingCts;
    private Task? _housekeepingTask;

    /// <summary>Creates the engine. <paramref name="settingsAccessor"/> is called fresh on every
    /// decision so hot-reloaded settings take effect immediately.</summary>
    public BanEngine(
        IStore store,
        IFirewall firewall,
        Func<WinGuardSettings> settingsAccessor,
        ILogger<BanEngine> logger,
        TimeProvider? timeProvider = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _firewall = firewall ?? throw new ArgumentNullException(nameof(firewall));
        _settingsAccessor = settingsAccessor ?? throw new ArgumentNullException(nameof(settingsAccessor));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Startup work (PLAN.md §11): reconcile or clear firewall rules from the database,
    /// auto-whitelist the machine's own addresses and start the housekeeping timer.
    /// </summary>
    public async Task StartAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var settings = _settingsAccessor();

            IReadOnlyList<BanEntry> activeBans;
            try
            {
                activeBans = await _store.GetActiveBansAsync(ct).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "BanEngine could not read active bans during startup.");
                activeBans = Array.Empty<BanEntry>();
            }

            foreach (var ban in activeBans)
            {
                _offenses.Seed(ban.IpAddress, ban.OffenseCount, ban.BannedAtUtc);
            }

            // Merge offense counts persisted in the settings blob (survives restarts).
            await LoadPersistedOffenseCountsAsync(ct).ConfigureAwait(false);

            if (settings.ClearBansOnStartup)
            {
                try
                {
                    _firewall.ClearAll();
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "BanEngine failed to clear firewall rules on startup.");
                }

                foreach (var ban in activeBans)
                {
                    try
                    {
                        await _store.RemoveBanAsync(ban.IpAddress, ct).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "BanEngine failed to remove ban {Ip} during startup clear.", ban.IpAddress);
                    }
                }

                _offenses.Clear();
                _rdpDedup.Clear();
                await SaveOffenseCountsAsync(ct).ConfigureAwait(false);
                await TryAddEventAsync(null, null, "Cleared bans on startup (ClearBansOnStartup).", ct).ConfigureAwait(false);
            }
            else
            {
                try
                {
                    _firewall.SyncRules(activeBans);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "BanEngine failed to synchronize firewall rules on startup.");
                }
            }

            await ReloadListsCoreAsync(ct).ConfigureAwait(false);
            await SeedDetectionsTodayAsync(ct).ConfigureAwait(false);

            StartHousekeepingLoop(ct);
            _logger.LogInformation(
                "BanEngine started: {Count} active ban(s), threshold {Threshold}, window {Window}.",
                activeBans.Count,
                settings.FailedLoginThreshold,
                settings.CountWindow);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Applies the PLAN.md §5 algorithm to one failed login. Never throws for a single bad
    /// item: invalid/whitelisted/internal/already-banned inputs are logged and ignored.
    /// </summary>
    public async Task ProcessAsync(FailedLogin failed, CancellationToken ct = default)
    {
        if (failed is null)
        {
            return;
        }

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await ProcessCoreAsync(failed, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "BanEngine failed to process a failed login (source {Source}, ip {Ip}).", failed.Source, failed.IpAddress);
            await TryAddEventAsync(
                new LogEvent
                {
                    TimestampUtc = NowUtc(),
                    Level = LogEventLevel.Error,
                    Source = failed.Source,
                    IpAddress = IpMatcher.TryNormalize(failed.IpAddress, out var n) ? n : null,
                    Message = $"ERROR processing failed login: {ex.Message}",
                },
                CancellationToken.None).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Reads <see cref="FailedLogin"/> items from <paramref name="reader"/> until cancellation,
    /// swallowing and logging per-item failures.
    /// </summary>
    public async Task RunAsync(ChannelReader<FailedLogin> reader, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(reader);

        try
        {
            await foreach (var failed in reader.ReadAllAsync(ct).ConfigureAwait(false))
            {
                try
                {
                    await ProcessAsync(failed, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Unhandled error while processing a failed login.");
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Normal shutdown.
        }
    }

    /// <summary>
    /// One pass of expiry/reconcile housekeeping (PLAN.md §5): expire due bans, prune counters
    /// older than <see cref="WinGuardSettings.ExpireTime"/>, reload lists and reconcile the
    /// firewall against the active bans.
    /// </summary>
    public async Task HousekeepOnceAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await HousekeepCoreAsync(forceReconcile: true, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "BanEngine housekeeping failed.");
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Reloads the whitelist/blacklist matcher from the store so a list change made over IPC takes
    /// effect immediately, without running a full housekeeping pass.
    /// </summary>
    public async Task ReloadListsAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await ReloadListsCoreAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Failed logins seen today (local day) for a protocol: every failure from a non-internal,
    /// non-whitelisted address after RDP de-duplication, whether or not it led to a ban.
    /// </summary>
    public int GetDetectionsToday(ProtocolSource source)
    {
        lock (_statsLock)
        {
            RollDetectionsDayLocked();
            var index = (int)source;
            return index >= 0 && index < _detectionsToday.Length ? _detectionsToday[index] : 0;
        }
    }

    /// <summary>Manually blocks an IP (IPC <c>BlockNow</c>). Throws for invalid or whitelisted IPs.</summary>
    public async Task BanNowAsync(string ip, TimeSpan? duration, bool permanent, string? note, CancellationToken ct = default)
    {
        if (!IpMatcher.TryNormalize(ip, out var normalized))
        {
            throw new ArgumentException($"'{ip}' is not a valid IP address.", nameof(ip));
        }

        if (!IpMatcher.IsBannable(normalized))
        {
            throw new ArgumentException($"'{normalized}' is not a host address and cannot be blocked.", nameof(ip));
        }

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await EnsureListsLoadedCoreAsync(ct).ConfigureAwait(false);
            if (_matcher.IsWhitelisted(normalized))
            {
                throw new InvalidOperationException($"'{normalized}' is whitelisted and will not be blocked.");
            }

            var settings = _settingsAccessor();
            var now = NowUtc();
            var isPermanent = permanent;
            DateTime expiresUtc;
            TimeSpan? effectiveDuration = null;

            if (isPermanent)
            {
                expiresUtc = DateTime.MaxValue;
            }
            else
            {
                var chosen = duration is { } requested && requested > TimeSpan.Zero
                    ? requested
                    : settings.TierForOffense(1);
                if (chosen > settings.MaxBanDuration)
                {
                    chosen = settings.MaxBanDuration;
                }

                effectiveDuration = chosen;
                expiresUtc = now + chosen;
            }

            var existing = await SafeGetBanAsync(normalized, ct).ConfigureAwait(false);

            // Re-banning an IP that is still banned (e.g. "promote to permanent") is not a new
            // offense; only a fresh ban moves the escalation tier.
            var stillBanned = existing is not null && (existing.IsPermanent || existing.ExpiresUtc > now);
            var offense = stillBanned
                ? Math.Max(Math.Max(1, existing!.OffenseCount), _offenses.GetCount(normalized))
                : ComputeOffense(normalized, existing);

            var ban = new BanEntry
            {
                IpAddress = normalized,
                Source = existing?.Source ?? ProtocolSource.Custom,
                BannedAtUtc = now,
                ExpiresUtc = expiresUtc,
                OffenseCount = offense,
                IsPermanent = isPermanent,
                Note = string.IsNullOrWhiteSpace(note) ? null : note.Trim(),
            };

            await _store.UpsertBanAsync(ban, ct).ConfigureAwait(false);
            _offenses.Set(normalized, offense, now);
            await SaveOffenseCountsAsync(ct).ConfigureAwait(false);
            TryFirewall(() => _firewall.Block(normalized), "block", normalized);

            var message = isPermanent
                ? $"MANUAL BLOCK {normalized} (permanent)"
                : $"MANUAL BLOCK {normalized} for {FormatDuration(effectiveDuration!.Value)} (offense #{offense})";
            await TryAddEventAsync(new LogEvent
            {
                TimestampUtc = now,
                Level = LogEventLevel.Warning,
                Source = ban.Source,
                IpAddress = normalized,
                Message = message,
            }, ct).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Manually unblocks an IP (IPC <c>Unblock</c>). Idempotent; invalid IPs throw.</summary>
    public async Task UnbanAsync(string ip, CancellationToken ct = default)
    {
        if (!IpMatcher.TryNormalize(ip, out var normalized))
        {
            throw new ArgumentException($"'{ip}' is not a valid IP address.", nameof(ip));
        }

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            try
            {
                await _store.RemoveBanAsync(normalized, ct).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Manual unblock: failed to remove ban {Ip} from the store.", normalized);
            }

            TryFirewall(() => _firewall.Unblock(normalized), "unblock", normalized);

            // Clean slate (review E-M4/S-M7): a manual unban resets escalation and drops
            // the IP's counter rows, so a re-offense starts at tier 1.
            _offenses.Remove(normalized);
            await SaveOffenseCountsAsync(ct).ConfigureAwait(false);
            try
            {
                await _store.ClearFailedLoginsAsync(normalized, ct).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Manual unblock: failed to clear failed logins for {Ip}.", normalized);
            }

            await TryAddEventAsync(new LogEvent
            {
                TimestampUtc = NowUtc(),
                Level = LogEventLevel.Warning,
                IpAddress = normalized,
                Message = $"MANUAL UNBLOCK {normalized}",
            }, ct).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Number of bans currently permanent or not yet expired.</summary>
    public async Task<int> GetActiveBanCountAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var bans = await _store.GetActiveBansAsync(ct).ConfigureAwait(false);
            return bans.Count;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Stops the housekeeping timer. Safe to call more than once.</summary>
    public async Task StopAsync(CancellationToken ct = default)
    {
        CancellationTokenSource? cts;
        Task? task;

        lock (_lifecycle)
        {
            cts = _housekeepingCts;
            task = _housekeepingTask;
            _housekeepingCts = null;
            _housekeepingTask = null;
        }

        if (cts is null)
        {
            return;
        }

        try
        {
            cts.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // Already disposed.
        }

        if (task is not null)
        {
            try
            {
                await task.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Expected.
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "BanEngine housekeeping loop terminated with an error.");
            }
        }

        cts.Dispose();
    }

    // ---- core algorithm ----

    private async Task ProcessCoreAsync(FailedLogin failed, CancellationToken ct)
    {
        // 1. Normalize.
        if (!IpMatcher.TryNormalize(failed.IpAddress, out var ip))
        {
            _logger.LogWarning("Discarding failed login with invalid IP '{Ip}'.", failed.IpAddress);
            return;
        }

        if (!IpMatcher.IsBannable(ip))
        {
            _logger.LogDebug("Discarding failed login from non-host address {Ip}.", ip);
            return;
        }

        failed.IpAddress = ip;
        failed.TimestampUtc = NormalizeUtc(failed.TimestampUtc);

        var settings = _settingsAccessor();
        await EnsureListsLoadedCoreAsync(ct).ConfigureAwait(false);

        // Internal IPs are ignored unless explicitly enabled (PLAN §5).
        if (!settings.ProcessInternalIPs && IpMatcher.IsInternal(ip))
        {
            _logger.LogDebug("Skipping internal IP {Ip}.", ip);
            return;
        }

        // 2. Whitelist always wins.
        if (_matcher.IsWhitelisted(ip))
        {
            _logger.LogDebug("Skipping whitelisted IP {Ip}.", ip);
            if (ShouldRecordSkip("w:" + ip))
            {
                await TryAddEventAsync(new LogEvent
                {
                    TimestampUtc = NowUtc(),
                    Level = LogEventLevel.Info,
                    Source = failed.Source,
                    IpAddress = ip,
                    Message = $"SKIPPED {ip} (whitelist)",
                }, ct).ConfigureAwait(false);
            }

            return;
        }

        // An exclusion rule matched (RDP 4625). It is never counted, but it is remembered so the
        // RdpCoreTS 140 event describing the same attempt is dropped too; when that 140 arrived
        // first and was already counted, that one count is taken back.
        if (failed.IsExcluded)
        {
            if (failed.Source == ProtocolSource.Rdp
                && _rdpDedup.RecordExcluded(ip, failed.Detector, failed.TimestampUtc))
            {
                try
                {
                    await _store.RemoveLatestFailedLoginAsync(ip, ProtocolSource.Rdp, ct).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Could not take back the counted RDP failure for excluded attempt from {Ip}.", ip);
                }
            }

            _logger.LogDebug("Skipping excluded failure for {Ip}.", ip);
            return;
        }

        // RDP de-dup: merge only cross-detector 4625+140 pairs describing the SAME attempt
        // (PLAN §4.2). Same-detector events within the window are distinct attempts.
        if (failed.Source == ProtocolSource.Rdp && _rdpDedup.IsDuplicateAndRecord(ip, failed.Detector, failed.TimestampUtc))
        {
            _logger.LogDebug("Skipping duplicate RDP failure for {Ip} (detector {Detector}).", ip, failed.Detector);
            return;
        }

        RecordDetection(failed.Source);

        var current = await SafeGetBanAsync(ip, ct).ConfigureAwait(false);
        var now = NowUtc();

        // 3. Blacklist -> ensure a permanent ban.
        if (_matcher.IsBlacklisted(ip))
        {
            if (current is { IsPermanent: true })
            {
                TryFirewall(() => _firewall.Block(ip), "block", ip);
                return;
            }

            var offense = ComputeOffense(ip, current);
            var permanentBan = new BanEntry
            {
                IpAddress = ip,
                Source = failed.Source,
                BannedAtUtc = now,
                ExpiresUtc = DateTime.MaxValue,
                OffenseCount = offense,
                IsPermanent = true,
                Note = "blacklist",
            };

            await _store.UpsertBanAsync(permanentBan, ct).ConfigureAwait(false);
            _offenses.Set(ip, offense, now);
            await SaveOffenseCountsAsync(ct).ConfigureAwait(false);
            TryFirewall(() => _firewall.Block(ip), "block", ip);
            await TryAddEventAsync(new LogEvent
            {
                TimestampUtc = now,
                Level = LogEventLevel.Warning,
                Source = failed.Source,
                IpAddress = ip,
                Message = $"BLOCKED {ip} for permanent (offense #{offense})",
            }, ct).ConfigureAwait(false);
            return;
        }

        // 4. Already actively banned -> nothing to do.
        if (current is not null && (current.IsPermanent || current.ExpiresUtc > now))
        {
            _logger.LogDebug("IP {Ip} is already banned; ignoring attempt.", ip);
            if (ShouldRecordSkip("b:" + ip))
            {
                await TryAddEventAsync(new LogEvent
                {
                    TimestampUtc = now,
                    Level = LogEventLevel.Info,
                    Source = failed.Source,
                    IpAddress = ip,
                    Message = $"SKIPPED {ip} (already banned)",
                }, ct).ConfigureAwait(false);
            }

            return;
        }

        // 5 + 6. Record the attempt and count within the rolling window (per protocol, so
        // overrides apply) in one store round trip.
        var window = settings.CountWindowFor(failed.Source);
        if (window <= TimeSpan.Zero)
        {
            window = settings.CountWindow;
        }

        var since = now - window;
        var count = await _store.AddFailedLoginAndCountAsync(failed, since, ct).ConfigureAwait(false);

        // 7. Threshold crossed -> escalate and ban.
        var threshold = Math.Max(1, settings.ThresholdFor(failed.Source));
        if (count < threshold)
        {
            return;
        }

        var nextOffense = ComputeOffense(ip, current);
        var duration = settings.TierForOffense(nextOffense);
        if (duration <= TimeSpan.Zero)
        {
            duration = TimeSpan.FromHours(24);
        }

        var expiresUtc = now + duration;
        var ban = new BanEntry
        {
            IpAddress = ip,
            Source = failed.Source,
            BannedAtUtc = now,
            ExpiresUtc = expiresUtc,
            OffenseCount = nextOffense,
            IsPermanent = false,
        };

        await _store.UpsertBanAsync(ban, ct).ConfigureAwait(false);
        _offenses.Set(ip, nextOffense, now);
        await SaveOffenseCountsAsync(ct).ConfigureAwait(false);
        TryFirewall(() => _firewall.Block(ip), "block", ip);
        await _store.ClearFailedLoginsAsync(ip, ct).ConfigureAwait(false);

        _logger.LogWarning("Blocked {Ip} for {Duration} (offense #{Offense}).", ip, duration, nextOffense);
        await TryAddEventAsync(new LogEvent
        {
            TimestampUtc = now,
            Level = LogEventLevel.Warning,
            Source = failed.Source,
            IpAddress = ip,
            Message = $"BLOCKED {ip} for {FormatDuration(duration)} (offense #{nextOffense})",
        }, ct).ConfigureAwait(false);
    }

    // ---- detection statistics ----

    private void RecordDetection(ProtocolSource source)
    {
        lock (_statsLock)
        {
            RollDetectionsDayLocked();
            var index = (int)source;
            if (index >= 0 && index < _detectionsToday.Length)
            {
                _detectionsToday[index]++;
            }
        }
    }

    private void RollDetectionsDayLocked()
    {
        var today = DateOnly.FromDateTime(_timeProvider.GetLocalNow().DateTime);
        if (today != _detectionsDay)
        {
            _detectionsDay = today;
            Array.Clear(_detectionsToday);
        }
    }

    /// <summary>
    /// After a restart the in-memory counters start from the attempts still on record for today
    /// (a lower bound: rows are deleted when a ban fires). Best effort.
    /// </summary>
    private async Task SeedDetectionsTodayAsync(CancellationToken ct)
    {
        try
        {
            var localNow = _timeProvider.GetLocalNow();
            var midnightUtc = (localNow - localNow.TimeOfDay).UtcDateTime;
            var seed = new int[_detectionsToday.Length];
            foreach (var source in Enum.GetValues<ProtocolSource>())
            {
                var index = (int)source;
                if (index >= 0 && index < seed.Length)
                {
                    seed[index] = await _store.CountFailedLoginsSinceAsync(midnightUtc, source, ct).ConfigureAwait(false);
                }
            }

            lock (_statsLock)
            {
                RollDetectionsDayLocked();
                for (var i = 0; i < seed.Length; i++)
                {
                    _detectionsToday[i] = Math.Max(_detectionsToday[i], seed[i]);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not seed today's detection counters.");
        }
    }

    // ---- lists / helpers ----

    private async Task EnsureListsLoadedCoreAsync(CancellationToken ct)
    {
        if (_listsLoaded)
        {
            return;
        }

        await ReloadListsCoreAsync(ct).ConfigureAwait(false);
    }

    private async Task ReloadListsCoreAsync(CancellationToken ct)
    {
        IReadOnlyList<string> configuredWhitelist;
        IReadOnlyList<string> blacklist;
        try
        {
            configuredWhitelist = await _store.GetListAsync(ListKind.Whitelist, ct).ConfigureAwait(false);
            blacklist = await _store.GetListAsync(ListKind.Blacklist, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "BanEngine failed to load IP lists; keeping the previous matcher.");
            return;
        }

        var whitelist = new List<string>(configuredWhitelist);
        whitelist.AddRange(IpMatcher.GetLocalAddresses());
        _matcher = new IpMatcher(whitelist, blacklist);
        _listsLoaded = true;
    }

    private async Task<BanEntry?> SafeGetBanAsync(string ip, CancellationToken ct)
    {
        try
        {
            return await _store.GetBanAsync(ip, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "BanEngine failed to read the existing ban for {Ip}.", ip);
            return null;
        }
    }

    private int ComputeOffense(string ip, BanEntry? existing)
    {
        var prior = existing?.OffenseCount ?? 0;
        var cached = _offenses.GetCount(ip);
        if (cached > prior)
        {
            prior = cached;
        }

        return prior + 1;
    }

    private void TryFirewall(Action action, string operation, string ip)
    {
        try
        {
            action();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Firewall {Operation} failed for {Ip}.", operation, ip);
        }
    }

    private async Task TryAddEventAsync(LogEvent logEvent, CancellationToken ct)
    {
        try
        {
            await _store.AddEventAsync(logEvent, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to record WinGuard event '{Message}'.", logEvent.Message);
        }
    }

    private async Task TryAddEventAsync(ProtocolSource? source, string? ip, string message, CancellationToken ct)
    {
        await TryAddEventAsync(new LogEvent
        {
            TimestampUtc = NowUtc(),
            Level = LogEventLevel.Info,
            Source = source,
            IpAddress = ip,
            Message = message,
        }, ct).ConfigureAwait(false);
    }

    private bool ShouldRecordSkip(string key)
    {
        var now = NowUtc();
        if (_lastSkipEventUtc.TryGetValue(key, out var last) && now - last < SkipEventInterval)
        {
            return false;
        }

        if (_lastSkipEventUtc.Count > 10_000)
        {
            _lastSkipEventUtc.Clear();
        }

        _lastSkipEventUtc[key] = now;
        return true;
    }

    private DateTime NowUtc() => _timeProvider.GetUtcNow().UtcDateTime;

    private DateTime NormalizeUtc(DateTime value)
    {
        if (value == default)
        {
            return NowUtc();
        }

        return value.Kind switch
        {
            DateTimeKind.Utc => value,
            DateTimeKind.Local => value.ToUniversalTime(),
            _ => DateTime.SpecifyKind(value, DateTimeKind.Utc),
        };
    }

    private static string FormatDuration(TimeSpan duration) => duration.ToString("c", CultureInfo.InvariantCulture);

    private void StartHousekeepingLoop(CancellationToken ct)
    {
        CancellationTokenSource cts;
        lock (_lifecycle)
        {
            // Cancel any previous loop; its CTS is owned by StopAsync.
            _housekeepingCts?.Cancel();
            cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            _housekeepingCts = cts;
            _housekeepingTask = Task.Run(() => HousekeepingLoopAsync(cts.Token), CancellationToken.None);
        }
    }

    private async Task HousekeepingLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var interval = _settingsAccessor().HousekeepingInterval;
            if (interval < TimeSpan.FromSeconds(1))
            {
                interval = Defaults.HousekeepingInterval;
            }

            try
            {
                await Task.Delay(interval, _timeProvider, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }

            try
            {
                await _gate.WaitAsync(ct).ConfigureAwait(false);
                try
                {
                    await HousekeepCoreAsync(forceReconcile: false, ct).ConfigureAwait(false);
                }
                finally
                {
                    _gate.Release();
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "BanEngine housekeeping iteration failed.");
            }
        }
    }
}