using System.Globalization;
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
    private readonly IEventPublisher _publisher;

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly object _lifecycle = new();

    // Offense counts drive tier escalation (24h -> 7d -> 30d). They survive expired-then-
    // deleted ban rows in memory AND across service restarts via the offense_counts table
    // — review ruling: escalation must survive monthly reboots.
    private readonly OffenseTracker _offenses = new();

    // Appended to what is reported about a ban the firewall does not reflect, so an event or a
    // notification never claims an IP was blocked or unblocked when nothing was enforced.
    private const string ReportOnlyNote = " (report-only: firewall unchanged)";

    // Ban-history rows pruned per housekeeping pass, so working off a backlog cannot hold the gate.
    private const int BanHistoryPruneBatch = 5_000;

    // Recent RDP failures per IP for detector-aware 4625/140 de-dup (accessed under _gate).
    private readonly RdpDeduplicator _rdpDedup = new();

    // Replayed events get their own de-dup: see RdpDeduplicator's constructor. It is only needed
    // while the replay runs, so housekeeping empties it once start-up is long over.
    private static readonly TimeSpan ReplayDedupLifetime = TimeSpan.FromMinutes(10);
    private readonly RdpDeduplicator _replayDedup = new(trimByEventTime: false);

    // Everything logged up to this moment was handled by the previous run, so backlog replay must
    // not count it again. Persisted under this key by housekeeping and on stop. A crash can repeat
    // at most the events of one housekeeping interval. Until StartAsync sets it, nothing replays.
    private const string LastAliveSettingKey = "engine_last_alive_utc";
    private DateTime _replayCutoffUtc = DateTime.MaxValue;
    private DateTime _startedUtc;

    // Bans the store refused to save: enforced in the firewall anyway, kept here so reconcile does
    // not lift them as orphans, and saved by housekeeping once the store recovers (under _gate).
    private readonly Dictionary<string, BanEntry> _unsavedBans = new(StringComparer.Ordinal);

    // The unsaved bans made while the store could not say what it holds for the address. Its row may
    // be stronger (permanent, other ports), so until housekeeping can merge them these stay on all
    // ports and out of the store: a blind block or save could only take something away (under _gate).
    private readonly HashSet<string> _blindBans = new(StringComparer.Ordinal);

    /// <summary>
    /// How many unsaved bans are held at most, so a flood of attackers during a long outage cannot
    /// grow memory without limit. Past that the one closest to its end goes, and that is logged.
    /// </summary>
    internal int MaxUnsavedBans { get; set; } = 50_000;

    // Counts failures while the store refuses them (accessed under _gate).
    private readonly FallbackFailureCounter _fallbackCounts = new();

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

    // Buffered daily-statistics deltas (day, source) -> (detections, bans), flushed to the store
    // during housekeeping so the hot path stays write-free. Own lock, read by IPC.
    private readonly Dictionary<(DateOnly Day, ProtocolSource Source), (int Detections, int Bans)> _dailyStats = new();

    // Canonical CIDR entries of the blacklist (e.g. "203.0.113.0/24"): enforced as firewall
    // range rules so a blacklisted subnet is blocked as a whole, not address-by-address.
    private List<string> _blacklistedRanges = [];

    // Holds the server's own addresses from the start, so an unreadable database cannot lift the
    // self-lockout protection along with the configured lists.
    private IpMatcher _matcher = new(IpMatcher.GetLocalAddresses(), Array.Empty<string>());
    private bool _listsLoaded;

    private CancellationTokenSource? _housekeepingCts;
    private Task? _housekeepingTask;

    /// <summary>Creates the engine. <paramref name="settingsAccessor"/> is called fresh on every
    /// decision so hot-reloaded settings take effect immediately.</summary>
    /// <param name="eventPublisher">Optional fan-out for engine events (notifications, Windows Event Log).</param>
    public BanEngine(
        IStore store,
        IFirewall firewall,
        Func<WinGuardSettings> settingsAccessor,
        ILogger<BanEngine> logger,
        TimeProvider? timeProvider = null,
        IEventPublisher? eventPublisher = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _firewall = firewall ?? throw new ArgumentNullException(nameof(firewall));
        _settingsAccessor = settingsAccessor ?? throw new ArgumentNullException(nameof(settingsAccessor));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _timeProvider = timeProvider ?? TimeProvider.System;
        _publisher = eventPublisher ?? NullEventPublisher.Instance;
    }

    /// <summary>
    /// Startup work (PLAN.md §11): reconcile or clear firewall rules from the database,
    /// auto-whitelist the machine's own addresses and start the housekeeping timer.
    /// </summary>
    public async Task StartAsync(CancellationToken ct)
    {
        await RefreshBlocklistsAsync(ct).ConfigureAwait(false);
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var settings = _settingsAccessor();

            IReadOnlyList<BanEntry> activeBans = Array.Empty<BanEntry>();
            var bansKnown = false;
            try
            {
                activeBans = await _store.GetActiveBansAsync(ct).ConfigureAwait(false);
                bansKnown = true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "BanEngine could not read active bans during startup.");
            }

            foreach (var ban in activeBans)
            {
                _offenses.Seed(ban.IpAddress, ban.OffenseCount, ban.BannedAtUtc);
            }

            // Merge the persisted offense counts (survive restarts).
            await LoadPersistedOffenseCountsAsync(ct).ConfigureAwait(false);
            await LoadReplayCutoffAsync(ct).ConfigureAwait(false);

            // The lists come before any firewall work: a sync removes whatever it is not given, so
            // it has to know the blacklisted ranges or they would be unenforced until housekeeping.
            await ReloadListsCoreAsync(ct).ConfigureAwait(false);

            // Before any firewall work: a disarm survives a restart until its window ends.
            await CheckDisarmCoreAsync(ct).ConfigureAwait(false);

            if (settings.ClearBansOnStartup)
            {
                // The bans go, the blacklisted ranges stay. Sync instead of ClearAll, which would
                // leave the ranges unenforced for a moment. Report-only leaves the firewall alone.
                // Without the lists a sync would take the ranges and blocklists with it, so the
                // rules stay until reconcile lifts the ban rules as orphans once the lists load.
                if (!FirewallFrozen && !_listsLoaded)
                {
                    _logger.LogWarning("BanEngine left the firewall rules as they are: the lists could not be read. Reconcile clears the old ban rules once they can.");
                }
                else if (!FirewallFrozen)
                {
                    try
                    {
                        _firewall.SyncRules(FirewallTargets([]));
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "BanEngine failed to clear firewall rules on startup.");
                    }
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
                await TryAddEventAsync(null, null, $"Cleared bans on startup (ClearBansOnStartup).{ReportSuffix()}", ct).ConfigureAwait(false);
            }
            else if (IsDisarmed)
            {
                _logger.LogWarning("BanEngine started disarmed: bans are recorded but the firewall stays empty until {Until:u}.", DisarmedUntilUtc);
            }
            else if (settings.ReportOnly)
            {
                // Monitoring mode: never touch the firewall, but keep the database the source of
                // truth. Rules left over from before the flag was set stay until it is switched off;
                // that same reconcile pass lifts them and re-blocks every active ban.
                _logger.LogInformation("BanEngine started in report-only mode: failures are counted and recorded, but the firewall is not modified.");
                await TryAddEventAsync(null, null, "Started in report-only mode: bans are recorded but NOT enforced in the firewall.", ct).ConfigureAwait(false);
            }
            else if (bansKnown && _listsLoaded)
            {
                try
                {
                    _firewall.SyncRules(FirewallTargets(activeBans));
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "BanEngine failed to synchronize firewall rules on startup.");
                }
            }
            else
            {
                // A sync removes everything it is not given, so on an unreadable database it would
                // wipe every enforced ban. The rules stay; reconcile corrects them once it is back.
                _logger.LogWarning("BanEngine left the firewall rules as they are: the bans or lists could not be read.");
            }

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
            if (failed.IsSuccess)
            {
                await ProcessSuccessCoreAsync(failed, ct).ConfigureAwait(false);
            }
            else
            {
                await ProcessCoreAsync(failed, ct).ConfigureAwait(false);
            }
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
        await RefreshBlocklistsAsync(ct).ConfigureAwait(false);
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

    /// <summary>
    /// Manually blocks an IP or a range such as an IPv6 aggregate ban being promoted (IPC
    /// <c>BlockNow</c>). Throws for invalid or whitelisted targets. Without
    /// <paramref name="permanent"/> or a <paramref name="duration"/> a ban already running keeps
    /// whatever is longer: only an explicit choice can shorten it.
    /// </summary>
    public async Task BanNowAsync(string ip, TimeSpan? duration, bool permanent, string? note, CancellationToken ct = default)
    {
        if (!IpMatcher.TryNormalizeBanTarget(ip, out var normalized))
        {
            throw new ArgumentException($"'{ip}' is not a valid IP address.", nameof(ip));
        }

        var isRange = normalized.Contains('/');
        if (!isRange && !IpMatcher.IsBannable(normalized))
        {
            throw new ArgumentException($"'{normalized}' is not a host address and cannot be blocked.", nameof(ip));
        }

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await EnsureListsLoadedCoreAsync(ct).ConfigureAwait(false);
            if (isRange ? _matcher.OverlapsWhitelist(normalized) : _matcher.IsWhitelisted(normalized))
            {
                throw new InvalidOperationException($"'{normalized}' is whitelisted and will not be blocked.");
            }

            ForgetLogonState(normalized);
            var settings = _settingsAccessor();
            var now = NowUtc();
            var (existing, rowKnown) = await FindBanAsync(normalized, ct).ConfigureAwait(false);

            // Re-banning an IP that is still banned (e.g. "promote to permanent") is not a new
            // offense; only a fresh ban moves the escalation tier.
            var stillBanned = existing is not null && (existing.IsPermanent || existing.ExpiresUtc > now);
            var offense = stillBanned
                ? Math.Max(Math.Max(1, existing!.OffenseCount), _offenses.GetCount(normalized))
                : ComputeOffense(normalized, existing);

            var requested = duration is { } value && value > TimeSpan.Zero ? value : (TimeSpan?)null;
            var isPermanent = permanent;
            DateTime expiresUtc;
            TimeSpan? effectiveDuration = null;

            if (isPermanent)
            {
                expiresUtc = DateTime.MaxValue;
            }
            else
            {
                var chosen = requested ?? settings.TierForOffense(1);
                if (chosen > settings.MaxBanDuration)
                {
                    chosen = settings.MaxBanDuration;
                }

                effectiveDuration = chosen;
                expiresUtc = now + chosen;

                // Nothing was asked for, so nothing the running ban already gives is taken away.
                if (requested is null && stillBanned && (existing!.IsPermanent || existing.ExpiresUtc > expiresUtc))
                {
                    isPermanent = existing.IsPermanent;
                    expiresUtc = isPermanent ? DateTime.MaxValue : existing.ExpiresUtc;
                    effectiveDuration = isPermanent ? null : expiresUtc - now;
                }
            }

            // What the administrator spelled out stands whatever the store holds; the default does
            // not, so it must not replace a row nobody could read.
            if (permanent || requested is not null)
            {
                _blindBans.Remove(normalized);
            }
            else if (!rowKnown)
            {
                _blindBans.Add(normalized);
            }

            var ban = new BanEntry
            {
                IpAddress = normalized,
                Source = stillBanned ? existing!.Source : ProtocolSource.Manual,
                BannedAtUtc = now,
                ExpiresUtc = expiresUtc,
                OffenseCount = offense,
                IsPermanent = isPermanent,
                Note = string.IsNullOrWhiteSpace(note) ? (stillBanned ? existing!.Note : null) : note.Trim(),
                PortScope = PortProfiles.AllPorts,
            };

            // Enforce first: a database problem must never leave an attacker unblocked.
            TryBlock(normalized, PortSet.All);
            await SaveBanAsync(ban, ct).ConfigureAwait(false);
            _offenses.Set(normalized, offense, now);
            await SaveOffenseCountsAsync(ct).ConfigureAwait(false);
            if (!stillBanned)
            {
                RecordBanStat(ban.Source);
            }

            await AddBanHistoryCoreAsync(new BanHistoryEntry
            {
                TimestampUtc = now,
                Action = stillBanned ? BanHistoryAction.Updated : BanHistoryAction.Banned,
                IpAddress = normalized,
                Source = ban.Source,
                OffenseCount = offense,
                IsPermanent = isPermanent,
                Duration = effectiveDuration,
                Note = ban.Note,
            }, ct).ConfigureAwait(false);

            var message = isPermanent
                ? $"MANUAL BLOCK {normalized} (permanent){ReportSuffix()}"
                : $"MANUAL BLOCK {normalized} for {FormatDuration(effectiveDuration!.Value)} (offense #{offense}){ReportSuffix()}";
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

    /// <summary>Manually unblocks an IP or a range ban (IPC <c>Unblock</c>). Idempotent; invalid values throw.</summary>
    public async Task UnbanAsync(string ip, CancellationToken ct = default)
    {
        if (!IpMatcher.TryNormalizeBanTarget(ip, out var normalized))
        {
            throw new ArgumentException($"'{ip}' is not a valid IP address.", nameof(ip));
        }

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await UnbanCoreAsync(normalized, $"MANUAL UNBLOCK {normalized}", ct).ConfigureAwait(false);
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

        // Do not lose today's buffered statistics deltas on shutdown.
        try
        {
            await FlushDailyStatsAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not flush daily statistics on stop.");
        }

        // One last try for what the store refused: a ban unsaved now would be an orphan at next start.
        await _gate.WaitAsync(CancellationToken.None).ConfigureAwait(false);
        try
        {
            await RetryUnsavedBansAsync(NowUtc(), CancellationToken.None).ConfigureAwait(false);
            await SaveOffenseCountsAsync(CancellationToken.None).ConfigureAwait(false);
            await EvaluateReplayedSuccessesAsync(NowUtc(), all: true, CancellationToken.None).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }

        await SaveLastAliveAsync(CancellationToken.None).ConfigureAwait(false);

        cts.Dispose();
    }

    // ---- core algorithm ----

    /// <summary>
    /// Removes a ban with a clean slate (review E-M4/S-M7): escalation is reset and the IP's counter
    /// rows are dropped, so a re-offense starts at tier 1. Call under the gate.
    /// </summary>
    private async Task UnbanCoreAsync(string normalized, string eventMessage, CancellationToken ct)
    {
        var (existing, _) = await FindBanAsync(normalized, ct).ConfigureAwait(false);
        _unsavedBans.Remove(normalized);
        _blindBans.Remove(normalized);
        _fallbackCounts.Remove(normalized);
        _failuresAtBan.Remove(normalized);

        try
        {
            await _store.RemoveBanAsync(normalized, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unblock: failed to remove ban {Ip} from the store.", normalized);
        }

        TryUnblock(normalized);

        _offenses.Remove(normalized);
        await SaveOffenseCountsAsync(ct).ConfigureAwait(false);
        try
        {
            await _store.ClearFailedLoginsAsync(normalized, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unblock: failed to clear failed logins for {Ip}.", normalized);
        }

        // Unbanning is idempotent and also runs for any address that gets whitelisted: only a ban
        // that really ended is history, and worth a notification.
        if (existing is null)
        {
            return;
        }

        await AddBanHistoryCoreAsync(new BanHistoryEntry
        {
            TimestampUtc = NowUtc(),
            Action = BanHistoryAction.Unbanned,
            IpAddress = normalized,
            Source = existing.Source,
            OffenseCount = existing.OffenseCount,
            IsPermanent = existing.IsPermanent,
        }, ct).ConfigureAwait(false);

        await TryAddEventAsync(new LogEvent
        {
            TimestampUtc = NowUtc(),
            Level = LogEventLevel.Warning,
            Source = existing.Source,
            IpAddress = normalized,
            Message = eventMessage + ReportSuffix(),
        }, ct).ConfigureAwait(false);
    }

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

        // Replay exists for what happened while the service was down. Anything older was handled
        // by the previous run, and counting it again would re-ban an IP an administrator unbanned.
        if (failed.IsReplayed && failed.TimestampUtc <= _replayCutoffUtc)
        {
            _logger.LogDebug("Skipping replayed failure from {Ip}: the previous run already processed it.", ip);
            return;
        }

        var settings = _settingsAccessor();
        await EnsureListsLoadedCoreAsync(ct).ConfigureAwait(false);

        // Internal IPs are ignored unless explicitly enabled (PLAN §5).
        if (!settings.ProcessInternalIPs && IpMatcher.IsInternal(ip))
        {
            _logger.LogDebug("Skipping internal IP {Ip}.", ip);
            return;
        }

        // 2. Whitelist always wins.
        if (_matcher.IsWhitelisted(ip) || IsTemporarilyTrusted(ip, settings))
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

        // Blacklist membership is checked on the FULL address: list entries are networks, and the
        // aggregated prefix computed below is not an address they could contain.
        var blacklisted = _matcher.IsBlacklisted(ip);

        // IPv6 aggregate banning: an attacker rotating addresses inside their /64 would never
        // cross a per-address threshold, so count and ban the whole prefix instead.
        if (!blacklisted
            && settings.Ipv6AggregatePrefixLength > 0
            && ip.Contains(':')
            && IpMatcher.TryAggregateIpv6(ip, settings.Ipv6AggregatePrefixLength, out var aggregatedPrefix))
        {
            // A block rule beats every allow rule, so banning a prefix that holds a whitelisted
            // address (this server's own, for one) would block that address too. Such a prefix
            // stays on per-address bans.
            if (_matcher.OverlapsWhitelist(aggregatedPrefix) || OverlapsTemporaryTrust(aggregatedPrefix))
            {
                _logger.LogDebug("Not aggregating {Ip}: prefix {Prefix} overlaps the whitelist.", ip, aggregatedPrefix);
            }
            else
            {
                _logger.LogDebug("Aggregating IPv6 address {Ip} to prefix {Prefix}.", ip, aggregatedPrefix);
                ip = aggregatedPrefix;
                failed.IpAddress = ip;
            }
        }

        var rdpDedup = failed.IsReplayed ? _replayDedup : _rdpDedup;

        // An exclusion rule matched (RDP 4625). It is never counted, but it is remembered so the
        // RdpCoreTS 140 event describing the same attempt is dropped too; when that 140 arrived
        // first and was already counted, that one count is taken back.
        if (failed.IsExcluded)
        {
            if (failed.Source == ProtocolSource.Rdp
                && rdpDedup.RecordExcluded(ip, failed.Detector, failed.TimestampUtc))
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
        var alreadyCounted = false;
        if (failed.Source == ProtocolSource.Rdp && rdpDedup.IsDuplicateAndRecord(ip, failed.Detector, failed.TimestampUtc, out var partnerCounted))
        {
            _logger.LogDebug("Skipping duplicate RDP failure for {Ip} (detector {Detector}).", ip, failed.Detector);
            if (!partnerCounted || !NamesCountedAttempt(failed, settings.Rules))
            {
                return;
            }

            alreadyCounted = true;
        }

        if (!alreadyCounted)
        {
            RecordDetection(failed.Source);
        }

        // A row that cannot be read is not a row that is not there: an attacker still gets banned
        // during an outage, but as a blind ban, which can only add to whatever the row says.
        var (current, rowKnown) = await FindBanAsync(ip, ct).ConfigureAwait(false);
        var now = NowUtc();

        // 3. Blacklist -> ensure a permanent ban.
        if (blacklisted)
        {
            if (current is { IsPermanent: true })
            {
                await EnsureAllPortsAsync(current, ct).ConfigureAwait(false);
                return;
            }

            if (!rowKnown)
            {
                _blindBans.Add(ip);
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
                PortScope = PortProfiles.AllPorts,
            };

            TryBlock(ip, PortSet.All);
            await SaveBanAsync(permanentBan, ct).ConfigureAwait(false);
            _offenses.Set(ip, offense, now);
            await SaveOffenseCountsAsync(ct).ConfigureAwait(false);
            RecordBanStat(failed.Source);
            await AddBanHistoryCoreAsync(new BanHistoryEntry
            {
                TimestampUtc = now,
                Action = BanHistoryAction.Banned,
                IpAddress = ip,
                Source = failed.Source,
                OffenseCount = offense,
                IsPermanent = true,
                Note = "blacklist",
            }, ct).ConfigureAwait(false);
            await TryAddEventAsync(new LogEvent
            {
                TimestampUtc = now,
                Level = LogEventLevel.Warning,
                Source = failed.Source,
                IpAddress = ip,
                Message = $"BLOCKED {ip} for permanent (offense #{offense}){ReportSuffix()}",
            }, ct).ConfigureAwait(false);
            return;
        }

        // 4. Already actively banned -> nothing to do, unless the ban leaves this engine's ports
        // open: such a failure counts like any other, and crossing the threshold widens the ban.
        var isBanned = current is not null && (current.IsPermanent || current.ExpiresUtc > now);
        if (isBanned && BanCovers(current!, failed, settings))
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

        int count;
        if (alreadyCounted)
        {
            count = await NameCountedAttemptAsync(failed, ct).ConfigureAwait(false);
        }
        else if (IsWithinReplayWindow(failed, settings, now))
        {
            count = await CountReplayedFailureAsync(failed, window, ct).ConfigureAwait(false);
        }
        else
        {
            count = await CountFailureAsync(failed, now - window, ct).ConfigureAwait(false);
        }

        // 7. Threshold crossed or a detection rule fired -> escalate and ban.
        var threshold = Math.Max(1, settings.ThresholdFor(failed.Source));
        var rule = await EvaluateRulesAsync(failed, count, threshold, settings.Rules, now, ct).ConfigureAwait(false);
        if (count < threshold && rule is null)
        {
            return;
        }

        // Until the lists load this may be a whitelisted administrator, and a block rule would lock
        // them out. That leaves attackers free for now, so the failures stay counted: the next one
        // after the lists load bans.
        if (!_listsLoaded)
        {
            _logger.LogWarning("Not blocking {Ip} yet: the whitelist could not be read. Its failures stay counted.", ip);
            if (ShouldRecordSkip("l:" + ip))
            {
                await TryAddEventAsync(new LogEvent
                {
                    TimestampUtc = now,
                    Level = LogEventLevel.Warning,
                    Source = failed.Source,
                    IpAddress = ip,
                    Message = $"SKIPPED {ip} (whitelist unreadable: not blocked yet, failures stay counted)",
                }, ct).ConfigureAwait(false);
            }

            return;
        }

        var nextOffense = ComputeOffense(ip, current);
        var duration = settings.TierForOffense(nextOffense);
        if (duration <= TimeSpan.Zero)
        {
            duration = TimeSpan.FromHours(24);
        }

        if (isBanned)
        {
            await WidenBanAsync(current!, failed, nextOffense, duration, settings, ct).ConfigureAwait(false);
            return;
        }

        if (!rowKnown)
        {
            _blindBans.Add(ip);
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
            Note = rule,
            PortScope = PortProfiles.ScopeFor(failed.Source, failed.Detector),
        };

        // Enforce first: a database problem must never leave an attacker unblocked.
        var ports = EnforcedPorts(ban, settings);
        TryBlock(ip, ports);
        await SaveBanAsync(ban, ct).ConfigureAwait(false);
        _offenses.Set(ip, nextOffense, now);
        await SaveOffenseCountsAsync(ct).ConfigureAwait(false);
        RememberFailuresAtBan(ip, count, expiresUtc, settings.Rules);
        _fallbackCounts.Remove(ip);
        try
        {
            await _store.ClearFailedLoginsAsync(ip, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _logger.LogError(ex, "Could not clear the failed logins of banned IP {Ip}.", ip);
        }

        RecordBanStat(failed.Source);
        await AddBanHistoryCoreAsync(new BanHistoryEntry
        {
            TimestampUtc = now,
            Action = BanHistoryAction.Banned,
            IpAddress = ip,
            Source = failed.Source,
            OffenseCount = nextOffense,
            Duration = duration,
            Note = rule,
        }, ct).ConfigureAwait(false);

        var reportSuffix = ReportSuffix();
        var ruleText = rule is null ? string.Empty : $" ({rule})";
        _logger.LogWarning("Blocked {Ip} for {Duration}{Rule} (offense #{Offense}).{Suffix}", ip, duration, ruleText, nextOffense, reportSuffix);
        await TryAddEventAsync(new LogEvent
        {
            TimestampUtc = now,
            Level = LogEventLevel.Warning,
            Source = failed.Source,
            IpAddress = ip,
            Message = $"BLOCKED {ip}{PortsNote(ports)} for {FormatDuration(duration)}{ruleText} (offense #{nextOffense}){reportSuffix}",
        }, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Records one failure and returns the rolling count. A failure the store refuses is kept in
    /// memory and counts together with the stored ones, so an outage in the middle of an attack
    /// neither resets the count nor, once it is over, loses what was seen meanwhile.
    /// </summary>
    private async Task<int> CountFailureAsync(FailedLogin failed, DateTime since, CancellationToken ct)
    {
        var ip = failed.IpAddress;
        try
        {
            var stored = await _store.AddFailedLoginAndCountAsync(failed, since, ct).ConfigureAwait(false);
            return stored + _fallbackCounts.Count(ip, failed.Source, since);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _logger.LogError(ex, "Could not record a failed login from {Ip}; counting it in memory.", ip);
            _fallbackCounts.Record(ip, failed.Source, failed.TimestampUtc);
        }

        var inMemory = _fallbackCounts.Count(ip, failed.Source, since);
        try
        {
            return inMemory + await _store.CountFailedLoginsAsync(ip, since, failed.Source, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _logger.LogDebug(ex, "Could not read the stored failures of {Ip} either.", ip);
            return inMemory;
        }
    }

    /// <summary>Whether this replayed failure gets counted against its own time, see <see cref="CountReplayedFailureAsync"/>.</summary>
    private static bool IsWithinReplayWindow(FailedLogin failed, WinGuardSettings settings, DateTime now) =>
        failed.IsReplayed && now - failed.TimestampUtc <= TimeSpan.FromMinutes(settings.EventBacklogReplayMinutes);

    /// <summary>
    /// Records a replayed failure and returns the most failures in one count window it is at either
    /// end of. Measured from now, a burst older than the window would ban nobody however heavy it
    /// was, while the same burst minutes later would. Replay delivers a channel newest first, and
    /// live events get in between, so the others can be on either side of this one: the window
    /// reaching forward finds a burst arriving newest first, the one reaching back a burst arriving
    /// oldest first, and neither takes in failures further apart than a live ban would.
    /// </summary>
    private async Task<int> CountReplayedFailureAsync(FailedLogin failed, TimeSpan window, CancellationToken ct)
    {
        var at = failed.TimestampUtc;
        await CountFailureAsync(failed, at, ct).ConfigureAwait(false);
        var reachingBack = await CountFailuresBetweenAsync(failed, at - window, at, ct).ConfigureAwait(false);
        var reachingForward = await CountFailuresBetweenAsync(failed, at, at + window, ct).ConfigureAwait(false);
        return Math.Max(reachingBack, reachingForward);
    }

    /// <summary>Failures of this IP and source between two moments, both included. What the store cannot say counts as none.</summary>
    private async Task<int> CountFailuresBetweenAsync(FailedLogin failed, DateTime fromUtc, DateTime toUtc, CancellationToken ct)
    {
        var inMemory = _fallbackCounts.Count(failed.IpAddress, failed.Source, fromUtc, toUtc);
        try
        {
            var fromThen = await _store.CountFailedLoginsAsync(failed.IpAddress, fromUtc, failed.Source, ct).ConfigureAwait(false);
            var afterwards = await _store.CountFailedLoginsAsync(failed.IpAddress, toUtc.AddTicks(1), failed.Source, ct).ConfigureAwait(false);
            return inMemory + fromThen - afterwards;
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _logger.LogDebug(ex, "Could not read the stored failures of {Ip}.", failed.IpAddress);
            return inMemory;
        }
    }

    /// <summary>Saves a ban already enforced in the firewall, keeping it in memory when the store refuses it or must not be trusted with it.</summary>
    private async Task SaveBanAsync(BanEntry ban, CancellationToken ct)
    {
        if (_blindBans.Contains(ban.IpAddress))
        {
            HoldUnsavedBan(ban);
            return;
        }

        try
        {
            await _store.UpsertBanAsync(ban, ct).ConfigureAwait(false);

            // An older unsaved version of this ban must not overwrite this one on the next retry.
            _unsavedBans.Remove(ban.IpAddress);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // The service is stopping with the block in place: the stop pass saves it.
            HoldUnsavedBan(ban);
            throw;
        }
        catch (Exception ex)
        {
            HoldUnsavedBan(ban);
            _logger.LogError(ex, "Could not save the ban of {Ip}; it stays enforced and will be saved when the store recovers.", ban.IpAddress);
        }
    }

    /// <summary>Keeps a ban the store does not have yet. At the limit the ban closest to its end makes room, and that is logged.</summary>
    private void HoldUnsavedBan(BanEntry ban)
    {
        if (!_unsavedBans.ContainsKey(ban.IpAddress) && _unsavedBans.Count >= MaxUnsavedBans)
        {
            var dropped = _unsavedBans.Values.MinBy(held => held.ExpiresUtc)!;
            _unsavedBans.Remove(dropped.IpAddress);
            _blindBans.Remove(dropped.IpAddress);
            _logger.LogError(
                "Holding {Limit} unsaved bans: dropped the one of {Ip} (ends {Expires:u}) for {New}. Its firewall rule goes at the next reconcile unless the store has a ban for it.",
                MaxUnsavedBans,
                dropped.IpAddress,
                dropped.ExpiresUtc,
                ban.IpAddress);
        }

        _unsavedBans[ban.IpAddress] = ban;
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

            BufferDailyStatLocked(source, detections: 1, bans: 0);
        }
    }

    private void RecordBanStat(ProtocolSource source)
    {
        lock (_statsLock)
        {
            RollDetectionsDayLocked();
            BufferDailyStatLocked(source, detections: 0, bans: 1);
        }
    }

    private void BufferDailyStatLocked(ProtocolSource source, int detections, int bans) =>
        BufferDailyStatLocked(DateOnly.FromDateTime(_timeProvider.GetLocalNow().DateTime), source, detections, bans);

    private void BufferDailyStatLocked(DateOnly day, ProtocolSource source, int detections, int bans)
    {
        var key = (day, source);
        var current = _dailyStats.TryGetValue(key, out var existing)
            ? existing
            : (Detections: 0, Bans: 0);
        _dailyStats[key] = (current.Detections + detections, current.Bans + bans);
    }

    /// <summary>
    /// Drains the buffered daily-statistics deltas into the store. Called from housekeeping so the
    /// per-event hot path performs no statistics writes, and from StopAsync so a shutdown does not
    /// lose the day's tail. Whatever the store refuses goes back into the buffer for the next flush.
    /// </summary>
    private async Task FlushDailyStatsAsync(CancellationToken ct)
    {
        List<(DateOnly Day, ProtocolSource Source, int Detections, int Bans)> drained;
        lock (_statsLock)
        {
            if (_dailyStats.Count == 0)
            {
                return;
            }

            drained = _dailyStats
                .Select(pair => (pair.Key.Day, pair.Key.Source, pair.Value.Detections, pair.Value.Bans))
                .ToList();
            _dailyStats.Clear();
        }

        for (var i = 0; i < drained.Count; i++)
        {
            var entry = drained[i];
            try
            {
                var dayUtc = entry.Day.ToDateTime(TimeOnly.MinValue, DateTimeKind.Utc);
                await _store.AddDailyStatsAsync(dayUtc, entry.Source, entry.Detections, entry.Bans, ct).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Could not persist daily statistics for {Day}/{Source}; keeping them for the next flush.", entry.Day, entry.Source);
                lock (_statsLock)
                {
                    foreach (var unsaved in drained.Skip(i))
                    {
                        BufferDailyStatLocked(unsaved.Day, unsaved.Source, unsaved.Detections, unsaved.Bans);
                    }
                }

                return;
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

        // Remember the blacklisted CIDR entries in canonical form: housekeeping enforces them as
        // whole-subnet firewall range rules instead of banning each address on first contact. A
        // block rule beats every allow rule, so a range is cut around the addresses the whitelist
        // (which holds this server's own addresses too) must keep reachable.
        _blacklistedRanges = blacklist
            .Where(entry => !IpMatcher.TryNormalize(entry, out _))
            .Select(entry => IpMatcher.TryNormalizeRange(entry, out var canonical) ? canonical : null)
            .Where(canonical => canonical is not null && IpMatcher.IsBannableRange(canonical))
            .SelectMany(canonical => _matcher.SubtractWhitelist(canonical!))
            .Distinct(StringComparer.Ordinal)
            .ToList();

        ApplyBlocklist(whitelist);
    }

    /// <summary>
    /// The ban of this address, the unsaved one first as it is the newer. <c>Known</c> is false when
    /// the store could not be read: no ban is then all that can be said, not that there is none.
    /// </summary>
    private async Task<(BanEntry? Ban, bool Known)> FindBanAsync(string ip, CancellationToken ct)
    {
        if (_unsavedBans.TryGetValue(ip, out var unsaved))
        {
            return (unsaved, true);
        }

        try
        {
            return (await _store.GetBanAsync(ip, ct).ConfigureAwait(false), true);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _logger.LogError(ex, "BanEngine failed to read the existing ban for {Ip}.", ip);
            return (null, false);
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

    /// <summary>
    /// Enforcement-side block, honoring report-only mode: in monitoring mode the ban is still
    /// recorded in the store (and its history row written), but the firewall is left untouched.
    /// A target a list holds as well stays on all ports, however narrow the ban.
    /// </summary>
    private void TryBlock(string ipOrRange, PortSet ports)
    {
        if (FirewallFrozen)
        {
            return;
        }

        var effective = IsListTarget(ipOrRange) ? PortSet.All : ports;
        TryFirewall(() => _firewall.Block(ipOrRange, effective), "block", ipOrRange);
    }

    /// <summary>
    /// Enforcement-side unblock, honoring report-only mode like <see cref="TryBlock"/>. A rule from
    /// before the mode was switched on outlives its ban until then: reconcile lifts it as an orphan.
    /// A target a list holds as well stays blocked when its ban ends.
    /// </summary>
    private void TryUnblock(string ipOrRange)
    {
        if (FirewallFrozen || IsListTarget(ipOrRange))
        {
            return;
        }

        TryFirewall(() => _firewall.Unblock(ipOrRange), "unblock", ipOrRange);
    }

    private string ReportSuffix() =>
        IsDisarmed ? DisarmedNote : _settingsAccessor().ReportOnly ? ReportOnlyNote : string.Empty;

    /// <summary>Appends a ban-history row; failures are logged, never propagated.</summary>
    private async Task AddBanHistoryCoreAsync(BanHistoryEntry entry, CancellationToken ct)
    {
        try
        {
            await _store.AddBanHistoryAsync(entry, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not append ban history for {Ip}.", entry.IpAddress);
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

        // Fan out to notification sinks (webhook / Telegram / SMTP / Windows Event Log).
        // Publishers contract: non-blocking, exception-free.
        try
        {
            _publisher.Publish(logEvent);
        }
        catch (Exception)
        {
            // Isolated in the composite; belt and braces.
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
                await WaitForNextPassAsync(interval, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }

            try
            {
                await RefreshBlocklistsAsync(ct).ConfigureAwait(false);
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