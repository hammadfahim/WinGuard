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
public sealed class BanEngine
{
    private static readonly TimeSpan RdpDedupWindow = TimeSpan.FromSeconds(2);

    private readonly IStore _store;
    private readonly IFirewall _firewall;
    private readonly Func<WinGuardSettings> _settingsAccessor;
    private readonly ILogger<BanEngine> _logger;
    private readonly TimeProvider _timeProvider;

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly object _lifecycle = new();

    // Offense counts survive an expired-then-removed ban row within this process run, so
    // tier escalation keeps working across ban cycles (the schema stores it only on the
    // active ban; see final report / PLAN §5 step 7).
    private readonly Dictionary<string, int> _offenseCounts = new(StringComparer.Ordinal);

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
                if (!_offenseCounts.TryGetValue(ban.IpAddress, out var existing) || existing < ban.OffenseCount)
                {
                    _offenseCounts[ban.IpAddress] = ban.OffenseCount;
                }
            }

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

                _offenseCounts.Clear();
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
            await HousekeepCoreAsync(ct).ConfigureAwait(false);
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

    /// <summary>Manually blocks an IP (IPC <c>BlockNow</c>). Throws for invalid or whitelisted IPs.</summary>
    public async Task BanNowAsync(string ip, TimeSpan? duration, bool permanent, string? note, CancellationToken ct = default)
    {
        if (!IpMatcher.TryNormalize(ip, out var normalized))
        {
            throw new ArgumentException($"'{ip}' is not a valid IP address.", nameof(ip));
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
            var offense = ComputeOffense(normalized, existing);

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
            _offenseCounts[normalized] = offense;
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
            await TryAddEventAsync(new LogEvent
            {
                TimestampUtc = NowUtc(),
                Level = LogEventLevel.Info,
                Source = failed.Source,
                IpAddress = ip,
                Message = $"SKIPPED {ip} (whitelist)",
            }, ct).ConfigureAwait(false);
            return;
        }

        // RDP de-dup: 4625 and RdpCoreTS 140 describe the same attempt (PLAN §4.2).
        if (failed.Source == ProtocolSource.Rdp && await IsRdpDuplicateAsync(ip, failed.TimestampUtc, ct).ConfigureAwait(false))
        {
            _logger.LogDebug("Skipping duplicate RDP failure for {Ip}.", ip);
            return;
        }

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
            _offenseCounts[ip] = offense;
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
            await TryAddEventAsync(new LogEvent
            {
                TimestampUtc = now,
                Level = LogEventLevel.Info,
                Source = failed.Source,
                IpAddress = ip,
                Message = $"SKIPPED {ip} (already banned)",
            }, ct).ConfigureAwait(false);
            return;
        }

        // 5. Record the attempt.
        await _store.AddFailedLoginAsync(failed, ct).ConfigureAwait(false);

        // 6. Count within the rolling window (per protocol, so overrides apply).
        var window = settings.CountWindowFor(failed.Source);
        if (window <= TimeSpan.Zero)
        {
            window = settings.CountWindow;
        }

        var since = now - window;
        var count = await _store.CountFailedLoginsAsync(ip, since, failed.Source, ct).ConfigureAwait(false);

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
        _offenseCounts[ip] = nextOffense;
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

    private async Task<bool> IsRdpDuplicateAsync(string ip, DateTime timestampUtc, CancellationToken ct)
    {
        var since = timestampUtc - RdpDedupWindow;
        if (since < DateTime.MinValue)
        {
            since = DateTime.MinValue;
        }

        FailedLogin? recent;
        try
        {
            recent = await _store.GetRecentFailedLoginAsync(ip, ProtocolSource.Rdp, since, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "RDP de-dup lookup failed for {Ip}; processing normally.", ip);
            return false;
        }

        return recent is not null && Math.Abs((recent.TimestampUtc - timestampUtc).TotalSeconds) <= RdpDedupWindow.TotalSeconds;
    }

    private async Task HousekeepCoreAsync(CancellationToken ct)
    {
        var settings = _settingsAccessor();
        var now = NowUtc();
        var dueBans = await _store.GetDueBansAsync(now, ct).ConfigureAwait(false);

        // Expire due bans (the engine's clock is authoritative; the store must not pre-filter).
        foreach (var ban in dueBans)
        {
            if (ban.IsPermanent || ban.ExpiresUtc > now)
            {
                continue;
            }

            TryFirewall(() => _firewall.Unblock(ban.IpAddress), "unblock", ban.IpAddress);

            try
            {
                await _store.RemoveBanAsync(ban.IpAddress, ct).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Housekeeping failed to remove expired ban {Ip}.", ban.IpAddress);
            }

            _logger.LogInformation("Unbanned {Ip} (ban expired).", ban.IpAddress);
            await TryAddEventAsync(new LogEvent
            {
                TimestampUtc = now,
                Level = LogEventLevel.Info,
                Source = ban.Source,
                IpAddress = ban.IpAddress,
                Message = $"UNBANNED {ban.IpAddress}",
            }, ct).ConfigureAwait(false);
        }

        // Forget stale counters.
        var expireBefore = now - settings.ExpireTime;
        try
        {
            await _store.PruneFailedLoginsAsync(expireBefore, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Housekeeping failed to prune stale failed logins.");
        }

        await ReloadListsCoreAsync(ct).ConfigureAwait(false);
        await ReconcileFirewallCoreAsync(ct).ConfigureAwait(false);
    }

    private async Task ReconcileFirewallCoreAsync(CancellationToken ct)
    {
        IReadOnlyList<BanEntry> activeBans;
        IReadOnlyList<string> blocked;
        try
        {
            activeBans = await _store.GetActiveBansAsync(ct).ConfigureAwait(false);
            blocked = _firewall.ListBlocked();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Housekeeping reconcile failed to read bans/firewall state.");
            return;
        }

        var activeSet = new HashSet<string>(activeBans.Select(b => b.IpAddress), StringComparer.OrdinalIgnoreCase);

        // Remove orphan rules that no longer correspond to an active ban.
        foreach (var blockedIp in blocked)
        {
            if (!activeSet.Contains(blockedIp))
            {
                TryFirewall(() => _firewall.Unblock(blockedIp), "unblock orphan", blockedIp);
            }
        }

        // Re-add missing rules for active bans (self-heal after reboot/firewall reset).
        foreach (var ban in activeBans)
        {
            if (!blocked.Contains(ban.IpAddress, StringComparer.OrdinalIgnoreCase))
            {
                TryFirewall(() => _firewall.Block(ban.IpAddress), "re-block", ban.IpAddress);
            }
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
        if (_offenseCounts.TryGetValue(ip, out var cached) && cached > prior)
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
                await HousekeepOnceAsync(ct).ConfigureAwait(false);
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