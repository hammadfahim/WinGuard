using System.Globalization;
using Microsoft.Extensions.Logging;
using WinGuard.Core.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Model;

namespace WinGuard.Core.Engine;

/// <summary>Offense-count persistence, ban expiry, pruning and firewall reconciliation.</summary>
public sealed partial class BanEngine
{
    /// <summary>Restores the persisted offense counts, merging with the active-ban seed (max wins).</summary>
    private async Task LoadPersistedOffenseCountsAsync(CancellationToken ct)
    {
        try
        {
            var persisted = await _store.GetOffenseCountsAsync(ct).ConfigureAwait(false);
            foreach (var entry in persisted)
            {
                if (entry.Count > 0)
                {
                    _offenses.Seed(entry.IpAddress, entry.Count, entry.LastUtc);
                }
            }

            _logger.LogInformation(
                "Restored {Count} persisted offense count(s); tier escalation survives restarts.",
                persisted.Count);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not load persisted offense counts; escalation starts from active bans only.");
        }
    }

    /// <summary>
    /// Persists what changed so escalation survives service restarts (review ruling, topic #1). What
    /// the store refuses stays marked as changed for the next call; a ban never depends on this.
    /// </summary>
    private async Task SaveOffenseCountsAsync(CancellationToken ct)
    {
        var (changed, removed) = _offenses.GetUnsaved();
        if (changed.Count == 0 && removed.Count == 0)
        {
            return;
        }

        try
        {
            await _store.SaveOffenseCountsAsync(changed, removed, ct).ConfigureAwait(false);
            _offenses.MarkSaved();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not persist offense counts; retrying later, but escalation may reset if the service restarts first.");
        }
    }

    /// <summary>Restores the replay cutoff. Without a saved one nothing is replayed: the rows it would cover may already be counted.</summary>
    private async Task LoadReplayCutoffAsync(CancellationToken ct)
    {
        _startedUtc = NowUtc();
        _replayCutoffUtc = _startedUtc;
        try
        {
            var all = await _store.GetAllSettingsAsync(ct).ConfigureAwait(false);
            if (all.TryGetValue(LastAliveSettingKey, out var text)
                && DateTime.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var lastAlive)
                && lastAlive < _startedUtc)
            {
                _replayCutoffUtc = lastAlive;
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not read when the service last ran; skipping the backlog replay.");
        }
    }

    /// <summary>Records that every event logged up to now has been handled, for the next start's replay.</summary>
    private async Task SaveLastAliveAsync(CancellationToken ct)
    {
        try
        {
            await _store.SetSettingAsync(
                LastAliveSettingKey,
                NowUtc().ToString("o", CultureInfo.InvariantCulture),
                ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _logger.LogWarning(ex, "Could not save the replay position; the next backlog replay may repeat events.");
        }
    }

    /// <summary>Saves bans the store refused earlier and lifts the ones that have run out meanwhile.</summary>
    private async Task RetryUnsavedBansAsync(DateTime now, CancellationToken ct)
    {
        var storeDown = false;
        foreach (var ban in _unsavedBans.Values.ToList())
        {
            if (!ban.IsPermanent && ban.ExpiresUtc <= now)
            {
                _unsavedBans.Remove(ban.IpAddress);
                TryFirewall(() => _firewall.Unblock(ban.IpAddress), "unblock", ban.IpAddress);
                _offenses.Touch(ban.IpAddress, now);
                continue;
            }

            if (storeDown)
            {
                continue;
            }

            try
            {
                await _store.UpsertBanAsync(ban, ct).ConfigureAwait(false);
                _unsavedBans.Remove(ban.IpAddress);
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                storeDown = true;
                _logger.LogWarning(ex, "Still cannot save {Count} ban(s); they stay enforced.", _unsavedBans.Count);
            }
        }
    }

    /// <summary>
    /// Lifts range bans that hold a whitelisted address, however they got that way: a whitelist entry
    /// added later, a server address that changed, or a ban from a version without this check.
    /// </summary>
    private async Task LiftWhitelistedRangeBansAsync(IReadOnlyList<BanEntry> activeBans, CancellationToken ct)
    {
        foreach (var ban in activeBans)
        {
            if (ban.IpAddress.Contains('/') && _matcher.OverlapsWhitelist(ban.IpAddress))
            {
                _logger.LogWarning("Lifting range ban {Range}: it overlaps the whitelist.", ban.IpAddress);
                await UnbanCoreAsync(ban.IpAddress, $"UNBLOCKED {ban.IpAddress} (overlaps the whitelist)", ct).ConfigureAwait(false);
            }
        }
    }

    private async Task HousekeepCoreAsync(bool forceReconcile, CancellationToken ct)
    {
        var settings = _settingsAccessor();
        var now = NowUtc();

        _fallbackCounts.Trim(now - settings.ExpireTime);
        await RetryUnsavedBansAsync(now, ct).ConfigureAwait(false);

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

            await AddBanHistoryCoreAsync(new BanHistoryEntry
            {
                TimestampUtc = now,
                Action = BanHistoryAction.Expired,
                IpAddress = ban.IpAddress,
                Source = ban.Source,
                OffenseCount = ban.OffenseCount,
                Duration = ban.BannedAtUtc == DateTime.MinValue || ban.ExpiresUtc == DateTime.MaxValue
                    ? null
                    : ban.ExpiresUtc - ban.BannedAtUtc,
            }, ct).ConfigureAwait(false);

            // The escalation quiet period starts when the ban ENDS, not when the offense
            // was recorded — otherwise a 7d/30d ban would outlive its own offense record
            // and tier escalation would silently reset (E-M2 pruning interaction).
            _offenses.Touch(ban.IpAddress, now);

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

        // Event retention (review S-N4): keep the events table bounded.
        try
        {
            await _store.PruneEventsAsync(now - TimeSpan.FromDays(settings.EventRetentionDays > 0 ? settings.EventRetentionDays : Defaults.EventRetentionDays), ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Housekeeping failed to prune old events.");
        }

        // Trim the in-memory RDP de-dup window.
        _rdpDedup.Trim(now);
        if (now - _startedUtc > ReplayDedupLifetime)
        {
            _replayDedup.Clear();
        }

        // Prune stale offense counts (review E-M2): no active ban and nothing within OffenseMemory.
        IReadOnlyList<BanEntry>? activeForPrune = null;
        try
        {
            activeForPrune = await _store.GetActiveBansAsync(ct).ConfigureAwait(false);
            var activeIps = new HashSet<string>(activeForPrune.Select(b => b.IpAddress).Concat(_unsavedBans.Keys), StringComparer.Ordinal);
            _offenses.PruneStale(activeIps, now - settings.OffenseMemory);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Housekeeping failed to prune stale offense counts.");
        }

        // Everything this pass changed, plus whatever the store refused earlier.
        await SaveOffenseCountsAsync(ct).ConfigureAwait(false);

        await ReloadListsCoreAsync(ct).ConfigureAwait(false);

        if (activeForPrune is not null)
        {
            await LiftWhitelistedRangeBansAsync(activeForPrune, ct).ConfigureAwait(false);
        }

        // Persist the buffered per-day statistics deltas.
        await FlushDailyStatsAsync(ct).ConfigureAwait(false);
        await SaveLastAliveAsync(ct).ConfigureAwait(false);

        // Expiry above already unblocked what is due; the full firewall comparison is only a
        // self-heal against outside changes, so the timer loop runs it at most once a minute.
        if (forceReconcile || (now - _lastReconcileUtc).Duration() >= ReconcileInterval)
        {
            _lastReconcileUtc = now;
            await ReconcileFirewallCoreAsync(ct).ConfigureAwait(false);
        }
    }

    private async Task ReconcileFirewallCoreAsync(CancellationToken ct)
    {
        // Monitoring mode never enforces: leave the firewall alone entirely (bans recorded in
        // the store become enforced the moment report-only is switched off, right here).
        if (_settingsAccessor().ReportOnly)
        {
            return;
        }

        List<BanEntry> activeBans;
        IReadOnlyList<string> blocked;
        try
        {
            // Bans the store has not taken yet are enforced too: they are not orphans.
            activeBans = (await _store.GetActiveBansAsync(ct).ConfigureAwait(false))
                .Concat(_unsavedBans.Values)
                .ToList();
            blocked = _firewall.ListBlocked();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Housekeeping reconcile failed to read bans/firewall state.");
            return;
        }

        var blockedSet = new HashSet<string>(blocked, StringComparer.OrdinalIgnoreCase);
        var activeSet = new HashSet<string>(activeBans.Select(b => b.IpAddress), StringComparer.OrdinalIgnoreCase);

        // Blacklisted CIDR entries are enforced as whole-subnet range rules: they belong to the
        // expected state just like active bans (a blacklisted range is blocked as a whole, not
        // address-by-address on first contact).
        var expectedRanges = new List<string>();
        foreach (var range in _blacklistedRanges)
        {
            if (activeSet.Add(range))
            {
                expectedRanges.Add(range);
            }
        }

        // Remove orphan rules that no longer correspond to an active ban or blacklisted range.
        foreach (var blockedIp in blocked)
        {
            if (!activeSet.Contains(blockedIp))
            {
                TryFirewall(() => _firewall.Unblock(blockedIp), "unblock orphan", blockedIp);
            }
        }

        // Re-add missing rules for active bans (self-heal after reboot/firewall reset) and for
        // newly blacklisted subnets.
        foreach (var ban in activeBans)
        {
            if (!blockedSet.Contains(ban.IpAddress))
            {
                TryFirewall(() => _firewall.Block(ban.IpAddress), "re-block", ban.IpAddress);
            }
        }

        foreach (var range in expectedRanges)
        {
            if (!blockedSet.Contains(range))
            {
                TryFirewall(() => _firewall.Block(range), "blacklist range", range);
                _logger.LogInformation("Enforcing blacklisted subnet {Range} as a firewall range rule.", range);
            }
        }
    }
}
