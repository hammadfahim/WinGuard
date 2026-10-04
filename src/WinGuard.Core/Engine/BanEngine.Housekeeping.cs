using System.Globalization;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using WinGuard.Core.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Model;

namespace WinGuard.Core.Engine;

/// <summary>Offense-count persistence, ban expiry, pruning and firewall reconciliation.</summary>
public sealed partial class BanEngine
{
    /// <summary>Restores offense counts from the settings blob, merging with the active-ban seed (max wins).</summary>
    private async Task LoadPersistedOffenseCountsAsync(CancellationToken ct)
    {
        try
        {
            var all = await _store.GetAllSettingsAsync(ct).ConfigureAwait(false);
            if (!all.TryGetValue(OffenseCountsSettingKey, out var json) || string.IsNullOrWhiteSpace(json))
            {
                return;
            }

            var persisted = JsonSerializer.Deserialize<Dictionary<string, OffenseRecord>>(json);
            if (persisted is null)
            {
                return;
            }

            foreach (var (ip, record) in persisted)
            {
                if (record is null || record.Count <= 0)
                {
                    continue;
                }

                _offenses.Seed(ip, record.Count, record.LastUtc);
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

    /// <summary>Persists the offense-count map so escalation survives service restarts (review ruling, topic #1).</summary>
    private async Task SaveOffenseCountsAsync(CancellationToken ct)
    {
        try
        {
            var now = NowUtc();
            var snapshot = _offenses.Snapshot(now);
            await _store.SetSettingAsync(
                OffenseCountsSettingKey,
                JsonSerializer.Serialize(snapshot),
                ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not persist offense counts; escalation may reset on restart.");
        }
    }

    private async Task HousekeepCoreAsync(bool forceReconcile, CancellationToken ct)
    {
        var settings = _settingsAccessor();
        var now = NowUtc();
        var dueBans = await _store.GetDueBansAsync(now, ct).ConfigureAwait(false);

        // Expire due bans (the engine's clock is authoritative; the store must not pre-filter).
        var offensesTouched = false;
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

            // The escalation quiet period starts when the ban ENDS, not when the offense
            // was recorded — otherwise a 7d/30d ban would outlive its own offense record
            // and tier escalation would silently reset (E-M2 pruning interaction).
            _offenses.Touch(ban.IpAddress, now);
            offensesTouched = true;

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

        if (offensesTouched)
        {
            await SaveOffenseCountsAsync(ct).ConfigureAwait(false);
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
            await _store.PruneEventsAsync(now - TimeSpan.FromDays(settings.EventRetentionDays > 0 ? settings.EventRetentionDays : DefaultEventRetentionDays), ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Housekeeping failed to prune old events.");
        }

        // Trim the in-memory RDP de-dup window.
        _rdpDedup.Trim(now);

        // Prune stale offense counts (review E-M2): no active ban and no offense within
        // ExpireTime x 4; rewrite the persisted blob when anything was removed.
        try
        {
            var activeForPrune = await _store.GetActiveBansAsync(ct).ConfigureAwait(false);
            var activeIps = new HashSet<string>(activeForPrune.Select(b => b.IpAddress), StringComparer.Ordinal);
            var offenseCutoff = now - TimeSpan.FromTicks(settings.ExpireTime.Ticks * 4);
            var removed = _offenses.PruneStale(activeIps, offenseCutoff);
            if (removed > 0)
            {
                await SaveOffenseCountsAsync(ct).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Housekeeping failed to prune stale offense counts.");
        }

        await ReloadListsCoreAsync(ct).ConfigureAwait(false);

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
}
