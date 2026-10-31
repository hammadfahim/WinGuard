using Microsoft.Extensions.Logging;
using WinGuard.Core.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Model;

namespace WinGuard.Core.Engine;

/// <summary>
/// Port profiles: a ban blocks the ports of the engines that banned it, so an attacker of RDP behind
/// a shared address leaves the other services of that address alone. The bans table has one row per
/// address, so a second engine does not get a ban of its own: the row grows to cover both.
/// </summary>
public sealed partial class BanEngine
{
    /// <summary>True when the ban already blocks every port of the engine reporting this failure.</summary>
    private static bool BanCovers(BanEntry ban, FailedLogin failed, WinGuardSettings settings) =>
        PortProfiles.Resolve(ban.PortScope, settings)
            .Covers(PortProfiles.Resolve(PortProfiles.ScopeFor(failed.Source, failed.Detector), settings));

    /// <summary>
    /// Extends a ban to the ports of an engine whose threshold the address crossed while banned. This
    /// is an offense like any other, and it gets a full tier: without that a ban about to run out
    /// would barely touch the new service. Who banned it first and since when stay as they are.
    /// </summary>
    private async Task WidenBanAsync(BanEntry ban, FailedLogin failed, int offense, TimeSpan duration, WinGuardSettings settings, CancellationToken ct)
    {
        var now = NowUtc();
        var ip = ban.IpAddress;
        var widened = new BanEntry
        {
            IpAddress = ip,
            Source = ban.Source,
            BannedAtUtc = ban.BannedAtUtc,
            ExpiresUtc = ban.IsPermanent || ban.ExpiresUtc > now + duration ? ban.ExpiresUtc : now + duration,
            OffenseCount = offense,
            IsPermanent = ban.IsPermanent,
            Note = ban.Note,
            PortScope = PortProfiles.Widen(ban.PortScope, PortProfiles.ScopeFor(failed.Source, failed.Detector)),
        };
        var ports = EnforcedPorts(widened, settings);

        // Enforce first: a database problem must never leave an attacker unblocked.
        TryBlock(ip, ports);
        await SaveBanAsync(widened, ct).ConfigureAwait(false);
        _offenses.Set(ip, offense, now);
        await SaveOffenseCountsAsync(ct).ConfigureAwait(false);
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
            Action = BanHistoryAction.Updated,
            IpAddress = ip,
            Source = failed.Source,
            OffenseCount = offense,
            IsPermanent = widened.IsPermanent,
            Duration = widened.IsPermanent ? null : widened.ExpiresUtc - now,
            Note = $"widened to {ports}",
        }, ct).ConfigureAwait(false);

        var reportSuffix = ReportSuffix();
        _logger.LogWarning("Widened the ban of {Ip} to {Ports} (offense #{Offense}).{Suffix}", ip, ports, offense, reportSuffix);
        await TryAddEventAsync(new LogEvent
        {
            TimestampUtc = now,
            Level = LogEventLevel.Warning,
            Source = failed.Source,
            IpAddress = ip,
            Message = $"BLOCKED {ip}{PortsNote(ports)} (ban widened, offense #{offense}){reportSuffix}",
        }, ct).ConfigureAwait(false);
    }

    /// <summary>Makes a permanent ban all-ports, as the blacklist requires, and enforces it.</summary>
    private async Task EnsureAllPortsAsync(BanEntry ban, CancellationToken ct)
    {
        TryBlock(ban.IpAddress, PortSet.All);
        if (ban.PortScope != PortProfiles.AllPorts)
        {
            ban.PortScope = PortProfiles.AllPorts;
            await SaveBanAsync(ban, ct).ConfigureAwait(false);
        }
    }

    private static string PortsNote(PortSet ports) => ports.IsAll ? string.Empty : $" on ports {ports}";

    /// <summary>
    /// What a ban blocks right now. A blind ban stays on all ports: a block moves the address out of
    /// the rule holding it, and only all ports is sure to cover what the unread row may be blocking.
    /// </summary>
    private PortSet EnforcedPorts(BanEntry ban, WinGuardSettings settings) =>
        _blindBans.Contains(ban.IpAddress) ? PortSet.All : PortProfiles.Resolve(ban.PortScope, settings);

    /// <summary>
    /// Works a blind ban into the row the store turned out to hold, the way a widening would: a ban
    /// still running keeps its origin and only gains ports and time. The offense follows the row too,
    /// as the ban was counted without it. Call under the gate.
    /// </summary>
    private BanEntry SettleBlindBan(BanEntry blind, BanEntry? stored, DateTime now)
    {
        var settled = blind;
        if (stored is not null && (stored.IsPermanent || stored.ExpiresUtc > now))
        {
            var isPermanent = stored.IsPermanent || blind.IsPermanent;
            settled = new BanEntry
            {
                IpAddress = blind.IpAddress,
                Source = stored.Source,
                BannedAtUtc = stored.BannedAtUtc,
                ExpiresUtc = isPermanent ? DateTime.MaxValue : stored.ExpiresUtc > blind.ExpiresUtc ? stored.ExpiresUtc : blind.ExpiresUtc,
                IsPermanent = isPermanent,
                Note = stored.Note ?? blind.Note,
                PortScope = WidenScope(stored.PortScope, blind.PortScope),
            };
        }

        settled.OffenseCount = Math.Max(blind.OffenseCount, (stored?.OffenseCount ?? 0) + 1);
        _offenses.Set(blind.IpAddress, settled.OffenseCount, now);
        _blindBans.Remove(blind.IpAddress);
        _unsavedBans[blind.IpAddress] = settled;
        return settled;
    }

    /// <summary>A scope covering both, of which the second can name several engines.</summary>
    private static string? WidenScope(string? scope, string? other) => other == PortProfiles.AllPorts
        ? PortProfiles.AllPorts
        : (other ?? string.Empty).Split('\n', StringSplitOptions.RemoveEmptyEntries).Aggregate(scope, PortProfiles.Widen);

    /// <summary>True for a target that is blacklisted or on a blocklist exactly as written.</summary>
    private bool IsListTarget(string ipOrRange) =>
        _blocklistTargets.Contains(ipOrRange) || _blacklistedRanges.Contains(ipOrRange, StringComparer.Ordinal);

    /// <summary>
    /// What the firewall should hold: these bans, the ones the store has not taken yet, the
    /// blacklisted ranges and the blocklist entries. Unsaved bans are newer than what the store says,
    /// and whatever a list holds is blocked on all ports, like a blind ban.
    /// </summary>
    private List<FirewallTarget> FirewallTargets(IEnumerable<BanEntry> activeBans)
    {
        var settings = _settingsAccessor();
        var resolved = new Dictionary<string, PortSet>(StringComparer.Ordinal);
        var targets = new Dictionary<string, PortSet>(StringComparer.OrdinalIgnoreCase);
        foreach (var ban in activeBans.Concat(_unsavedBans.Values))
        {
            // Thousands of bans, a handful of scopes.
            var scope = ban.PortScope ?? string.Empty;
            if (!resolved.TryGetValue(scope, out var ports))
            {
                ports = PortProfiles.Resolve(ban.PortScope, settings);
                resolved[scope] = ports;
            }

            targets[ban.IpAddress] = _blindBans.Contains(ban.IpAddress) ? PortSet.All : ports;
        }

        foreach (var entry in _blacklistedRanges.Concat(_blocklistTargets))
        {
            targets[entry] = PortSet.All;
        }

        return targets.Select(target => new FirewallTarget(target.Key, target.Value)).ToList();
    }
}
