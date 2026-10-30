using Microsoft.Extensions.Logging;
using WinGuard.Core.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Model;
using WinGuard.Core.Monitoring;

namespace WinGuard.Core.Engine;

/// <summary>Hands the numbers of a housekeeping pass to the metrics output.</summary>
public sealed partial class BanEngine
{
    /// <summary>Takes the metrics of each housekeeping pass; null leaves the feature out.</summary>
    public IMetricsPublisher? Metrics { get; init; }

    /// <summary>
    /// Everything used here is in memory already, and the publisher only queues, so this adds
    /// next to nothing to the time under the gate. A failure here must never touch a ban.
    /// </summary>
    /// <param name="settings">The settings of this pass.</param>
    /// <param name="activeBans">The bans this pass read; null when the store could not say.</param>
    /// <param name="now">The time of this pass.</param>
    private void PublishMetrics(WinGuardSettings settings, IReadOnlyList<BanEntry>? activeBans, DateTime now)
    {
        if (Metrics is null || activeBans is null || string.IsNullOrWhiteSpace(settings.PrometheusTextfilePath))
        {
            return;
        }

        try
        {
            var bans = activeBans.Concat(_unsavedBans.Values).DistinctBy(ban => ban.IpAddress).ToList();
            var engines = Enum.GetValues<ProtocolSource>()
                .Select(source => new EngineMetrics(
                    source.ToString().ToLowerInvariant(),
                    IsEngineEnabled(source, settings),
                    GetDetectionsToday(source),
                    bans.Count(ban => ban.Source == source)))
                .ToList();

            Metrics.Publish(
                new MetricsSnapshot(
                    now,
                    bans.Count,
                    engines,
                    (_firewall as IFirewallRuleCounter)?.CachedRuleCount,
                    settings.ReportOnly,
                    IsDisarmed,
                    settings.Notifications.Enabled,
                    settings.Notifications.Syslog.Enabled),
                settings.PrometheusTextfilePath);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not hand over the metrics of this housekeeping pass.");
        }
    }

    private static bool? IsEngineEnabled(ProtocolSource source, WinGuardSettings settings) => source switch
    {
        ProtocolSource.Rdp => settings.Rdp.Enabled,
        ProtocolSource.MsSql => settings.MsSql.Enabled,
        ProtocolSource.Ftp => settings.Ftp.Enabled,
        ProtocolSource.Custom => settings.CustomSources.Any(entry => entry.Enabled),
        _ => null,
    };
}
