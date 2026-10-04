using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Runtime.Versioning;
using System.Threading.Channels;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;
using WinGuard.Core.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Engine;
using WinGuard.Core.Model;

namespace WinGuard.Core.Detection;

/// <summary>
/// Primary RDP detector: subscribes to Security log event 4625 ("An account failed to log on")
/// with the audit-failure keyword filter from PLAN.md §4.1, extracts the client IP from the
/// EventData <c>IpAddress</c> field, applies the configured exclusion rules and pushes a
/// <see cref="FailedLogin"/> into the shared sink. Events with no usable IP are dropped so the
/// RdpCoreTS fallback can handle TLS/NLA connections (PLAN.md §4.1/§4.2).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class RdpSecurityLogDetector : IDetector
{
    /// <summary>Event log channel this detector watches.</summary>
    public const string ChannelName = "Security";

    /// <summary>XPath subscription query, exactly as specified in PLAN.md §4.1.</summary>
    public const string SubscriptionXPath = """
        <QueryList>
          <Query Id="0" Path="Security">
            <Select Path="Security">
              *[System[(EventID=4625) and (band(Keywords,0x8010000000000000))]]
            </Select>
          </Query>
        </QueryList>
        """;

    private readonly Func<WinGuardSettings> _settingsAccessor;
    private readonly ILogger<RdpSecurityLogDetector> _logger;
    private EventLogWatcher? _watcher;

    /// <summary>Creates the detector.</summary>
    /// <param name="settingsAccessor">Returns the current live settings.</param>
    /// <param name="logger">Logger for subscription/parse diagnostics.</param>
    /// <param name="timeProvider">Clock abstraction; defaults to <see cref="TimeProvider.System"/>.</param>
    public RdpSecurityLogDetector(
        Func<WinGuardSettings> settingsAccessor,
        ILogger<RdpSecurityLogDetector> logger,
        TimeProvider? timeProvider = null)
    {
        _settingsAccessor = settingsAccessor;
        _logger = logger;
        // The failure's own SystemTime is authoritative for this event-log engine; the injected
        // TimeProvider is accepted for API symmetry but is not used to stamp parsed records.
        _ = timeProvider;
    }

    /// <inheritdoc />
    public ProtocolSource Source => ProtocolSource.Rdp;

    /// <inheritdoc />
    public string Name => "RDP (Security 4625)";

    /// <inheritdoc />
    public Task StartAsync(Channel<FailedLogin> sink, CancellationToken ct)
    {
        if (!_settingsAccessor().Rdp.Enabled)
        {
            _logger.LogInformation("RDP Security 4625 detector is disabled by settings.");
            return Task.CompletedTask;
        }

        try
        {
            var query = new EventLogQuery(ChannelName, PathType.LogName, SubscriptionXPath)
            {
                TolerateQueryErrors = true,
            };
            var watcher = new EventLogWatcher(query);
            try
            {
                watcher.EventRecordWritten += (_, args) => OnEventRecord(args, sink);
                watcher.Enabled = true;
            }
            catch
            {
                watcher.Dispose();
                throw;
            }

            _watcher = watcher;
            ct.Register(DisposeWatcher);
            _logger.LogInformation("Subscribed to the {Channel} channel for 4625 failed-logon events.", ChannelName);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "RDP Security 4625 detector could not subscribe to the {Channel} channel; detection is inactive.", ChannelName);
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Parses a 4625 event XML record. Returns <see langword="false"/> when the record is not a
    /// 4625 event, carries no valid client IP, or is excluded by <see cref="RdpSettings.ExclusionRules"/>.
    /// </summary>
    /// <param name="eventXml">The Event XML (as produced by <c>EventLogRecord.ToXml()</c>).</param>
    /// <param name="settings">Live settings providing the exclusion rules.</param>
    /// <param name="failed">The parsed failure when the method returns <see langword="true"/>.</param>
    public static bool TryParse(string eventXml, WinGuardSettings settings, out FailedLogin? failed)
    {
        failed = null;
        if (string.IsNullOrWhiteSpace(eventXml) || settings is null)
        {
            return false;
        }

        XDocument document;
        try
        {
            document = XDocument.Parse(eventXml);
        }
        catch (Exception)
        {
            return false;
        }

        var root = document.Root;
        if (root is null)
        {
            return false;
        }

        var ns = root.Name.Namespace;
        var system = root.Element(ns + "System");
        if (system is null)
        {
            return false;
        }

        var eventId = system.Element(ns + "EventID")?.Value?.Trim();
        if (!string.Equals(eventId, "4625", StringComparison.Ordinal))
        {
            return false;
        }

        var eventData = ExtractEventData(root, ns);
        if (!eventData.TryGetValue("IpAddress", out var rawIp) || !IpMatcher.TryNormalize(rawIp, out var ip))
        {
            return false;
        }

        if (ExclusionEvaluator.IsExcluded(eventData, settings.Rdp.ExclusionRules))
        {
            return false;
        }

        var user = NormalizeOptional(eventData.GetValueOrDefault("TargetUserName"));
        failed = new FailedLogin
        {
            IpAddress = ip,
            UserName = user,
            Source = ProtocolSource.Rdp,
            TimestampUtc = ParseSystemTime(system, ns),
            RawLog = BuildRawLog(eventData, ip, user),
        };
        return true;
    }

    private void OnEventRecord(EventRecordWrittenEventArgs args, Channel<FailedLogin> sink)
    {
        // Live toggle: honor Rdp.Enabled per event, not only at subscribe time.
        if (!_settingsAccessor().Rdp.Enabled)
        {
            return;
        }

        try
        {
            var record = args.EventRecord;
            if (record is null)
            {
                if (args.EventException is not null)
                {
                    _logger.LogDebug(args.EventException, "Security 4625 subscription reported an event error.");
                }

                return;
            }

            string xml;
            using (record)
            {
                xml = record.ToXml();
            }

            if (TryParse(xml, _settingsAccessor(), out var failed) && failed is not null
                && !sink.Writer.TryWrite(failed))
            {
                _logger.LogWarning("RDP Security 4625 detector could not write to the sink channel (closed).");
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to process a Security 4625 event record.");
        }
    }

    private void DisposeWatcher()
    {
        try
        {
            var watcher = _watcher;
            _watcher = null;
            if (watcher is not null)
            {
                watcher.Enabled = false;
                watcher.Dispose();
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error while disposing the RDP Security 4625 watcher.");
        }
    }

    private static Dictionary<string, string> ExtractEventData(XElement root, XNamespace ns)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var eventData = root.Element(ns + "EventData");
        if (eventData is null)
        {
            return map;
        }

        foreach (var data in eventData.Elements(ns + "Data"))
        {
            var name = (string?)data.Attribute("Name");
            if (!string.IsNullOrEmpty(name))
            {
                map[name] = data.Value;
            }
        }

        return map;
    }

    private static DateTime ParseSystemTime(XElement system, XNamespace ns)
    {
        var value = (string?)system.Element(ns + "TimeCreated")?.Attribute("SystemTime");
        if (!string.IsNullOrWhiteSpace(value)
            && DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed))
        {
            return parsed.Kind == DateTimeKind.Utc ? parsed : parsed.ToUniversalTime();
        }

        return DateTime.UtcNow;
    }

    private static string? NormalizeOptional(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var trimmed = value.Trim();
        return trimmed == "-" ? null : trimmed;
    }

    private static string BuildRawLog(IReadOnlyDictionary<string, string> eventData, string ip, string? user)
    {
        static string Field(IReadOnlyDictionary<string, string> data, string key) =>
            data.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value : "-";

        return $"EventID=4625 RDP logon failure user={user ?? "-"} ip={ip} "
            + $"logonType={Field(eventData, "LogonType")} status={Field(eventData, "Status")} "
            + $"subStatus={Field(eventData, "SubStatus")} workstation={Field(eventData, "WorkstationName")}";
    }
}