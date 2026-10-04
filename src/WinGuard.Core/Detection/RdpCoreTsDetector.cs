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
/// RDP TLS/NLA fallback detector: subscribes to
/// <c>Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational</c> event 140, which logs the
/// client IP even when a Security 4625 record has an empty source over TLS (PLAN.md §4.2). The
/// resulting failure uses <see cref="ProtocolSource.Rdp"/> so the BanEngine can de-duplicate it
/// against the matching 4625.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class RdpCoreTsDetector : IDetector
{
    /// <summary>Event log channel this detector watches.</summary>
    public const string ChannelName = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational";

    /// <summary>XPath subscription query, exactly as specified in PLAN.md §4.2.</summary>
    public const string SubscriptionXPath = """
        <QueryList>
          <Query Id="0" Path="Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational">
            <Select Path="Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational">
              *[System[(EventID=140)]]
            </Select>
          </Query>
        </QueryList>
        """;

    private readonly Func<WinGuardSettings> _settingsAccessor;
    private readonly ILogger<RdpCoreTsDetector> _logger;
    private EventLogWatcher? _watcher;

    /// <summary>Creates the detector.</summary>
    /// <param name="settingsAccessor">Returns the current live settings.</param>
    /// <param name="logger">Logger for subscription/parse diagnostics.</param>
    /// <param name="timeProvider">Clock abstraction; defaults to <see cref="TimeProvider.System"/>.</param>
    public RdpCoreTsDetector(
        Func<WinGuardSettings> settingsAccessor,
        ILogger<RdpCoreTsDetector> logger,
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
    public string Name => "RDP (RdpCoreTS 140)";

    /// <inheritdoc />
    public Task StartAsync(Channel<FailedLogin> sink, CancellationToken ct)
    {
        var settings = _settingsAccessor();
        if (!settings.Rdp.Enabled || !settings.Rdp.UseRdpCoreTsFallback)
        {
            _logger.LogInformation("RdpCoreTS 140 fallback detector is disabled by settings.");
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
            _logger.LogInformation("Subscribed to the {Channel} channel for event 140.", ChannelName);
        }
        catch (Exception ex)
        {
            // Channel may be absent when the RDP role is not installed: degrade gracefully.
            _logger.LogError(ex, "RdpCoreTS 140 detector could not subscribe to {Channel}; fallback detection is inactive.", ChannelName);
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Parses a RdpCoreTS 140 event XML record, extracting the client IP from the
    /// EventData <c>IPString</c> field. Returns <see langword="false"/> for other event IDs or when
    /// no valid IP is present.
    /// </summary>
    /// <param name="eventXml">The Event XML (as produced by <c>EventLogRecord.ToXml()</c>).</param>
    /// <param name="failed">The parsed failure when the method returns <see langword="true"/>.</param>
    public static bool TryParse(string eventXml, out FailedLogin? failed)
    {
        failed = null;
        if (string.IsNullOrWhiteSpace(eventXml))
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
        if (!string.Equals(eventId, "140", StringComparison.Ordinal))
        {
            return false;
        }

        var dataElements = root.Element(ns + "EventData")?.Elements(ns + "Data").ToList();
        var rawIp = dataElements?
            .FirstOrDefault(data => string.Equals((string?)data.Attribute("Name"), "IPString", StringComparison.OrdinalIgnoreCase))
            ?.Value;

        if (string.IsNullOrEmpty(rawIp))
        {
            // Some RdpCoreTS builds emit event 140 with a single unnamed Data element; fall back
            // to the first positional value when the named IPString field is absent (or empty).
            rawIp = dataElements?.FirstOrDefault()?.Value;
        }

        if (!IpMatcher.TryNormalize(rawIp, out var ip))
        {
            return false;
        }

        failed = new FailedLogin
        {
            IpAddress = ip,
            UserName = null,
            Source = ProtocolSource.Rdp,
            Detector = "140",
            TimestampUtc = ParseSystemTime(system, ns),
            RawLog = $"EventID=140 RdpCoreTS connection failure ip={ip}",
        };
        return true;
    }

    private void OnEventRecord(EventRecordWrittenEventArgs args, Channel<FailedLogin> sink)
    {
        // Live toggle: honor Rdp.Enabled + UseRdpCoreTsFallback per event, not only at subscribe time.
        var current = _settingsAccessor();
        if (!current.Rdp.Enabled || !current.Rdp.UseRdpCoreTsFallback)
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
                    _logger.LogDebug(args.EventException, "RdpCoreTS 140 subscription reported an event error.");
                }

                return;
            }

            string xml;
            using (record)
            {
                xml = record.ToXml();
            }

            if (TryParse(xml, out var failed) && failed is not null
                && !sink.Writer.TryWrite(failed))
            {
                _logger.LogWarning("RdpCoreTS 140 detector could not write to the sink channel (closed).");
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to process a RdpCoreTS 140 event record.");
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
            _logger.LogDebug(ex, "Error while disposing the RdpCoreTS 140 watcher.");
        }
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
}