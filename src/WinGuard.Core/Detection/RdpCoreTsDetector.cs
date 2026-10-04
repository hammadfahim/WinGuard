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
public sealed class RdpCoreTsDetector : EventLogDetectorBase
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

    /// <summary>Creates the detector.</summary>
    /// <param name="settingsAccessor">Returns the current live settings.</param>
    /// <param name="logger">Logger for subscription/parse diagnostics.</param>
    /// <param name="timeProvider">Accepted for API symmetry; the event's own SystemTime stamps the record.</param>
    public RdpCoreTsDetector(
        Func<WinGuardSettings> settingsAccessor,
        ILogger<RdpCoreTsDetector> logger,
        TimeProvider? timeProvider = null)
        : base(logger)
    {
        _settingsAccessor = settingsAccessor;
        _ = timeProvider;
    }

    /// <inheritdoc />
    public override ProtocolSource Source => ProtocolSource.Rdp;

    /// <inheritdoc />
    public override string Name => "RDP (RdpCoreTS 140)";

    /// <inheritdoc />
    protected override string LogChannel => ChannelName;

    /// <inheritdoc />
    protected override IReadOnlyList<(string Query, bool TolerateQueryErrors)> Queries => [(SubscriptionXPath, true)];

    /// <inheritdoc />
    protected override bool IsEnabled()
    {
        var rdp = _settingsAccessor().Rdp;
        return rdp.Enabled && rdp.UseRdpCoreTsFallback;
    }

    /// <inheritdoc />
    protected override FailedLogin? Parse(EventRecord record)
    {
        if (!TryParse(record.ToXml(), out var failed) || failed is null)
        {
            return null;
        }

        // A 140 event carries only the IP, so only IP-based exclusion rules can be applied here;
        // rules about user names or logon types are applied through the matching 4625 event.
        failed.IsExcluded = ExclusionEvaluator.IsExcludedByIpOnlyRules(failed.IpAddress, _settingsAccessor().Rdp.ExclusionRules);
        return failed;
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

    private static DateTime ParseSystemTime(XElement system, XNamespace ns) => DetectorUtil.ParseSystemTime(system, ns);
}