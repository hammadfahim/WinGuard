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
public sealed class RdpSecurityLogDetector : EventLogDetectorBase
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

    /// <summary>Creates the detector.</summary>
    /// <param name="settingsAccessor">Returns the current live settings.</param>
    /// <param name="logger">Logger for subscription/parse diagnostics.</param>
    /// <param name="timeProvider">Accepted for API symmetry; the event's own SystemTime stamps the record.</param>
    public RdpSecurityLogDetector(
        Func<WinGuardSettings> settingsAccessor,
        ILogger<RdpSecurityLogDetector> logger,
        TimeProvider? timeProvider = null)
        : base(logger)
    {
        _settingsAccessor = settingsAccessor;
        _ = timeProvider;
    }

    /// <inheritdoc />
    public override ProtocolSource Source => ProtocolSource.Rdp;

    /// <inheritdoc />
    public override string Name => "RDP (Security 4625)";

    /// <inheritdoc />
    protected override string LogChannel => ChannelName;

    /// <inheritdoc />
    protected override IReadOnlyList<(string Query, bool TolerateQueryErrors)> Queries => [(SubscriptionXPath, true)];

    /// <inheritdoc />
    protected override string? BacklogEventXPath => "EventID=4625";

    /// <inheritdoc />
    protected override TimeSpan BacklogWindow() =>
        TimeSpan.FromMinutes(Math.Max(0, _settingsAccessor().EventBacklogReplayMinutes));

    /// <inheritdoc />
    protected override bool IsEnabled() => _settingsAccessor().Rdp.Enabled;

    /// <inheritdoc />
    protected override FailedLogin? Parse(EventRecord record)
    {
        // An excluded failure is still forwarded (flagged) so the engine can drop the RdpCoreTS
        // 140 event that describes the same attempt.
        TryParseDetailed(record.ToXml(), _settingsAccessor(), out var failed, out var excluded);
        if (failed is not null)
        {
            failed.IsExcluded = excluded;
        }

        return failed;
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
        if (TryParseDetailed(eventXml, settings, out failed, out var excluded) && !excluded)
        {
            return true;
        }

        failed = null;
        return false;
    }

    /// <summary>
    /// Like <see cref="TryParse"/>, but an event removed by an exclusion rule is still returned,
    /// with <paramref name="excluded"/> set, instead of being dropped.
    /// </summary>
    public static bool TryParseDetailed(string eventXml, WinGuardSettings settings, out FailedLogin? failed, out bool excluded)
    {
        failed = null;
        excluded = false;
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

        excluded = ExclusionEvaluator.IsExcluded(eventData, settings.Rdp.ExclusionRules);

        var user = NormalizeOptional(eventData.GetValueOrDefault("TargetUserName"));
        failed = new FailedLogin
        {
            IpAddress = ip,
            UserName = user,
            Source = ProtocolSource.Rdp,
            Detector = "4625",
            TimestampUtc = ParseSystemTime(system, ns),
            RawLog = BuildRawLog(eventData, ip, user),
        };
        return true;
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

    private static DateTime ParseSystemTime(XElement system, XNamespace ns) => DetectorUtil.ParseSystemTime(system, ns);

    private static string? NormalizeOptional(string? value) => DetectorUtil.NormalizeOptional(value);

    private static string BuildRawLog(IReadOnlyDictionary<string, string> eventData, string ip, string? user)
    {
        static string Field(IReadOnlyDictionary<string, string> data, string key) =>
            data.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value : "-";

        return $"EventID=4625 RDP logon failure user={user ?? "-"} ip={ip} "
            + $"logonType={Field(eventData, "LogonType")} status={Field(eventData, "Status")} "
            + $"subStatus={Field(eventData, "SubStatus")} workstation={Field(eventData, "WorkstationName")}";
    }
}