using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using System.Threading.Channels;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;
using WinGuard.Core.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Engine;
using WinGuard.Core.Model;

namespace WinGuard.Core.Detection;

/// <summary>
/// MS SQL Server detector: subscribes to Application log event 18456 ("Login failed") from a
/// provider whose name contains <c>MSSQL</c> (PLAN.md §4.3). The client IP is read from the
/// formatted message as <c>[CLIENT: x.x.x.x]</c> and the attempted login from the first
/// EventData value. Non-bruteforce reasons matching <see cref="MsSqlSettings.IgnoreMessagePatterns"/>
/// are skipped.
/// <para>
/// The provider filter in the XPath uses <c>contains()</c>; if the channel rejects that query at
/// runtime the detector transparently falls back to an EventID-only subscription and filters the
/// provider name in code.
/// </para>
/// <para>
/// Interactive users may write to the Application log, under any source name they like. An event
/// therefore only counts when its provider is an instance of SQL Server installed on this machine
/// (<see cref="SqlServerInstances"/>), which turns the forgery off wherever there is no SQL Server.
/// On a real SQL host a local user can still forge one: nothing in the event tells it apart. The
/// event's <c>Security UserID</c> does not help, because ReportEvent takes it from the caller
/// (lpUserSid, which may be NULL) and Microsoft documents no check of it. See SECURITY.md.
/// </para>
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class MsSqlDetector : EventLogDetectorBase
{
    /// <summary>Event log channel this detector watches.</summary>
    public const string ChannelName = "Application";

    /// <summary>Provider-filtered XPath subscription query from PLAN.md §4.3.</summary>
    public const string SubscriptionXPath = """
        <QueryList>
          <Query Id="0" Path="Application">
            <Select Path="Application">
              *[System[(EventID=18456)]] and *[System[Provider[contains(@Name,'MSSQL')]]]
            </Select>
          </Query>
        </QueryList>
        """;

    /// <summary>EventID-only fallback query used when the provider filter XPath is rejected.</summary>
    public const string FallbackSubscriptionXPath = """
        <QueryList>
          <Query Id="0" Path="Application">
            <Select Path="Application">
              *[System[(EventID=18456)]]
            </Select>
          </Query>
        </QueryList>
        """;

    private static readonly Regex ClientRegex = new(
        @"\[CLIENT:\s*(?<ip>[^\]]+)\]",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private readonly Func<WinGuardSettings> _settingsAccessor;
    private readonly SqlServerInstances _instances;

    /// <summary>Creates the detector.</summary>
    /// <param name="settingsAccessor">Returns the current live settings.</param>
    /// <param name="logger">Logger for subscription/parse diagnostics.</param>
    /// <param name="timeProvider">Clock for re-reading the installed instances; the event's own SystemTime stamps the record.</param>
    public MsSqlDetector(
        Func<WinGuardSettings> settingsAccessor,
        ILogger<MsSqlDetector> logger,
        TimeProvider? timeProvider = null)
        : this(settingsAccessor, logger, timeProvider, SqlServerInstances.ReadInstalledProviders)
    {
    }

    /// <summary>For the tests: a machine with whatever instances they need.</summary>
    internal MsSqlDetector(
        Func<WinGuardSettings> settingsAccessor,
        ILogger<MsSqlDetector> logger,
        TimeProvider? timeProvider,
        Func<IReadOnlySet<string>> readInstalledProviders)
        : base(logger)
    {
        _settingsAccessor = settingsAccessor;
        _instances = new SqlServerInstances(readInstalledProviders, timeProvider ?? TimeProvider.System, logger);
    }

    /// <inheritdoc />
    public override ProtocolSource Source => ProtocolSource.MsSql;

    /// <inheritdoc />
    public override string Name => "MS SQL (Application 18456)";

    /// <inheritdoc />
    protected override string LogChannel => ChannelName;

    /// <inheritdoc />
    protected override IReadOnlyList<(string Query, bool TolerateQueryErrors)> Queries =>
        [(SubscriptionXPath, false), (FallbackSubscriptionXPath, true)];

    /// <inheritdoc />
    /// <remarks>EventID-only: the provider is filtered in code by <see cref="Parse"/>, which also
    /// covers the backlog the same way the fallback subscription does.</remarks>
    protected override string? BacklogEventXPath => "EventID=18456";

    /// <inheritdoc />
    protected override TimeSpan BacklogWindow() =>
        TimeSpan.FromMinutes(Math.Max(0, _settingsAccessor().EventBacklogReplayMinutes));

    /// <inheritdoc />
    protected override bool IsEnabled() => _settingsAccessor().MsSql.Enabled;

    /// <inheritdoc />
    protected override FailedLogin? Parse(EventRecord record)
    {
        // No SQL Server here: nothing a user writes under its name is worth parsing.
        if (_instances.Current.Count == 0)
        {
            return null;
        }

        return ParseEvent(record.ToXml(), TryFormatDescription(record));
    }

    /// <summary>What <see cref="Parse"/> makes of an event's text, against this machine's instances.</summary>
    internal FailedLogin? ParseEvent(string eventXml, string? formattedMessage) =>
        TryParse(eventXml, formattedMessage, _settingsAccessor(), _instances.Current, out var failed) ? failed : null;

    /// <summary>
    /// Parses a 18456 event XML record plus its formatted message. The provider must be one of the
    /// installed instances (case-insensitive), the message must not contain any configured ignore
    /// pattern, and a valid client IP must be present in <c>[CLIENT: ...]</c>.
    /// </summary>
    /// <param name="eventXml">The Event XML (as produced by <c>EventLogRecord.ToXml()</c>).</param>
    /// <param name="formattedMessage">The provider-formatted message, or null when unavailable.</param>
    /// <param name="settings">Live settings providing ignore patterns.</param>
    /// <param name="installedProviders">Provider names of this machine's instances; see <see cref="SqlServerInstances"/>.</param>
    /// <param name="failed">The parsed failure when the method returns <see langword="true"/>.</param>
    public static bool TryParse(string eventXml, string? formattedMessage, WinGuardSettings settings, IReadOnlySet<string> installedProviders, out FailedLogin? failed)
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
        if (!string.Equals(eventId, "18456", StringComparison.Ordinal))
        {
            return false;
        }

        var provider = (string?)system.Element(ns + "Provider")?.Attribute("Name") ?? string.Empty;
        if (!installedProviders.Contains(provider))
        {
            return false;
        }

        var user = NormalizeOptional(
            root.Element(ns + "EventData")?.Elements(ns + "Data").FirstOrDefault()?.Value);

        // The message quotes the login name, which the client chooses: one spelled like an ignore
        // pattern must not switch counting off for that client.
        if (formattedMessage is not null
            && IsIgnored(user is null ? formattedMessage : formattedMessage.Replace($"'{user}'", string.Empty), settings.MsSql.IgnoreMessagePatterns))
        {
            return false;
        }

        var rawIp = ExtractClientIp(formattedMessage) ?? ExtractClientIp(eventXml);
        if (rawIp is null || !IpMatcher.TryNormalize(rawIp, out var ip))
        {
            return false;
        }

        failed = new FailedLogin
        {
            IpAddress = ip,
            UserName = user,
            Source = ProtocolSource.MsSql,
            Detector = "18456",
            TimestampUtc = ParseSystemTime(system, ns),
            RawLog = BuildRawLog(formattedMessage, ip, user),
        };
        return true;
    }

    private string? TryFormatDescription(EventRecord record)
    {
        try
        {
            return record is EventLogRecord logRecord ? logRecord.FormatDescription() : null;
        }
        catch (Exception ex)
        {
            // Message DLL missing / access denied: fall back to scanning the raw XML.
            Logger.LogDebug(ex, "FormatDescription failed for a 18456 record; using the raw event XML.");
            return null;
        }
    }

    private static string? ExtractClientIp(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return null;
        }

        // SQL Server appends "[CLIENT: ip]" at the END of the message. The login name earlier in the
        // text is chosen by the remote client, so an attacker could plant a fake "[CLIENT: x]" there:
        // only the last occurrence is trustworthy.
        var matches = ClientRegex.Matches(text);
        return matches.Count > 0 ? matches[^1].Groups["ip"].Value.Trim() : null;
    }

    private static bool IsIgnored(string message, string[] patterns)
    {
        if (patterns is null)
        {
            return false;
        }

        foreach (var pattern in patterns)
        {
            if (!string.IsNullOrEmpty(pattern)
                && message.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return true;
            }
        }

        return false;
    }

    private static DateTime ParseSystemTime(XElement system, XNamespace ns) => DetectorUtil.ParseSystemTime(system, ns);

    private static string? NormalizeOptional(string? value) => DetectorUtil.NormalizeOptional(value);

    private static string BuildRawLog(string? formattedMessage, string ip, string? user)
    {
        var detail = string.IsNullOrWhiteSpace(formattedMessage)
            ? "-"
            : formattedMessage.Replace('\r', ' ').Replace('\n', ' ').Trim();
        if (detail.Length > 200)
        {
            detail = detail[..200];
        }

        return $"EventID=18456 MSSQL login failure user={user ?? "-"} ip={ip} detail={detail}";
    }
}