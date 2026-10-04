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
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class MsSqlDetector : IDetector
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
    private readonly ILogger<MsSqlDetector> _logger;
    private EventLogWatcher? _watcher;

    /// <summary>Creates the detector.</summary>
    /// <param name="settingsAccessor">Returns the current live settings.</param>
    /// <param name="logger">Logger for subscription/parse diagnostics.</param>
    /// <param name="timeProvider">Clock abstraction; defaults to <see cref="TimeProvider.System"/>.</param>
    public MsSqlDetector(
        Func<WinGuardSettings> settingsAccessor,
        ILogger<MsSqlDetector> logger,
        TimeProvider? timeProvider = null)
    {
        _settingsAccessor = settingsAccessor;
        _logger = logger;
        // The failure's own SystemTime is authoritative for this event-log engine; the injected
        // TimeProvider is accepted for API symmetry but is not used to stamp parsed records.
        _ = timeProvider;
    }

    /// <inheritdoc />
    public ProtocolSource Source => ProtocolSource.MsSql;

    /// <inheritdoc />
    public string Name => "MS SQL (Application 18456)";

    /// <inheritdoc />
    public Task StartAsync(Channel<FailedLogin> sink, CancellationToken ct)
    {
        if (!_settingsAccessor().MsSql.Enabled)
        {
            _logger.LogInformation("MS SQL 18456 detector is disabled by settings.");
            return Task.CompletedTask;
        }

        var watcher = TrySubscribe(SubscriptionXPath, sink, tolerateQueryErrors: false, "provider-filtered");
        if (watcher is null)
        {
            _logger.LogWarning("MS SQL detector: provider-filtered XPath was rejected; falling back to an EventID-only subscription.");
            watcher = TrySubscribe(FallbackSubscriptionXPath, sink, tolerateQueryErrors: true, "EventID-only");
        }

        if (watcher is null)
        {
            _logger.LogError("MS SQL 18456 detector could not subscribe to the {Channel} channel; detection is inactive.", ChannelName);
            return Task.CompletedTask;
        }

        _watcher = watcher;
        ct.Register(DisposeWatcher);
        _logger.LogInformation("Subscribed to the {Channel} channel for 18456 login-failure events.", ChannelName);
        return Task.CompletedTask;
    }

    /// <summary>
    /// Parses a 18456 event XML record plus its formatted message. The provider name must contain
    /// <c>MSSQL</c> (case-insensitive), the message must not contain any configured ignore pattern,
    /// and a valid client IP must be present in <c>[CLIENT: ...]</c>.
    /// </summary>
    /// <param name="eventXml">The Event XML (as produced by <c>EventLogRecord.ToXml()</c>).</param>
    /// <param name="formattedMessage">The provider-formatted message, or null when unavailable.</param>
    /// <param name="settings">Live settings providing ignore patterns.</param>
    /// <param name="failed">The parsed failure when the method returns <see langword="true"/>.</param>
    public static bool TryParse(string eventXml, string? formattedMessage, WinGuardSettings settings, out FailedLogin? failed)
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
        if (provider.IndexOf("MSSQL", StringComparison.OrdinalIgnoreCase) < 0)
        {
            return false;
        }

        if (formattedMessage is not null && IsIgnored(formattedMessage, settings.MsSql.IgnoreMessagePatterns))
        {
            return false;
        }

        var rawIp = ExtractClientIp(formattedMessage) ?? ExtractClientIp(eventXml);
        if (rawIp is null || !IpMatcher.TryNormalize(rawIp, out var ip))
        {
            return false;
        }

        var user = NormalizeOptional(
            root.Element(ns + "EventData")?.Elements(ns + "Data").FirstOrDefault()?.Value);

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

    private EventLogWatcher? TrySubscribe(string xpath, Channel<FailedLogin> sink, bool tolerateQueryErrors, string description)
    {
        EventLogWatcher? watcher = null;
        try
        {
            var query = new EventLogQuery(ChannelName, PathType.LogName, xpath)
            {
                TolerateQueryErrors = tolerateQueryErrors,
            };
            watcher = new EventLogWatcher(query);
            watcher.EventRecordWritten += (_, args) => OnEventRecord(args, sink);
            watcher.Enabled = true;
            return watcher;
        }
        catch (Exception ex)
        {
            watcher?.Dispose();
            _logger.LogDebug(ex, "MS SQL {Description} subscription attempt failed.", description);
            return null;
        }
    }

    private void OnEventRecord(EventRecordWrittenEventArgs args, Channel<FailedLogin> sink)
    {
        // Live toggle: honor MsSql.Enabled per event, not only at subscribe time.
        if (!_settingsAccessor().MsSql.Enabled)
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
                    _logger.LogDebug(args.EventException, "MS SQL 18456 subscription reported an event error.");
                }

                return;
            }

            string xml;
            string? message;
            using (record)
            {
                xml = record.ToXml();
                message = TryFormatDescription(record);
            }

            if (TryParse(xml, message, _settingsAccessor(), out var failed) && failed is not null
                && !sink.Writer.TryWrite(failed))
            {
                _logger.LogWarning("MS SQL 18456 detector could not write to the sink channel (closed).");
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to process an Application 18456 event record.");
        }
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
            _logger.LogDebug(ex, "FormatDescription failed for a 18456 record; using the raw event XML.");
            return null;
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
            _logger.LogDebug(ex, "Error while disposing the MS SQL 18456 watcher.");
        }
    }

    private static string? ExtractClientIp(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return null;
        }

        var match = ClientRegex.Match(text);
        return match.Success ? match.Groups["ip"].Value.Trim() : null;
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