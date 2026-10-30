using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;
using System.Threading.Channels;
using System.Xml;
using Microsoft.Extensions.Logging;
using WinGuard.Core.Config;
using WinGuard.Core.Engine;
using WinGuard.Core.Model;

namespace WinGuard.Core.Detection;

/// <summary>
/// Watches Security 4624 ("An account was successfully logged on") for network (3) and RDP (10)
/// logons and hands them to the engine, flagged <see cref="FailedLogin.IsSuccess"/>. Type 7 stays
/// out: Microsoft documents it only as "This workstation was unlocked", with nothing about a remote
/// source. An RDP logon with NLA logs a type 3 and a type 10; the engine's per-IP limit merges them.
/// <para>
/// A busy server logs 4624 constantly, so this detector stays unsubscribed while nothing needs the
/// events, the subscription filters as much as XPath can, and the fields are read without building
/// a document. Addresses cannot be filtered by range in XPath, so internal ones go here, before
/// the engine sees them.
/// </para>
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class LogonSuccessDetector : EventLogDetectorBase
{
    /// <summary>Event log channel this detector watches.</summary>
    public const string ChannelName = "Security";

    /// <summary>
    /// The payload filter: network and RDP logons with a client address, without local ones and
    /// without ANONYMOUS LOGON (S-1-5-7), a null session that proves nothing about a password.
    /// </summary>
    public const string EventDataXPath =
        "EventData[(Data[@Name='LogonType']='3' or Data[@Name='LogonType']='10')"
        + " and Data[@Name='IpAddress']!='-'"
        + " and Data[@Name='IpAddress']!='127.0.0.1'"
        + " and Data[@Name='IpAddress']!='::1'"
        + " and Data[@Name='TargetUserSid']!='" + AnonymousLogonSid + "']";

    /// <summary>XPath subscription query.</summary>
    public const string SubscriptionXPath =
        "<QueryList><Query Id=\"0\" Path=\"Security\"><Select Path=\"Security\">"
        + "*[System[(EventID=4624)] and " + EventDataXPath + "]"
        + "</Select></Query></QueryList>";

    private const string AnonymousLogonSid = "S-1-5-7";

    // A quarter of the shared channel. It drops its oldest entry when full, so beyond this a flood of
    // logons would start pushing out failures; missing an alert under such load costs less.
    internal const int MaxQueuedBeforeDropping = 5_000;

    private static readonly XmlReaderSettings ReaderSettings = new()
    {
        IgnoreComments = true,
        IgnoreProcessingInstructions = true,
        IgnoreWhitespace = true,
    };

    private readonly Func<WinGuardSettings> _settingsAccessor;
    private volatile bool _overloadLogged;

    /// <summary>Creates the detector.</summary>
    /// <param name="settingsAccessor">Returns the current live settings.</param>
    /// <param name="logger">Logger for subscription/parse diagnostics.</param>
    public LogonSuccessDetector(Func<WinGuardSettings> settingsAccessor, ILogger<LogonSuccessDetector> logger)
        : base(logger)
    {
        _settingsAccessor = settingsAccessor;
    }

    /// <inheritdoc />
    public override ProtocolSource Source => ProtocolSource.Rdp;

    /// <inheritdoc />
    public override string Name => "Logons (Security 4624)";

    /// <inheritdoc />
    protected override string LogChannel => ChannelName;

    /// <inheritdoc />
    protected override IReadOnlyList<(string Query, bool TolerateQueryErrors)> Queries => [(SubscriptionXPath, true)];

    /// <inheritdoc />
    protected override string? BacklogEventXPath => "EventID=4624";

    /// <inheritdoc />
    protected override string? BacklogDataXPath => EventDataXPath;

    /// <inheritdoc />
    protected override TimeSpan BacklogWindow()
    {
        var settings = _settingsAccessor();
        return settings.Rules.CompromiseAlerts
            ? TimeSpan.FromMinutes(Math.Max(0, settings.EventBacklogReplayMinutes))
            : TimeSpan.Zero;
    }

    /// <inheritdoc />
    protected override bool IsEnabled() => _settingsAccessor().Rules.ObservesLogons();

    /// <inheritdoc />
    private protected override bool WantsSubscription() => IsEnabled();

    /// <inheritdoc />
    private protected override bool ShouldForward(Channel<FailedLogin> sink)
    {
        if (HasRoom(sink))
        {
            _overloadLogged = false;
            return true;
        }

        if (!_overloadLogged)
        {
            _overloadLogged = true;
            Logger.LogWarning("{Detector}: the engine is behind; dropping logons so they cannot displace failures.", Name);
        }

        return false;
    }

    /// <summary>Whether a logon can still enter the shared channel without crowding out failures.</summary>
    internal static bool HasRoom(Channel<FailedLogin> sink) =>
        !sink.Reader.CanCount || sink.Reader.Count < MaxQueuedBeforeDropping;

    /// <inheritdoc />
    protected override FailedLogin? Parse(EventRecord record) =>
        TryParse(record.ToXml(), _settingsAccessor(), out var logon) ? logon : null;

    /// <summary>
    /// Parses a 4624 event XML record. Returns <see langword="false"/> for anything the engine has no
    /// use for: another event or logon type, no client address, an internal address while
    /// <see cref="WinGuardSettings.ProcessInternalIPs"/> is off, an anonymous or a machine logon.
    /// </summary>
    /// <param name="eventXml">The Event XML (as produced by <c>EventLogRecord.ToXml()</c>).</param>
    /// <param name="settings">Live settings.</param>
    /// <param name="logon">The logon when the method returns <see langword="true"/>, flagged as a success.</param>
    public static bool TryParse(string eventXml, WinGuardSettings settings, out FailedLogin? logon)
    {
        logon = null;
        if (string.IsNullOrWhiteSpace(eventXml)
            || settings is null
            || !TryReadFields(eventXml, out var fields)
            || fields.EventId != "4624"
            || !int.TryParse(fields.LogonType, out var logonType)
            || logonType is not (3 or 10)
            || fields.UserSid == AnonymousLogonSid
            || !IpMatcher.TryNormalize(fields.IpAddress, out var ip)
            || (!settings.ProcessInternalIPs && IpMatcher.IsInternal(ip)))
        {
            return false;
        }

        // Machine accounts log on over the network all day and are not people typing passwords.
        var user = DetectorUtil.NormalizeOptional(fields.UserName);
        if (user is null || user.EndsWith('$'))
        {
            return false;
        }

        logon = new FailedLogin
        {
            IpAddress = ip,
            UserName = user,
            Source = ProtocolSource.Rdp,
            Detector = "4624",
            TimestampUtc = DetectorUtil.ParseSystemTime(fields.SystemTime),
            IsSuccess = true,
            LogonType = logonType,
        };
        return true;
    }

    /// <summary>One forward pass over the record, which costs far less per event than a document.</summary>
    private static bool TryReadFields(string eventXml, out LogonFields fields)
    {
        fields = default;
        try
        {
            using var text = new StringReader(eventXml);
            using var reader = XmlReader.Create(text, ReaderSettings);
            while (!reader.EOF)
            {
                if (reader.NodeType != XmlNodeType.Element)
                {
                    reader.Read();
                    continue;
                }

                switch (reader.LocalName)
                {
                    case "EventID":
                        fields.EventId = reader.ReadElementContentAsString().Trim();
                        break;
                    case "TimeCreated":
                        fields.SystemTime = reader.GetAttribute("SystemTime");
                        reader.Read();
                        break;
                    case "Data":
                        var name = reader.GetAttribute("Name");
                        fields.Set(name, reader.ReadElementContentAsString());
                        break;
                    default:
                        reader.Read();
                        break;
                }
            }

            return true;
        }
        catch (XmlException)
        {
            return false;
        }
    }

    private struct LogonFields
    {
        public string? EventId;
        public string? SystemTime;
        public string? LogonType;
        public string? IpAddress;
        public string? UserName;
        public string? UserSid;

        public void Set(string? name, string value)
        {
            switch (name)
            {
                case "LogonType":
                    LogonType = value;
                    break;
                case "IpAddress":
                    IpAddress = value;
                    break;
                case "TargetUserName":
                    UserName = value;
                    break;
                case "TargetUserSid":
                    UserSid = value;
                    break;
            }
        }
    }
}
