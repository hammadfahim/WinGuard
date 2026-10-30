namespace WinGuard.Core.Config;

/// <summary>Transport of the syslog channel.</summary>
public enum SyslogProtocol
{
    Udp = 0,
    Tcp = 1,
}

/// <summary>What the syslog message text looks like; the header is RFC 5424 either way.</summary>
public enum SyslogFormat
{
    /// <summary>The event as plain text.</summary>
    Rfc5424 = 0,

    /// <summary>ArcSight Common Event Format, for SIEMs that parse it.</summary>
    Cef = 1,
}

/// <summary>
/// Syslog output for SIEMs. Like the Windows Event Log it has its own switch, independent of the
/// notification master switch and of the chat rate limit: a SIEM wants the full record, and a
/// local collector is not a phone that buzzes. Off by default.
/// </summary>
public sealed class SyslogSettings
{
    public const int DefaultPort = 514;

    /// <summary>The RFC 5424 "security/authorization messages" facility.</summary>
    public const int DefaultFacility = 4;

    public const int MaxFacility = 23;

    public bool Enabled { get; set; }

    /// <summary>Receiver, as a host name or an address.</summary>
    public string Host { get; set; } = string.Empty;

    public int Port { get; set; } = DefaultPort;

    public SyslogProtocol Protocol { get; set; } = SyslogProtocol.Udp;

    public SyslogFormat Format { get; set; } = SyslogFormat.Rfc5424;

    /// <summary>RFC 5424 facility, 0 to 23.</summary>
    public int Facility { get; set; } = DefaultFacility;

    /// <summary>Repairs what would otherwise only fail at the first event; called from <see cref="WinGuardSettings.Normalize"/>.</summary>
    internal void Normalize()
    {
        Host = Host?.Trim() ?? string.Empty;
        Port = Port is >= 1 and <= 65535 ? Port : DefaultPort;
        Facility = Facility is >= 0 and <= MaxFacility ? Facility : DefaultFacility;
        Protocol = Enum.IsDefined(Protocol) ? Protocol : SyslogProtocol.Udp;
        Format = Enum.IsDefined(Format) ? Format : SyslogFormat.Rfc5424;
    }
}
