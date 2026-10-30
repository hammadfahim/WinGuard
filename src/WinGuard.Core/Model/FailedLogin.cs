namespace WinGuard.Core.Model;

/// <summary>
/// A single failed login observed by one of the detectors.
/// Created by detectors, consumed (and normalized in place) by the BanEngine.
/// </summary>
public sealed class FailedLogin
{
    /// <summary>Normalized attacker IP (no port, no brackets; IPv6 lowercased).</summary>
    public string IpAddress { get; set; } = string.Empty;

    /// <summary>Account name the attacker tried, when known. May be null.</summary>
    public string? UserName { get; set; }

    /// <summary>Which engine observed the failure.</summary>
    public ProtocolSource Source { get; set; }

    /// <summary>
    /// Fine-grained detector identity within a <see cref="Source"/> (e.g. "4625" vs "140"
    /// for RDP, "iis-ftp" vs "filezilla" for FTP, the source name for custom logs).
    /// Used for 4625/140 de-duplication (only cross-detector pairs describe the same
    /// attempt) and diagnostics. Not persisted.
    /// </summary>
    public string? Detector { get; set; }

    /// <summary>When the failure happened, in UTC.</summary>
    public DateTime TimestampUtc { get; set; }

    /// <summary>
    /// True when an exclusion rule matched this failure. It is still sent to the engine so the
    /// counterpart event from the other RDP detector can be dropped as well; it is never counted.
    /// </summary>
    public bool IsExcluded { get; set; }

    /// <summary>
    /// True when this failure comes from the start-up backlog replay rather than a live event. The
    /// engine counts it only if it happened after the previous run stopped processing events.
    /// </summary>
    public bool IsReplayed { get; set; }

    /// <summary>
    /// True when this is a successful logon (Security 4624) on its way to the engine rather than a
    /// failure. Sharing the channel keeps it in order with the failures around it. It is never
    /// counted and never reaches failed_logins.
    /// </summary>
    public bool IsSuccess { get; set; }

    /// <summary>The Windows logon type of a successful logon (3 network, 10 RDP); 0 otherwise. Not persisted.</summary>
    public int LogonType { get; set; }

    /// <summary>The matched raw log/event text, for diagnostics. Not persisted.</summary>
    public string RawLog { get; set; } = string.Empty;
}
