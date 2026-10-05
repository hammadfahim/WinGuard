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

    /// <summary>The matched raw log/event text, for diagnostics. Not persisted.</summary>
    public string RawLog { get; set; } = string.Empty;
}
