namespace WinGuard.Core.Model;

/// <summary>
/// A single failed login observed by one of the detectors.
/// Immutable; created by detectors, consumed by the BanEngine.
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

    /// <summary>The matched raw log/event text, for the GUI event feed and the DB.</summary>
    public string RawLog { get; set; } = string.Empty;
}
