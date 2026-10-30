namespace WinGuard.Core.Model;

/// <summary>An active (or historical) firewall ban for one IP.</summary>
public sealed class BanEntry
{
    /// <summary>Normalized IP. Primary key in the bans table.</summary>
    public string IpAddress { get; set; } = string.Empty;

    /// <summary>Which engine first triggered the ban.</summary>
    public ProtocolSource Source { get; set; }

    public DateTime BannedAtUtc { get; set; }

    /// <summary>BannedAtUtc + current tier duration; <see cref="DateTime.MaxValue"/> when permanent.</summary>
    public DateTime ExpiresUtc { get; set; }

    /// <summary>How many times this IP has crossed the threshold (drives tier escalation).</summary>
    public int OffenseCount { get; set; } = 1;

    /// <summary>True for blacklist/manual permanent bans; never expires.</summary>
    public bool IsPermanent { get; set; }

    public string? Note { get; set; }
}

/// <summary>How many times one IP (or IPv6 prefix) has offended, which picks its next ban tier.</summary>
public sealed class OffenseCountEntry
{
    public string IpAddress { get; set; } = string.Empty;

    public int Count { get; set; }

    /// <summary>When the IP last offended or a ban of it ended; the offense memory runs from here.</summary>
    public DateTime LastUtc { get; set; }
}
