namespace WinGuard.Core.Model;

/// <summary>The lifecycle action that produced a ban-history row.</summary>
public enum BanHistoryAction
{
    /// <summary>The threshold was crossed (or the blacklist/manual block fired) and the IP was banned.</summary>
    Banned = 0,

    /// <summary>The ban expired and the IP was automatically unblocked.</summary>
    Expired = 1,

    /// <summary>An administrator removed the ban manually (optionally whitelisting the IP).</summary>
    Unbanned = 2,

    /// <summary>The ban was superseded (e.g. promoted to permanent or re-banned while still banned).</summary>
    Updated = 3,

    /// <summary>No change to a ban: an IP with failures or an active ban logged on successfully.</summary>
    SuspiciousLogon = 4,
}

/// <summary>
/// One row of the ban history: every ban, expiry and manual unban is recorded so administrators
/// can answer "how many attacks happened last month?" even though active bans are deleted on
/// expiry. Written by the engine, read by the statistics view; rows are never changed, and
/// housekeeping drops them once they are older than the retention period.
/// </summary>
public sealed class BanHistoryEntry
{
    /// <summary>Store-assigned monotonically increasing id (0 for rows not yet persisted).</summary>
    public long Id { get; set; }

    public DateTime TimestampUtc { get; set; }

    public BanHistoryAction Action { get; set; }

    /// <summary>Normalized banned IP (or IPv6 aggregate prefix, when aggregation is enabled).</summary>
    public string IpAddress { get; set; } = string.Empty;

    public ProtocolSource Source { get; set; }

    /// <summary>Offense count at the time of the action (tier the ban used).</summary>
    public int OffenseCount { get; set; }

    public bool IsPermanent { get; set; }

    /// <summary>How long the ban was set for (<c>null</c> for permanent).</summary>
    public TimeSpan? Duration { get; set; }

    public string? Note { get; set; }
}

/// <summary>Per-day, per-protocol activity counters kept by the engine and flushed during housekeeping.</summary>
public sealed class DailyStatEntry
{
    /// <summary>
    /// The day the counters belong to (date part only). Despite the name this is the server's LOCAL
    /// calendar day, which is what the dashboard's "today" means; it is only stored as a UTC value.
    /// </summary>
    public DateTime DayUtc { get; set; }

    public ProtocolSource Source { get; set; }

    /// <summary>Failed logins observed that day (after dedup, before any ban logic).</summary>
    public int Detections { get; set; }

    /// <summary>Bans issued that day for this protocol.</summary>
    public int Bans { get; set; }
}

/// <summary>Aggregated "top attacker" row for the statistics view (derived from ban history).</summary>
public sealed class TopOffenderEntry
{
    public string IpAddress { get; set; } = string.Empty;

    /// <summary>Total bans recorded for this IP in the queried window.</summary>
    public int BanCount { get; set; }

    /// <summary>Highest offense count reached (escalation tier indicator).</summary>
    public int MaxOffense { get; set; }

    /// <summary>Timestamp of the most recent ban for this IP (MinValue when none).</summary>
    public DateTime LastSeenUtc { get; set; }
}
