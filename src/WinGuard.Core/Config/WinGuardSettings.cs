using System.Text.Json;
using WinGuard.Core.Model;

namespace WinGuard.Core.Config;

/// <summary>
/// Strongly-typed live settings (PLAN.md §5/§6 + §4.4/§4.5). Stored in the DB
/// (settings table, single JSON blob under key "engine"), hot-swapped by the service
/// when the GUI sends UpdateSettings. Held behind a Func&lt;WinGuardSettings&gt; so every
/// component always sees the current instance.
/// </summary>
public sealed class WinGuardSettings
{
    public int FailedLoginThreshold { get; set; } = Defaults.FailedLoginThreshold;
    public TimeSpan CountWindow { get; set; } = Defaults.CountWindow;
    public TimeSpan ExpireTime { get; set; } = Defaults.ExpireTime;
    public TimeSpan[] BanTiers { get; set; } = (TimeSpan[])Defaults.BanTiers.Clone();
    public TimeSpan MaxBanDuration { get; set; } = Defaults.MaxBanDuration;
    public TimeSpan HousekeepingInterval { get; set; } = Defaults.HousekeepingInterval;
    public bool ClearBansOnStartup { get; set; }
    public bool ProcessInternalIPs { get; set; }
    public int MaxAddressesPerRule { get; set; } = Defaults.MaxAddressesPerRule;

    /// <summary>Empty = block all ports (1 firewall condition per IP; cheapest). Non-empty = block only these ports.</summary>
    public string[] BlockedPorts { get; set; } = [];

    public RdpSettings Rdp { get; set; } = new();
    public MsSqlSettings MsSql { get; set; } = new();
    public FtpSettings Ftp { get; set; } = new();
    public List<CustomLogSource> CustomSources { get; set; } = [];

    /// <summary>Effective threshold for a protocol (per-protocol override wins).</summary>
    public int ThresholdFor(ProtocolSource source) => source switch
    {
        ProtocolSource.Rdp => Rdp.Threshold ?? FailedLoginThreshold,
        ProtocolSource.MsSql => MsSql.Threshold ?? FailedLoginThreshold,
        ProtocolSource.Ftp => Ftp.Threshold ?? FailedLoginThreshold,
        _ => FailedLoginThreshold,
    };

    /// <summary>Effective count window for a protocol (per-protocol override wins).</summary>
    public TimeSpan CountWindowFor(ProtocolSource source) => source switch
    {
        ProtocolSource.Rdp => Rdp.CountWindow ?? CountWindow,
        ProtocolSource.MsSql => MsSql.CountWindow ?? CountWindow,
        ProtocolSource.Ftp => Ftp.CountWindow ?? CountWindow,
        _ => CountWindow,
    };

    /// <summary>Duration for the Nth offense (1-based): BanTiers[min(offense-1, len-1)], capped at MaxBanDuration.</summary>
    public TimeSpan TierForOffense(int offenseCount)
    {
        if (BanTiers.Length == 0)
        {
            return MaxBanDuration;
        }

        var tier = BanTiers[Math.Clamp(offenseCount - 1, 0, BanTiers.Length - 1)];
        return tier > MaxBanDuration ? MaxBanDuration : tier;
    }

    public WinGuardSettings Clone() =>
        JsonSerializer.Deserialize<WinGuardSettings>(JsonSerializer.Serialize(this))!;

    /// <summary>Basic sanity clamps applied after loading from DB/IPC.</summary>
    public void Normalize()
    {
        FailedLoginThreshold = Math.Max(1, FailedLoginThreshold);
        MaxAddressesPerRule = Math.Clamp(MaxAddressesPerRule, 1, Defaults.MaxAddressesPerRule);
        if (CountWindow <= TimeSpan.Zero)
        {
            CountWindow = Defaults.CountWindow;
        }

        if (ExpireTime <= TimeSpan.Zero)
        {
            ExpireTime = Defaults.ExpireTime;
        }

        if (HousekeepingInterval < TimeSpan.FromSeconds(1))
        {
            HousekeepingInterval = Defaults.HousekeepingInterval;
        }

        BanTiers = BanTiers is { Length: > 0 } ? BanTiers : (TimeSpan[])Defaults.BanTiers.Clone();

        // Drop non-positive tiers (bad IPC input); fall back to defaults when none survive.
        var positiveTiers = BanTiers.Where(t => t > TimeSpan.Zero).ToArray();
        BanTiers = positiveTiers.Length > 0 ? positiveTiers : (TimeSpan[])Defaults.BanTiers.Clone();

        // BlockedPorts tokens reach the firewall LocalPorts property: keep only "port" or
        // "start-end" numeric forms so garbage can't break rule creation.
        BlockedPorts = BlockedPorts
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Select(p => p.Trim())
            .Where(p => System.Text.RegularExpressions.Regex.IsMatch(p, @"^\d+(-\d+)?$"))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }
}

/// <summary>Shared per-protocol knobs.</summary>
public abstract class ProtocolSettings
{
    public bool Enabled { get; set; } = true;

    /// <summary>Overrides the global FailedLoginThreshold when set.</summary>
    public int? Threshold { get; set; }

    /// <summary>Overrides the global CountWindow when set.</summary>
    public TimeSpan? CountWindow { get; set; }
}

public sealed class RdpSettings : ProtocolSettings
{
    /// <summary>Also subscribe to RdpCoreTS/Operational 140 (TLS/NLA fallback). PLAN.md §4.2.</summary>
    public bool UseRdpCoreTsFallback { get; set; } = true;

    /// <summary>
    /// 4625 exclusion rules (PLAN.md §6): "Key=Value" conditions, ',' = AND within a rule,
    /// separate array entries = OR, '*' wildcard, '!=' negation.
    /// Example: "LogonType=2", "TargetUserName=backup-*", "IpAddress=127.0.0.1".
    /// </summary>
    public string[] ExclusionRules { get; set; } = [];
}

public sealed class MsSqlSettings : ProtocolSettings
{
    /// <summary>
    /// Literal substrings; a 18456 whose message contains any of these is ignored
    /// (non-bruteforce reasons). PLAN.md §4.3.
    /// </summary>
    public string[] IgnoreMessagePatterns { get; set; } =
    [
        "Failed to open the explicitly specified database",
    ];
}

public enum FtpServerKind
{
    IisFtp = 0,
    FileZilla = 1,
}

public sealed class FtpLogSource
{
    public string Name { get; set; } = string.Empty;

    public FtpServerKind Kind { get; set; } = FtpServerKind.IisFtp;

    /// <summary>IIS: log folder (e.g. C:\inetpub\logs\LogFiles\FTPSVC1). FileZilla: log file or folder.</summary>
    public string Path { get; set; } = string.Empty;
}

public sealed class FtpSettings : ProtocolSettings
{
    public TimeSpan PollInterval { get; set; } = Defaults.FtpPollInterval;

    public List<FtpLogSource> Sources { get; set; } = [];
}

/// <summary>Generic log source (PLAN.md §4.5): tail files, match a regex with named groups.</summary>
public sealed class CustomLogSource
{
    public string Name { get; set; } = string.Empty;

    public bool Enabled { get; set; } = true;

    /// <summary>File path or folder+glob, e.g. C:\logs\app\*.log or C:\logs\app\auth.log.</summary>
    public string PathGlob { get; set; } = string.Empty;

    /// <summary>Regex with named groups (?&lt;ipaddress&gt;...) and optional (?&lt;username&gt;...). A match = one failed login.</summary>
    public string Regex { get; set; } = string.Empty;
}
