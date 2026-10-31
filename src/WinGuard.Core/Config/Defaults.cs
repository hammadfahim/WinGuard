namespace WinGuard.Core.Config;

/// <summary>Default values per PLAN.md §5/§7/§10. The defaults ARE the required presets (24h / 7d / 30d tiers).</summary>
public static class Defaults
{
    public const int FailedLoginThreshold = 5;
    public static readonly TimeSpan CountWindow = TimeSpan.FromMinutes(10);
    public static readonly TimeSpan ExpireTime = TimeSpan.FromDays(1);
    public static readonly TimeSpan[] BanTiers =
    [
        TimeSpan.FromHours(24),
        TimeSpan.FromDays(7),
        TimeSpan.FromDays(30),
    ];
    public static readonly TimeSpan MaxBanDuration = TimeSpan.FromDays(365);
    public static readonly TimeSpan HousekeepingInterval = TimeSpan.FromSeconds(15);
    public static readonly TimeSpan FtpPollInterval = TimeSpan.FromSeconds(3);

    /// <summary>
    /// How long a repeat offender stays remembered after a ban ends. Well past the longest default
    /// tier: an attacker returning a few weeks after a ban must not be back at 24 hours.
    /// </summary>
    public static readonly TimeSpan OffenseMemory = TimeSpan.FromDays(90);

    public const int EventRetentionDays = 30;
    public const int BanHistoryRetentionDays = 365;

    /// <summary>Windows Firewall practical limit of addresses per rule; batch into WinGuard_Block_0001, ...</summary>
    public const int MaxAddressesPerRule = 1000;

    /// <summary>Most firewall entries taken from blocklist files together: 50 rules of the size above.</summary>
    public const int MaxBlocklistEntries = 50_000;

    public const string RuleNamePrefix = "WinGuard_Block_";
    public const string ServiceName = "WinGuardService";
    public const string ServiceDisplayName = "WinGuard Service";
    public const string ServiceDescription = "WinGuard - blocks brute-force attackers in the firewall";
    public const string DataFolderName = "WinGuard";

    public static string DataFolder =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), DataFolderName);

    public static string DatabasePath => Path.Combine(DataFolder, "winguard.db");

    public static string LogFolder => Path.Combine(DataFolder, "Logs");

    /// <summary>The break-glass drop file; see <see cref="Engine.DisarmFile"/>.</summary>
    public static string DisarmFilePath => Path.Combine(DataFolder, Engine.DisarmFile.FileName);
}
