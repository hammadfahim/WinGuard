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

    /// <summary>
    /// How long after its last ban ended an IP's offense count is remembered. Within this time a
    /// returning attacker continues at the next ban tier; after it they start again at the first.
    /// </summary>
    public TimeSpan OffenseMemory { get; set; } = Defaults.OffenseMemory;
    public TimeSpan HousekeepingInterval { get; set; } = Defaults.HousekeepingInterval;
    public bool ClearBansOnStartup { get; set; }
    public bool ProcessInternalIPs { get; set; }

    /// <summary>
    /// Monitoring mode: count failures, record would-be bans and log events, but never touch the
    /// Windows firewall. Lets an administrator trial WinGuard on a production server with zero risk
    /// of locking out a legitimate user. Bans recorded in report-only mode are enforced the moment
    /// the flag is switched off (the next reconcile pass re-blocks every active ban).
    /// </summary>
    public bool ReportOnly { get; set; }

    /// <summary>
    /// How many minutes of event-log history to replay when the service starts (covers failures
    /// logged while it was stopped, e.g. during a patch reboot). 0 disables the replay. The replay
    /// is capped in row count internally so a huge backlog cannot stall startup.
    /// </summary>
    public int EventBacklogReplayMinutes { get; set; } = 30;

    /// <summary>
    /// Ban whole IPv6 /N prefixes instead of single addresses, so an attacker rotating addresses
    /// inside their /64 cannot evade counting. 0 disables aggregation (per-address bans);
    /// 64 is the default (one customer site per prefix). Per address, one /64 holds enough
    /// addresses to stay under every threshold for ever, and to fill the firewall with bans.
    /// </summary>
    public int Ipv6AggregatePrefixLength { get; set; } = Defaults.Ipv6AggregatePrefixLength;

    /// <summary>Days of event history kept before housekeeping prunes it.</summary>
    public int EventRetentionDays { get; set; } = Defaults.EventRetentionDays;

    /// <summary>Days of ban history kept before housekeeping prunes it; top attackers count only what is kept.</summary>
    public int BanHistoryRetentionDays { get; set; } = Defaults.BanHistoryRetentionDays;
    public int MaxAddressesPerRule { get; set; } = Defaults.MaxAddressesPerRule;

    /// <summary>Out-of-band notifications (webhook / Telegram / e-mail / Windows Event Log).</summary>
    public NotificationSettings Notifications { get; set; } = new();

    /// <summary>
    /// A <c>.prom</c> file on a local drive that housekeeping keeps up to date, for the textfile
    /// collector of windows_exporter. Empty (the default) writes nothing; WinGuard opens no port.
    /// </summary>
    public string PrometheusTextfilePath { get; set; } = string.Empty;

    /// <summary>
    /// Empty = block all ports (1 firewall condition per IP; cheapest). Non-empty = block only these
    /// ports. Applies to every engine without a profile of its own; manual bans, blacklist bans and
    /// blacklisted ranges always block all ports.
    /// </summary>
    public string[] BlockedPorts { get; set; } = [];

    public RdpSettings Rdp { get; set; } = new();
    public MsSqlSettings MsSql { get; set; } = new();
    public FtpSettings Ftp { get; set; } = new();
    public List<CustomLogSource> CustomSources { get; set; } = [];

    /// <summary>Honeypot names, spraying, slow brute force and logon alerts; all off by default.</summary>
    public DetectionRuleSettings Rules { get; set; } = new();

    /// <summary>
    /// Local blocklist files (one IP or CIDR per line) blocked on all ports without waiting for a
    /// failed login. Empty = off. WinGuard never fetches a list: the administrator downloads it.
    /// </summary>
    public string[] BlocklistFiles { get; set; } = [];

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
        // Persisted/IPC JSON may carry explicit nulls; never let them crash startup or the engine.
        Rdp ??= new();
        MsSql ??= new();
        Ftp ??= new();
        Notifications ??= new();
        CustomSources ??= [];
        Ftp.Sources ??= [];
        MsSql.IgnoreMessagePatterns ??= [];
        Rdp.ExclusionRules ??= [];
        BlockedPorts ??= [];
        BanTiers ??= [];
        Notifications.Smtp ??= new();
        Rules ??= new();
        Rules.Normalize();
        Notifications.Syslog ??= new();
        Notifications.Syslog.Normalize();
        PrometheusTextfilePath = PrometheusTextfilePath?.Trim() ?? string.Empty;

        foreach (var source in CustomSources)
        {
            if (source?.Regex is not null)
            {
                source.Regex = CustomSourceRecipes.UpgradeRegex(source.Regex);
                source.PathGlob = CustomSourceRecipes.UpgradePathGlob(source.PathGlob ?? string.Empty, source.Regex);
            }
        }

        // Backlog replay: negative values make no sense; clamp to a sane upper bound (24 h).
        EventBacklogReplayMinutes = Math.Clamp(EventBacklogReplayMinutes < 0 ? 0 : EventBacklogReplayMinutes, 0, 1440);

        // IPv6 aggregation: 0 = off; otherwise a routable prefix length (>= /32 so a single
        // "site" is never mistaken for an aggregate, <= /64 as the loosest useful default cap).
        if (Ipv6AggregatePrefixLength != 0)
        {
            Ipv6AggregatePrefixLength = Math.Clamp(Ipv6AggregatePrefixLength, 32, 64);
        }

        // DateTime +/- TimeSpan overflows at either end of the calendar, which would abort a ban or
        // a whole housekeeping pass; cap durations.
        var maxSane = TimeSpan.FromDays(3650);
        if (MaxBanDuration <= TimeSpan.Zero)
        {
            MaxBanDuration = Defaults.MaxBanDuration;
        }

        if (MaxBanDuration > maxSane)
        {
            MaxBanDuration = maxSane;
        }

        FailedLoginThreshold = Math.Max(1, FailedLoginThreshold);
        EventRetentionDays = Math.Clamp(EventRetentionDays <= 0 ? Defaults.EventRetentionDays : EventRetentionDays, 1, 3650);
        BanHistoryRetentionDays = Math.Clamp(BanHistoryRetentionDays <= 0 ? Defaults.BanHistoryRetentionDays : BanHistoryRetentionDays, 1, 3650);
        MaxAddressesPerRule = Math.Clamp(MaxAddressesPerRule, 1, Defaults.MaxAddressesPerRule);

        CountWindow = CountWindow <= TimeSpan.Zero ? Defaults.CountWindow : Min(CountWindow, maxSane);
        Rdp.CountWindow = NormalizeWindow(Rdp.CountWindow, maxSane);
        MsSql.CountWindow = NormalizeWindow(MsSql.CountWindow, maxSane);
        Ftp.CountWindow = NormalizeWindow(Ftp.CountWindow, maxSane);

        // Housekeeping forgets failures older than ExpireTime, so an ExpireTime shorter than a count
        // window would silently shorten that window: attempts would vanish before they added up.
        ExpireTime = ExpireTime <= TimeSpan.Zero ? Defaults.ExpireTime : Min(ExpireTime, maxSane);
        ExpireTime = Max(ExpireTime, CountWindow);
        ExpireTime = Max(ExpireTime, Rdp.CountWindow ?? TimeSpan.Zero);
        ExpireTime = Max(ExpireTime, MsSql.CountWindow ?? TimeSpan.Zero);
        ExpireTime = Max(ExpireTime, Ftp.CountWindow ?? TimeSpan.Zero);
        ExpireTime = Max(ExpireTime, Rules.LongestFailureWindow());

        OffenseMemory = OffenseMemory <= TimeSpan.Zero ? Defaults.OffenseMemory : Min(OffenseMemory, maxSane);

        // Task.Delay throws for anything past about 49 days, which would end the polling loop.
        var maxInterval = TimeSpan.FromDays(1);
        HousekeepingInterval = HousekeepingInterval < TimeSpan.FromSeconds(1) ? Defaults.HousekeepingInterval : Min(HousekeepingInterval, maxInterval);
        Ftp.PollInterval = Ftp.PollInterval <= TimeSpan.Zero ? Defaults.FtpPollInterval : Min(Ftp.PollInterval, maxInterval);

        BanTiers = BanTiers is { Length: > 0 } ? BanTiers : (TimeSpan[])Defaults.BanTiers.Clone();

        // Drop non-positive tiers (bad IPC input); fall back to defaults when none survive.
        var positiveTiers = BanTiers.Where(t => t > TimeSpan.Zero).Select(t => t > maxSane ? maxSane : t).ToArray();
        BanTiers = positiveTiers.Length > 0 ? positiveTiers : (TimeSpan[])Defaults.BanTiers.Clone();

        // Port tokens reach the firewall LocalPorts property: keep only valid "port" or "start-end"
        // numeric forms so garbage can't break rule creation, and with it every block.
        BlockedPorts = NormalizePorts(BlockedPorts);
        Rdp.BlockedPorts = NormalizePorts(Rdp.BlockedPorts);
        MsSql.BlockedPorts = NormalizePorts(MsSql.BlockedPorts);
        Ftp.BlockedPorts = NormalizePorts(Ftp.BlockedPorts);
        Ftp.PassivePortRange = NormalizePorts([Ftp.PassivePortRange]).FirstOrDefault() ?? string.Empty;
        foreach (var source in CustomSources.Where(source => source is not null))
        {
            source.BlockedPorts = NormalizePorts(source.BlockedPorts);
        }

        BlocklistFiles = (BlocklistFiles ?? [])
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Select(path => path.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        // Notification rate limit: 0 would mean "drop everything", negative is nonsense.
        Notifications.RateLimitPerMinute = Math.Clamp(
            Notifications.RateLimitPerMinute <= 0 ? 20 : Notifications.RateLimitPerMinute, 1, 1000);
    }

    private static TimeSpan? NormalizeWindow(TimeSpan? window, TimeSpan max) =>
        window is { } value && value > TimeSpan.Zero ? Min(value, max) : null;

    private static string[] NormalizePorts(string?[]? ports) => (ports ?? [])
        .Where(p => !string.IsNullOrWhiteSpace(p))
        .Select(p => p!.Trim())
        .Where(p => PortSet.TryParseRange(p, out _, out _))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToArray();

    private static TimeSpan Min(TimeSpan a, TimeSpan b) => a < b ? a : b;

    private static TimeSpan Max(TimeSpan a, TimeSpan b) => a > b ? a : b;
}

/// <summary>Shared per-protocol knobs.</summary>
public abstract class ProtocolSettings
{
    public bool Enabled { get; set; } = true;

    /// <summary>Overrides the global FailedLoginThreshold when set.</summary>
    public int? Threshold { get; set; }

    /// <summary>Overrides the global CountWindow when set.</summary>
    public TimeSpan? CountWindow { get; set; }

    /// <summary>Ports a ban from this engine blocks. Empty = use the global BlockedPorts.</summary>
    public string[] BlockedPorts { get; set; } = [];
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

    /// <summary>
    /// The FTP server's passive data range, e.g. 50000-50100, blocked along with
    /// <see cref="ProtocolSettings.BlockedPorts"/> when that is set. Empty = none: every FTP server
    /// picks its own range, so WinGuard never assumes one.
    /// </summary>
    public string PassivePortRange { get; set; } = string.Empty;
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

    /// <summary>Ports a ban from this source blocks. Empty = use the global BlockedPorts.</summary>
    public string[] BlockedPorts { get; set; } = [];
}

/// <summary>
/// Out-of-band notification settings. All channels are opt-in and independent; WinGuard itself
/// never phones home — these settings only ever point at destinations the administrator entered.
/// Notifications fire for warning-level engine events (blocks, unblocks, blacklist bans) and are
/// rate-limited so a brute-force storm cannot flood the destination.
/// </summary>
public sealed class NotificationSettings
{
    /// <summary>Master switch for webhook/Telegram/SMTP delivery (the Windows Event Log has its own).</summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// HTTPS URL that receives a JSON POST per notification, e.g. a Slack/Discord/Mattermost
    /// incoming-webhook endpoint or an arbitrary automation receiver. Empty = disabled.
    /// </summary>
    public string WebhookUrl { get; set; } = string.Empty;

    /// <summary>Telegram bot token (from @BotFather). Empty = Telegram disabled.</summary>
    public string TelegramBotToken { get; set; } = string.Empty;

    /// <summary>Telegram chat id the notifications go to (from @userinfobot or the bot API).</summary>
    public string TelegramChatId { get; set; } = string.Empty;

    /// <summary>SMTP relay settings. A null/empty host disables the e-mail channel.</summary>
    public SmtpSettings? Smtp { get; set; } = new();

    /// <summary>Maximum notifications delivered per minute across all channels (burst protection).</summary>
    public int RateLimitPerMinute { get; set; } = 20;

    /// <summary>Also write WinGuard events to the Windows Application event log (source "WinGuard")
    /// so SIEM/Windows-Event-Forwarding setups can consume them without polling WinGuard's pipe.</summary>
    public bool WriteToWindowsEventLog { get; set; } = true;

    /// <summary>Syslog output; has its own switch and is not rate limited, like the Windows Event Log.</summary>
    public SyslogSettings Syslog { get; set; } = new();
}

/// <summary>Minimal SMTP relay configuration for notifications.</summary>
public sealed class SmtpSettings
{
    public string Host { get; set; } = string.Empty;

    public int Port { get; set; } = 25;

    public bool EnableSsl { get; set; } = true;

    /// <summary>Username; empty = anonymous relay (typical for an internal smarthost).</summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>Password; encrypted in the store like the webhook URL and Telegram token (see <see cref="SettingsSecrets"/>).</summary>
    public string Password { get; set; } = string.Empty;

    /// <value>Display/sender address, e.g. winguard@example.com.</value>
    public string From { get; set; } = string.Empty;

    /// <value>Recipient address for the notifications.</value>
    public string To { get; set; } = string.Empty;
}
