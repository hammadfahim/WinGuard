namespace WinGuard.Core.Config;

/// <summary>
/// Detection rules on top of the per-protocol failure threshold. Every rule is off by default and
/// read live, so switching one on or off needs no restart. They run after the whitelist, the
/// internal-IP check and the exclusion rules, and their bans take the normal tier path.
/// </summary>
public sealed class DetectionRuleSettings
{
    // ExpireTime follows the longest enabled window, and with it the failed_logins table: a long
    // window keeps every attacker's rows that long.
    private static readonly TimeSpan MaxWindow = TimeSpan.FromDays(30);

    private static readonly TimeSpan DefaultSprayWindow = TimeSpan.FromHours(1);
    private static readonly TimeSpan DefaultLongWindow = TimeSpan.FromHours(24);

    /// <summary>
    /// Account names nobody uses here, such as <c>admin</c>, <c>test</c> or <c>guest</c>. One failed
    /// login with such a name bans the IP at once, on the first attempt: never list an account that
    /// exists or that anyone might use, because a single mistyped password would ban that person and
    /// everyone behind the same address. Exact and case-insensitive, no wildcards; a <c>DOMAIN\</c>
    /// prefix or <c>@domain</c> suffix is removed before comparing.
    /// </summary>
    public string[] HoneypotUsernames { get; set; } = [];

    /// <summary>
    /// Password spraying: this many distinct user names from one IP within
    /// <see cref="SprayWindow"/>, across all engines, ban it. Failures without a user name do not
    /// count. 0 turns the rule off; otherwise at least 2.
    /// </summary>
    public int SprayMaxUsernames { get; set; }

    /// <summary>The window of <see cref="SprayMaxUsernames"/>.</summary>
    public TimeSpan SprayWindow { get; set; } = DefaultSprayWindow;

    /// <summary>
    /// Slow brute force: this many failures from one IP within
    /// <see cref="SlowBruteForceWindow"/>, across all engines, ban it, so pacing below the normal
    /// threshold does not help. 0 turns the rule off; otherwise at least 2.
    /// </summary>
    public int SlowBruteForceThreshold { get; set; }

    /// <summary>The window of <see cref="SlowBruteForceThreshold"/>, at most 30 days.</summary>
    public TimeSpan SlowBruteForceWindow { get; set; } = DefaultLongWindow;

    /// <summary>
    /// Watch successful network and RDP logons (Security 4624, which needs Audit Logon success) and
    /// raise a POSSIBLE COMPROMISE warning when an IP with an active ban, or with at least
    /// <see cref="CompromiseMinFailures"/> failures in <see cref="CompromiseWindow"/>, logs on. Off
    /// by default: a busy server logs 4624 constantly, and each event has to be read.
    /// </summary>
    public bool CompromiseAlerts { get; set; }

    /// <summary>Failures that make a following logon suspicious, at least 1.</summary>
    public int CompromiseMinFailures { get; set; } = 3;

    /// <summary>How far back failures count for <see cref="CompromiseAlerts"/>, at most 30 days.</summary>
    public TimeSpan CompromiseWindow { get; set; } = DefaultLongWindow;

    /// <summary>
    /// Risky, off (0) by default. After an RDP logon from an IP with no failures on record, treat that
    /// IP as whitelisted for this many hours (1 to 24), so an administrator cannot be locked out by
    /// their own typing. Anyone holding a valid RDP password can use it, and everything sharing that
    /// address is ignored meanwhile. Never applies after failures, a ban or a honeypot name, and is
    /// kept in memory only, so it ends with the service.
    /// </summary>
    public int TrustAdminIpHours { get; set; }

    /// <summary>Whether anything needs the successful logons at all.</summary>
    public bool ObservesLogons() => CompromiseAlerts || TrustAdminIpHours > 0;

    /// <summary>The longest time an enabled rule looks back in failed_logins; zero when none does.</summary>
    public TimeSpan LongestFailureWindow()
    {
        var longest = TimeSpan.Zero;
        if (SprayMaxUsernames > 0 && SprayWindow > longest)
        {
            longest = SprayWindow;
        }

        if (SlowBruteForceThreshold > 0 && SlowBruteForceWindow > longest)
        {
            longest = SlowBruteForceWindow;
        }

        if (CompromiseAlerts && CompromiseWindow > longest)
        {
            longest = CompromiseWindow;
        }

        return longest;
    }

    /// <summary>The <see cref="HoneypotUsernames"/> entry this user name matches, or null.</summary>
    public string? MatchHoneypot(string? userName)
    {
        if (HoneypotUsernames.Length == 0 || CanonicalUserName(userName) is not { } canonical)
        {
            return null;
        }

        foreach (var entry in HoneypotUsernames)
        {
            if (string.Equals(entry, canonical, StringComparison.OrdinalIgnoreCase))
            {
                return entry;
            }
        }

        return null;
    }

    /// <summary>
    /// The account part of a logon name: <c>DOMAIN\bob</c>, <c>bob@example.com</c> and <c>bob</c> are
    /// the same user. Null when nothing is left.
    /// </summary>
    public static string? CanonicalUserName(string? userName)
    {
        if (string.IsNullOrWhiteSpace(userName))
        {
            return null;
        }

        var name = userName.Trim();
        name = name[(name.LastIndexOf('\\') + 1)..];
        var at = name.LastIndexOf('@');
        if (at >= 0)
        {
            name = name[..at];
        }

        name = name.Trim();
        return name.Length == 0 ? null : name;
    }

    /// <summary>Sanity clamps, applied by <see cref="WinGuardSettings.Normalize"/>.</summary>
    public void Normalize()
    {
        HoneypotUsernames = (HoneypotUsernames ?? [])
            .Select(CanonicalUserName)
            .OfType<string>()
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        // A limit of 1 would ban on any failure at all.
        SprayMaxUsernames = SprayMaxUsernames <= 0 ? 0 : Math.Max(2, SprayMaxUsernames);
        SlowBruteForceThreshold = SlowBruteForceThreshold <= 0 ? 0 : Math.Max(2, SlowBruteForceThreshold);
        CompromiseMinFailures = Math.Max(1, CompromiseMinFailures);
        TrustAdminIpHours = TrustAdminIpHours <= 0 ? 0 : Math.Clamp(TrustAdminIpHours, 1, 24);

        SprayWindow = NormalizeWindow(SprayWindow, DefaultSprayWindow);
        SlowBruteForceWindow = NormalizeWindow(SlowBruteForceWindow, DefaultLongWindow);
        CompromiseWindow = NormalizeWindow(CompromiseWindow, DefaultLongWindow);
    }

    private static TimeSpan NormalizeWindow(TimeSpan window, TimeSpan fallback)
    {
        if (window <= TimeSpan.Zero)
        {
            return fallback;
        }

        return window > MaxWindow ? MaxWindow : window;
    }
}
