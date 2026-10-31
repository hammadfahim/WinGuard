using System.Globalization;

namespace WinGuard.Gui.Services;

/// <summary>Pure time formatting shared by every view.</summary>
public static class TimeText
{
    /// <summary>
    /// Converts a service timestamp to local time. A value with no kind is UTC by contract (the store
    /// writes UTC); <see cref="DateTime.ToLocalTime"/> alone would treat it as already local and show it
    /// off by the machine's offset.
    /// </summary>
    public static DateTime ToLocal(DateTime utc) => utc.Kind switch
    {
        DateTimeKind.Utc => utc.ToLocalTime(),
        DateTimeKind.Local => utc,
        _ => DateTime.SpecifyKind(utc, DateTimeKind.Utc).ToLocalTime(),
    };

    /// <summary>Forces a service timestamp to UTC kind so arithmetic against UtcNow is valid.</summary>
    public static DateTime AsUtc(DateTime value) => value.Kind switch
    {
        DateTimeKind.Utc => value,
        DateTimeKind.Local => value.ToUniversalTime(),
        _ => DateTime.SpecifyKind(value, DateTimeKind.Utc),
    };

    /// <summary>Local date and time in the machine's short format.</summary>
    public static string Full(DateTime utc) =>
        utc == default ? string.Empty : ToLocal(utc).ToString("g", CultureInfo.CurrentCulture);

    /// <summary>Sortable local timestamp with seconds, used by feeds and exports.</summary>
    public static string Stamp(DateTime utc) =>
        utc == default ? string.Empty : ToLocal(utc).ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

    /// <summary>"just now", "4m ago", "2h ago", "3d ago".</summary>
    public static string Ago(DateTime utc, DateTime nowUtc)
    {
        if (utc == default)
        {
            return string.Empty;
        }

        var age = nowUtc - AsUtc(utc);
        return age switch
        {
            { TotalSeconds: < 45 } => "just now",
            { TotalMinutes: < 60 } => $"{Math.Max(1, (int)Math.Round(age.TotalMinutes))}m ago",
            { TotalHours: < 24 } => $"{(int)age.TotalHours}h ago",
            _ => $"{(int)age.TotalDays}d ago",
        };
    }

    /// <summary>
    /// A live countdown that only shows the precision that matters: "12d 4h", "3h 12m", "4m 09s", "38s",
    /// and "expiring" once the time is up and the service has yet to lift the ban.
    /// </summary>
    public static string Countdown(TimeSpan remaining)
    {
        if (remaining <= TimeSpan.Zero)
        {
            return "expiring";
        }

        if (remaining.TotalDays >= 1)
        {
            return $"{(int)remaining.TotalDays}d {remaining.Hours}h";
        }

        if (remaining.TotalHours >= 1)
        {
            return $"{(int)remaining.TotalHours}h {remaining.Minutes}m";
        }

        return remaining.TotalMinutes >= 1
            ? $"{(int)remaining.TotalMinutes}m {remaining.Seconds:00}s"
            : $"{Math.Max(1, (int)Math.Ceiling(remaining.TotalSeconds))}s";
    }
}
