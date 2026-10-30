using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace WinGuard.Gui.Services;

/// <summary>
/// Friendly durations: administrators type "10m", "1h 30m", "2 days" or "90 sec" instead of raw
/// TimeSpans. The old "d.hh:mm:ss" form is still understood, so nothing that worked stops working.
/// </summary>
public static partial class DurationText
{
    /// <summary>Parses friendly or raw TimeSpan text. A bare number means minutes.</summary>
    public static bool TryParse(string? text, out TimeSpan value)
    {
        value = default;
        var input = text?.Trim();
        if (string.IsNullOrEmpty(input))
        {
            return false;
        }

        if (double.TryParse(input, NumberStyles.Float, CultureInfo.InvariantCulture, out var bare))
        {
            return TryBuild(bare * TimeSpan.TicksPerMinute, out value);
        }

        var total = 0d;
        var position = 0;
        foreach (Match match in PartPattern().Matches(input))
        {
            // Anything between two recognised parts other than spacing or "and" is not a duration.
            var between = input[position..match.Index];
            if (between.Trim(' ', ',').Length > 0 && !between.Trim().Equals("and", StringComparison.OrdinalIgnoreCase))
            {
                position = -1;
                break;
            }

            var amount = double.Parse(match.Groups["n"].Value, CultureInfo.InvariantCulture);
            total += amount * TicksPerUnit(match.Groups["u"].Value);
            position = match.Index + match.Length;
        }

        if (position > 0 && input[position..].Trim().Length == 0)
        {
            return TryBuild(total, out value);
        }

        // TimeSpan.Parse reads "24:00:00" as 24 DAYS: a first field above 23 silently means days. The
        // README writes tiers exactly that way, so hours are read here, as anyone would read them.
        var clock = ClockPattern().Match(input);
        if (clock.Success)
        {
            var ticks = (long.Parse(clock.Groups["h"].Value, CultureInfo.InvariantCulture) * TimeSpan.TicksPerHour)
                + (long.Parse(clock.Groups["m"].Value, CultureInfo.InvariantCulture) * TimeSpan.TicksPerMinute)
                + (long.Parse(clock.Groups["s"].Value, CultureInfo.InvariantCulture) * TimeSpan.TicksPerSecond);
            return TryBuild(ticks, out value);
        }

        // "1.00:00:00" from older settings, or pasted from the README.
        return input.Contains(':') && TimeSpan.TryParse(input, CultureInfo.InvariantCulture, out value);
    }

    /// <summary>Compact editable text: "10m", "1h 30m", "7d". The result parses back to the same value.</summary>
    public static string Format(TimeSpan value)
    {
        if (value <= TimeSpan.Zero)
        {
            return "0s";
        }

        var builder = new StringBuilder();
        Append(builder, value.Days, "d");
        Append(builder, value.Hours, "h");
        Append(builder, value.Minutes, "m");
        Append(builder, value.Seconds, "s");
        return builder.Length == 0 ? "1s" : builder.ToString();
    }

    /// <summary>Spelled-out reading of a duration, echoed under the field: "1 hour 30 minutes".</summary>
    public static string Describe(TimeSpan value)
    {
        var parts = new List<string>();
        void Add(int amount, string unit)
        {
            if (amount > 0)
            {
                parts.Add(amount == 1 ? $"1 {unit}" : $"{amount} {unit}s");
            }
        }

        Add(value.Days, "day");
        Add(value.Hours, "hour");
        Add(value.Minutes, "minute");
        Add(value.Seconds, "second");
        return parts.Count == 0 ? "0 seconds" : string.Join(" ", parts);
    }

    private static void Append(StringBuilder builder, int amount, string unit)
    {
        if (amount > 0)
        {
            if (builder.Length > 0)
            {
                builder.Append(' ');
            }

            builder.Append(amount.ToString(CultureInfo.InvariantCulture)).Append(unit);
        }
    }

    private static bool TryBuild(double ticks, out TimeSpan value)
    {
        value = default;
        if (double.IsNaN(ticks) || ticks < 0 || ticks >= TimeSpan.MaxValue.Ticks)
        {
            return false;
        }

        value = new TimeSpan((long)ticks);
        return true;
    }

    private static long TicksPerUnit(string unit) => char.ToLowerInvariant(unit[0]) switch
    {
        's' => TimeSpan.TicksPerSecond,
        'm' => TimeSpan.TicksPerMinute,
        'h' => TimeSpan.TicksPerHour,
        'd' => TimeSpan.TicksPerDay,
        _ => TimeSpan.TicksPerDay * 7,
    };

    [GeneratedRegex(@"(?<n>\d+(?:\.\d+)?)\s*(?<u>days?|d|hours?|hrs?|h|minutes?|mins?|m|seconds?|secs?|s|weeks?|w)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PartPattern();

    [GeneratedRegex(@"^(?<h>\d{1,4}):(?<m>[0-5]\d):(?<s>[0-5]\d)$", RegexOptions.CultureInvariant)]
    private static partial Regex ClockPattern();
}
