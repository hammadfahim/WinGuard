namespace WinGuard.Gui.Services;

/// <summary>Pure axis arithmetic for the charts.</summary>
public static class ChartScale
{
    /// <summary>
    /// The smallest "nice" axis maximum (1, 2, 2.5, 5 or 10 times a power of ten) at or above
    /// <paramref name="value"/>. Never less than <paramref name="floor"/>, so an all-zero or very quiet
    /// chart still has a sensible axis instead of a meaningless 0-1 scale.
    /// </summary>
    public static double NiceMax(double value, double floor = 4)
    {
        var target = Math.Max(value, floor);
        var magnitude = Math.Pow(10, Math.Floor(Math.Log10(target)));
        foreach (var step in new[] { 1, 2, 2.5, 4, 5, 8, 10 })
        {
            if (step * magnitude >= target)
            {
                return step * magnitude;
            }
        }

        return 10 * magnitude;
    }

    /// <summary>Evenly spaced gridline values from 0 to <paramref name="max"/> inclusive.</summary>
    public static IReadOnlyList<double> Ticks(double max, int intervals = 4)
    {
        var ticks = new double[intervals + 1];
        for (var i = 0; i <= intervals; i++)
        {
            ticks[i] = max * i / intervals;
        }

        return ticks;
    }

    /// <summary>Compact axis text: 950, 1.2k, 3M.</summary>
    public static string Compact(double value) => value switch
    {
        >= 1_000_000 => (value / 1_000_000).ToString("0.#", System.Globalization.CultureInfo.CurrentCulture) + "M",
        >= 1_000 => (value / 1_000).ToString("0.#", System.Globalization.CultureInfo.CurrentCulture) + "k",
        _ => value.ToString("0.#", System.Globalization.CultureInfo.CurrentCulture),
    };

    /// <summary>How many data points to skip between axis labels so about <paramref name="wanted"/> fit.</summary>
    public static int LabelStride(int points, int wanted) =>
        wanted <= 0 ? points : Math.Max(1, (int)Math.Ceiling(points / (double)wanted));
}
