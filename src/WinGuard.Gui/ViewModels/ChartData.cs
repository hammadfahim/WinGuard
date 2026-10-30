using WinGuard.Gui.Services;

namespace WinGuard.Gui.ViewModels;

/// <summary>
/// One named run of values. <see cref="Slot"/> ties the series to a fixed chart colour, so a colour
/// always follows its engine and filtering never repaints the survivors.
/// </summary>
public sealed record ChartSeries(string Name, int Slot, IReadOnlyList<double> Values);

/// <summary>
/// Immutable input for <see cref="Controls.ActivityChart"/>: stacked bars plus an optional line, all
/// on one axis. Two measures of very different size belong in two charts, not on two scales.
/// </summary>
public sealed class ChartData
{
    /// <summary>Creates the chart input.</summary>
    /// <param name="heads">Tooltip heading per point.</param>
    /// <param name="axisLabels">Short x-axis text per point.</param>
    /// <param name="bars">Stacked bar series, bottom first.</param>
    /// <param name="line">Optional line drawn over the bars on the same axis.</param>
    public ChartData(IReadOnlyList<string> heads, IReadOnlyList<string> axisLabels, IReadOnlyList<ChartSeries> bars, ChartSeries? line = null)
    {
        Heads = heads;
        AxisLabels = axisLabels;
        Bars = bars;
        Line = line;

        var peak = 0d;
        for (var i = 0; i < Count; i++)
        {
            peak = Math.Max(peak, Math.Max(StackAt(i), line is null ? 0 : line.Values[i]));
        }

        Peak = peak;
        Max = ChartScale.NiceMax(peak);
        Ticks = ChartScale.Ticks(Max);
    }

    /// <summary>A chart with nothing to draw.</summary>
    public static ChartData Empty { get; } = new([], [], []);

    /// <summary>Tooltip heading per point.</summary>
    public IReadOnlyList<string> Heads { get; }

    /// <summary>Short x-axis text per point.</summary>
    public IReadOnlyList<string> AxisLabels { get; }

    /// <summary>Stacked bar series, bottom first.</summary>
    public IReadOnlyList<ChartSeries> Bars { get; }

    /// <summary>Optional line on the same axis.</summary>
    public ChartSeries? Line { get; }

    /// <summary>Largest value drawn.</summary>
    public double Peak { get; }

    /// <summary>Axis maximum.</summary>
    public double Max { get; }

    /// <summary>Gridline values.</summary>
    public IReadOnlyList<double> Ticks { get; }

    /// <summary>Number of points.</summary>
    public int Count => Heads.Count;

    /// <summary>Height of the bar stack at a point.</summary>
    public double StackAt(int index)
    {
        var total = 0d;
        foreach (var series in Bars)
        {
            total += series.Values[index];
        }

        return total;
    }
}
