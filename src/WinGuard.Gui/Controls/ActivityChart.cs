using System.Globalization;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using WinGuard.Gui.Services;
using WinGuard.Gui.ViewModels;

namespace WinGuard.Gui.Controls;

/// <summary>
/// Stacked bars with an optional line, drawn directly in <see cref="OnRender"/>: a single visual
/// however many days are shown, which stays cheap over RDP. Hovering (or Left/Right while focused)
/// highlights a point and draws its tooltip inside the plot, so no popup window is involved.
/// All colours arrive through brush properties bound to theme tokens.
/// </summary>
public sealed class ActivityChart : FrameworkElement
{
    /// <summary>The values to draw.</summary>
    public static readonly DependencyProperty DataProperty = Register(nameof(Data), typeof(ChartData), ChartData.Empty);

    /// <summary>Colour slot 0.</summary>
    public static readonly DependencyProperty Series0BrushProperty = Register(nameof(Series0Brush), typeof(Brush));

    /// <summary>Colour slot 1.</summary>
    public static readonly DependencyProperty Series1BrushProperty = Register(nameof(Series1Brush), typeof(Brush));

    /// <summary>Colour slot 2.</summary>
    public static readonly DependencyProperty Series2BrushProperty = Register(nameof(Series2Brush), typeof(Brush));

    /// <summary>Colour slot 3.</summary>
    public static readonly DependencyProperty Series3BrushProperty = Register(nameof(Series3Brush), typeof(Brush));

    /// <summary>Colour of the line.</summary>
    public static readonly DependencyProperty LineBrushProperty = Register(nameof(LineBrush), typeof(Brush));

    /// <summary>Gridline colour.</summary>
    public static readonly DependencyProperty GridBrushProperty = Register(nameof(GridBrush), typeof(Brush));

    /// <summary>Axis text colour.</summary>
    public static readonly DependencyProperty AxisBrushProperty = Register(nameof(AxisBrush), typeof(Brush));

    /// <summary>Background of the surface behind the plot (the gap between stacked segments).</summary>
    public static readonly DependencyProperty SurfaceBrushProperty = Register(nameof(SurfaceBrush), typeof(Brush));

    /// <summary>Hover band colour.</summary>
    public static readonly DependencyProperty HoverBrushProperty = Register(nameof(HoverBrush), typeof(Brush));

    /// <summary>Tooltip background.</summary>
    public static readonly DependencyProperty TipBackgroundProperty = Register(nameof(TipBackground), typeof(Brush));

    /// <summary>Tooltip border.</summary>
    public static readonly DependencyProperty TipBorderProperty = Register(nameof(TipBorder), typeof(Brush));

    /// <summary>Tooltip text colour.</summary>
    public static readonly DependencyProperty TipTextProperty = Register(nameof(TipText), typeof(Brush));

    private const double AxisFontSize = 11;
    private const double TipFontSize = 12;
    private const double BottomGutter = 20;
    private const double TopGutter = 6;

    private static readonly Typeface Regular = new(new FontFamily("Segoe UI"), FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);
    private static readonly Typeface Strong = new(new FontFamily("Segoe UI"), FontStyles.Normal, FontWeights.SemiBold, FontStretches.Normal);

    private int _hover = -1;
    private Rect _plot;

    /// <summary>Creates the chart.</summary>
    public ActivityChart()
    {
        Focusable = true;
        FocusVisualStyle = null;
        ClipToBounds = true;
    }

    /// <summary>Gets or sets <see cref="DataProperty"/>.</summary>
    public ChartData Data
    {
        get => (ChartData)GetValue(DataProperty);
        set => SetValue(DataProperty, value);
    }

    /// <summary>Gets or sets <see cref="Series0BrushProperty"/>.</summary>
    public Brush? Series0Brush
    {
        get => (Brush?)GetValue(Series0BrushProperty);
        set => SetValue(Series0BrushProperty, value);
    }

    /// <summary>Gets or sets <see cref="Series1BrushProperty"/>.</summary>
    public Brush? Series1Brush
    {
        get => (Brush?)GetValue(Series1BrushProperty);
        set => SetValue(Series1BrushProperty, value);
    }

    /// <summary>Gets or sets <see cref="Series2BrushProperty"/>.</summary>
    public Brush? Series2Brush
    {
        get => (Brush?)GetValue(Series2BrushProperty);
        set => SetValue(Series2BrushProperty, value);
    }

    /// <summary>Gets or sets <see cref="Series3BrushProperty"/>.</summary>
    public Brush? Series3Brush
    {
        get => (Brush?)GetValue(Series3BrushProperty);
        set => SetValue(Series3BrushProperty, value);
    }

    /// <summary>Gets or sets <see cref="LineBrushProperty"/>.</summary>
    public Brush? LineBrush
    {
        get => (Brush?)GetValue(LineBrushProperty);
        set => SetValue(LineBrushProperty, value);
    }

    /// <summary>Gets or sets <see cref="GridBrushProperty"/>.</summary>
    public Brush? GridBrush
    {
        get => (Brush?)GetValue(GridBrushProperty);
        set => SetValue(GridBrushProperty, value);
    }

    /// <summary>Gets or sets <see cref="AxisBrushProperty"/>.</summary>
    public Brush? AxisBrush
    {
        get => (Brush?)GetValue(AxisBrushProperty);
        set => SetValue(AxisBrushProperty, value);
    }

    /// <summary>Gets or sets <see cref="SurfaceBrushProperty"/>.</summary>
    public Brush? SurfaceBrush
    {
        get => (Brush?)GetValue(SurfaceBrushProperty);
        set => SetValue(SurfaceBrushProperty, value);
    }

    /// <summary>Gets or sets <see cref="HoverBrushProperty"/>.</summary>
    public Brush? HoverBrush
    {
        get => (Brush?)GetValue(HoverBrushProperty);
        set => SetValue(HoverBrushProperty, value);
    }

    /// <summary>Gets or sets <see cref="TipBackgroundProperty"/>.</summary>
    public Brush? TipBackground
    {
        get => (Brush?)GetValue(TipBackgroundProperty);
        set => SetValue(TipBackgroundProperty, value);
    }

    /// <summary>Gets or sets <see cref="TipBorderProperty"/>.</summary>
    public Brush? TipBorder
    {
        get => (Brush?)GetValue(TipBorderProperty);
        set => SetValue(TipBorderProperty, value);
    }

    /// <summary>Gets or sets <see cref="TipTextProperty"/>.</summary>
    public Brush? TipText
    {
        get => (Brush?)GetValue(TipTextProperty);
        set => SetValue(TipTextProperty, value);
    }

    /// <summary>The highlighted point, or -1. Public so a render can show the tooltip.</summary>
    public int HoverIndex
    {
        get => _hover;
        set
        {
            var clamped = Data.Count == 0 ? -1 : Math.Clamp(value, -1, Data.Count - 1);
            if (clamped != _hover)
            {
                _hover = clamped;
                InvalidateVisual();
            }
        }
    }

    /// <inheritdoc />
    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        var count = Data.Count;
        if (count == 0 || _plot.Width <= 0)
        {
            return;
        }

        var x = e.GetPosition(this).X;
        HoverIndex = x < _plot.Left || x > _plot.Right
            ? -1
            : Math.Clamp((int)((x - _plot.Left) / (_plot.Width / count)), 0, count - 1);
    }

    /// <inheritdoc />
    protected override void OnMouseLeave(MouseEventArgs e)
    {
        base.OnMouseLeave(e);
        if (!IsKeyboardFocused)
        {
            HoverIndex = -1;
        }
    }

    /// <inheritdoc />
    protected override void OnLostKeyboardFocus(KeyboardFocusChangedEventArgs e)
    {
        base.OnLostKeyboardFocus(e);
        HoverIndex = -1;
    }

    /// <inheritdoc />
    protected override void OnMouseLeftButtonDown(MouseButtonEventArgs e)
    {
        base.OnMouseLeftButtonDown(e);
        Focus();
    }

    /// <inheritdoc />
    protected override void OnKeyDown(KeyEventArgs e)
    {
        base.OnKeyDown(e);
        var last = Data.Count - 1;
        switch (e.Key)
        {
            case Key.Left:
                HoverIndex = _hover <= 0 ? last : _hover - 1;
                e.Handled = true;
                break;
            case Key.Right:
                HoverIndex = _hover >= last ? 0 : _hover + 1;
                e.Handled = true;
                break;
            case Key.Home:
                HoverIndex = 0;
                e.Handled = true;
                break;
            case Key.End:
                HoverIndex = last;
                e.Handled = true;
                break;
            case Key.Escape:
                HoverIndex = -1;
                break;
        }
    }

    /// <inheritdoc />
    protected override void OnRender(DrawingContext dc)
    {
        var size = RenderSize;

        // Transparent, but hit-testable: gaps between bars must still report the pointer.
        dc.DrawRectangle(Brushes.Transparent, null, new Rect(size));

        var data = Data;
        if (data.Count == 0 || size.Width < 40 || size.Height < 40)
        {
            return;
        }

        var dip = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        var axisWidth = data.Ticks.Max(tick => Text(ChartScale.Compact(tick), AxisFontSize, Regular, AxisBrush, dip).Width) + 8;
        _plot = new Rect(axisWidth, TopGutter, Math.Max(1, size.Width - axisWidth), Math.Max(1, size.Height - BottomGutter - TopGutter));

        DrawGrid(dc, data, dip);

        var band = _plot.Width / data.Count;
        if (_hover >= 0 && _hover < data.Count)
        {
            dc.DrawRectangle(HoverBrush, null, new Rect(_plot.Left + (band * _hover), _plot.Top, band, _plot.Height));
        }

        DrawBars(dc, data, band);
        DrawAxisLabels(dc, data, band, dip);
        if (data.Line is { } line)
        {
            DrawLine(dc, line, data, band);
        }

        if (_hover >= 0 && _hover < data.Count)
        {
            DrawTip(dc, data, band, dip);
        }
    }

    private static DependencyProperty Register(string name, Type type, object? fallback = null) =>
        DependencyProperty.Register(
            name,
            type,
            typeof(ActivityChart),
            new FrameworkPropertyMetadata(fallback, FrameworkPropertyMetadataOptions.AffectsRender, OnAppearanceChanged));

    private static void OnAppearanceChanged(DependencyObject sender, DependencyPropertyChangedEventArgs e)
    {
        if (e.Property == DataProperty)
        {
            var chart = (ActivityChart)sender;
            if (chart._hover >= chart.Data.Count)
            {
                chart._hover = -1;
            }
        }
    }

    private static FormattedText Text(string text, double size, Typeface face, Brush? brush, double dip) =>
        new(text, CultureInfo.CurrentCulture, FlowDirection.LeftToRight, face, size, brush ?? Brushes.Gray, dip);

    private double Y(double value, double max) => _plot.Bottom - (_plot.Height * value / max);

    private Brush? SlotBrush(int slot) => slot switch
    {
        0 => Series0Brush,
        1 => Series1Brush,
        2 => Series2Brush,
        _ => Series3Brush,
    };

    private void DrawGrid(DrawingContext dc, ChartData data, double dip)
    {
        var pen = new Pen(GridBrush, 1);
        pen.Freeze();
        foreach (var tick in data.Ticks)
        {
            var y = Math.Round(Y(tick, data.Max)) + 0.5;
            dc.DrawLine(pen, new Point(_plot.Left, y), new Point(_plot.Right, y));

            var label = Text(ChartScale.Compact(tick), AxisFontSize, Regular, AxisBrush, dip);
            dc.DrawText(label, new Point(_plot.Left - label.Width - 8, y - (label.Height / 2)));
        }
    }

    private void DrawBars(DrawingContext dc, ChartData data, double band)
    {
        // Thin marks: the bar never fills its band, and leaves at least a 2 px gap to its neighbour.
        var width = Math.Max(2, Math.Min(band - 2, Math.Max(band * 0.62, 3)));
        width = Math.Min(width, 26);

        for (var i = 0; i < data.Count; i++)
        {
            var left = Math.Round(_plot.Left + (band * i) + ((band - width) / 2));
            var baseline = _plot.Bottom;
            var stackTop = -1;
            for (var s = data.Bars.Count - 1; s >= 0; s--)
            {
                if (data.Bars[s].Values[i] > 0)
                {
                    stackTop = s;
                    break;
                }
            }

            for (var s = 0; s <= stackTop; s++)
            {
                var series = data.Bars[s];
                var value = series.Values[i];
                if (value <= 0)
                {
                    continue;
                }

                var height = Math.Max(1.5, _plot.Height * value / data.Max);
                var top = baseline - height;

                // A 2 px surface gap keeps stacked neighbours apart without relying on hue alone.
                var gap = s < stackTop && height > 3 ? 2 : 0;
                var rect = new Rect(left, top + gap, width, Math.Max(1, height - gap));
                var radius = s == stackTop ? Math.Min(3, width / 2) : 0;
                dc.DrawRoundedRectangle(SlotBrush(series.Slot), null, rect, radius, radius);
                baseline = top;
            }
        }
    }

    private void DrawAxisLabels(DrawingContext dc, ChartData data, double band, double dip)
    {
        var sample = data.AxisLabels.Count > 0 ? data.AxisLabels.Max(label => label.Length) : 1;
        var wanted = (int)(_plot.Width / ((sample * 6.5) + 14));
        var stride = ChartScale.LabelStride(data.Count, wanted);

        // Anchor on the newest point, so the most recent day or minute is always labelled.
        for (var i = data.Count - 1; i >= 0; i -= stride)
        {
            var label = Text(data.AxisLabels[i], AxisFontSize, Regular, AxisBrush, dip);
            var x = _plot.Left + (band * i) + ((band - label.Width) / 2);
            x = Math.Clamp(x, _plot.Left, Math.Max(_plot.Left, _plot.Right - label.Width));
            dc.DrawText(label, new Point(x, _plot.Bottom + 4));
        }
    }

    private void DrawLine(DrawingContext dc, ChartSeries line, ChartData data, double band)
    {
        var pen = new Pen(LineBrush, 2) { LineJoin = PenLineJoin.Round, StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round };
        pen.Freeze();

        var geometry = new StreamGeometry();
        using (var context = geometry.Open())
        {
            for (var i = 0; i < data.Count; i++)
            {
                var point = new Point(_plot.Left + (band * (i + 0.5)), Y(line.Values[i], data.Max));
                if (i == 0)
                {
                    context.BeginFigure(point, false, false);
                }
                else
                {
                    context.LineTo(point, true, true);
                }
            }
        }

        geometry.Freeze();
        dc.DrawGeometry(null, pen, geometry);

        if (_hover >= 0 && _hover < data.Count)
        {
            var point = new Point(_plot.Left + (band * (_hover + 0.5)), Y(line.Values[_hover], data.Max));
            var ring = new Pen(SurfaceBrush, 2);
            ring.Freeze();
            dc.DrawEllipse(LineBrush, ring, point, 4.5, 4.5);
        }
    }

    private void DrawTip(DrawingContext dc, ChartData data, double band, double dip)
    {
        const double padding = 10;
        const double rowHeight = 18;
        const double swatch = 8;

        var rows = new List<(string Name, double Value, Brush? Brush)>();
        foreach (var series in data.Bars)
        {
            rows.Add((series.Name, series.Values[_hover], SlotBrush(series.Slot)));
        }

        if (data.Bars.Count > 1)
        {
            rows.Add(("Total", data.StackAt(_hover), null));
        }

        if (data.Line is { } line)
        {
            rows.Add((line.Name, line.Values[_hover], LineBrush));
        }

        var head = Text(data.Heads[_hover], TipFontSize, Strong, TipText, dip);
        var names = rows.Select(row => Text(row.Name, TipFontSize, Regular, TipText, dip)).ToList();
        var values = rows.Select(row => Text(row.Value.ToString("N0", CultureInfo.CurrentCulture), TipFontSize, Strong, TipText, dip)).ToList();

        var nameWidth = names.Count == 0 ? 0 : names.Max(text => text.Width);
        var valueWidth = values.Count == 0 ? 0 : values.Max(text => text.Width);
        var width = Math.Max(head.Width, swatch + 6 + nameWidth + 18 + valueWidth) + (padding * 2);
        var height = head.Height + 6 + (rows.Count * rowHeight) + (padding * 2) - 2;

        var anchor = _plot.Left + (band * (_hover + 1)) + 8;
        var x = anchor + width > _plot.Right ? _plot.Left + (band * _hover) - width - 8 : anchor;
        x = Math.Max(_plot.Left, x);
        var y = Math.Max(_plot.Top, _plot.Top + ((_plot.Height - height) / 2));

        var border = new Pen(TipBorder, 1);
        border.Freeze();
        dc.DrawRoundedRectangle(TipBackground, border, new Rect(Math.Round(x) + 0.5, Math.Round(y) + 0.5, Math.Round(width), Math.Round(height)), 5, 5);

        dc.DrawText(head, new Point(x + padding, y + padding - 2));
        var rowY = y + padding + head.Height + 4;
        for (var i = 0; i < rows.Count; i++)
        {
            if (rows[i].Brush is { } brush)
            {
                dc.DrawRoundedRectangle(brush, null, new Rect(x + padding, rowY + 4, swatch, swatch), 2, 2);
            }

            dc.DrawText(names[i], new Point(x + padding + swatch + 6, rowY));
            dc.DrawText(values[i], new Point(x + width - padding - values[i].Width, rowY));
            rowY += rowHeight;
        }
    }
}
