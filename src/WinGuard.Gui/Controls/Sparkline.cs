using System.Windows;
using System.Windows.Media;

namespace WinGuard.Gui.Controls;

/// <summary>A tiny trend line for a KPI tile: no axes, a 2 px line and one dot on the latest value.</summary>
public sealed class Sparkline : FrameworkElement
{
    /// <summary>The values, oldest first.</summary>
    public static readonly DependencyProperty ValuesProperty = DependencyProperty.Register(
        nameof(Values), typeof(IReadOnlyList<double>), typeof(Sparkline),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    /// <summary>Line colour.</summary>
    public static readonly DependencyProperty StrokeProperty = DependencyProperty.Register(
        nameof(Stroke), typeof(Brush), typeof(Sparkline),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    /// <summary>Gets or sets <see cref="ValuesProperty"/>.</summary>
    public IReadOnlyList<double>? Values
    {
        get => (IReadOnlyList<double>?)GetValue(ValuesProperty);
        set => SetValue(ValuesProperty, value);
    }

    /// <summary>Gets or sets <see cref="StrokeProperty"/>.</summary>
    public Brush? Stroke
    {
        get => (Brush?)GetValue(StrokeProperty);
        set => SetValue(StrokeProperty, value);
    }

    /// <inheritdoc />
    protected override void OnRender(DrawingContext dc)
    {
        var values = Values;
        var size = RenderSize;
        if (values is not { Count: > 1 } || size.Width <= 8 || size.Height <= 8)
        {
            return;
        }

        const double inset = 4;
        var max = Math.Max(1, values.Max());
        var step = (size.Width - (inset * 2)) / (values.Count - 1);
        Point At(int index) => new(inset + (step * index), size.Height - inset - ((size.Height - (inset * 2)) * values[index] / max));

        var geometry = new StreamGeometry();
        using (var context = geometry.Open())
        {
            context.BeginFigure(At(0), false, false);
            for (var i = 1; i < values.Count; i++)
            {
                context.LineTo(At(i), true, true);
            }
        }

        geometry.Freeze();

        var pen = new Pen(Stroke, 2) { LineJoin = PenLineJoin.Round, StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round };
        pen.Freeze();
        dc.DrawGeometry(null, pen, geometry);
        dc.DrawEllipse(Stroke, null, At(values.Count - 1), 3, 3);
    }
}
