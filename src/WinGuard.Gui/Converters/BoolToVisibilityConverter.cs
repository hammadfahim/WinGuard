using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace WinGuard.Gui.Converters;

/// <summary>
/// Converts a <see cref="bool"/> to a <see cref="Visibility"/>. Set <see cref="Invert"/> (or pass
/// the string "invert" as the converter parameter) to flip the result.
/// </summary>
public sealed class BoolToVisibilityConverter : IValueConverter
{
    /// <summary>When true, <c>true</c> maps to Collapsed and <c>false</c> to Visible.</summary>
    public bool Invert { get; set; }

    /// <inheritdoc />
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var flag = value is true;
        if (Invert)
        {
            flag = !flag;
        }

        if (parameter is string text && text.Equals("invert", StringComparison.OrdinalIgnoreCase))
        {
            flag = !flag;
        }

        return flag ? Visibility.Visible : Visibility.Collapsed;
    }

    /// <inheritdoc />
    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}