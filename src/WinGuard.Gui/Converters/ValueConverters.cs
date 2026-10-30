using System.Collections;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace WinGuard.Gui.Converters;

/// <summary>Collapses an element while the bound string, number or collection is empty.</summary>
public sealed class NotEmptyToVisibilityConverter : IValueConverter
{
    /// <summary>When true an empty value is what makes the element visible.</summary>
    public bool Invert { get; set; }

    /// <inheritdoc />
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var hasValue = value switch
        {
            null => false,
            string text => text.Length > 0,
            int number => number > 0,
            long number => number > 0,
            ICollection collection => collection.Count > 0,
            _ => true,
        };

        return hasValue != Invert ? Visibility.Visible : Visibility.Collapsed;
    }

    /// <inheritdoc />
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>True while the bound text is not empty, for marking an input invalid from its error text.</summary>
public sealed class NotEmptyToBoolConverter : IValueConverter
{
    /// <inheritdoc />
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is string { Length: > 0 };

    /// <inheritdoc />
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>Negates a boolean binding.</summary>
public sealed class InverseBoolConverter : IValueConverter
{
    /// <inheritdoc />
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is not true;

    /// <inheritdoc />
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is not true;
}
