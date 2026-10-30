using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using WinGuard.Gui.ViewModels;

namespace WinGuard.Gui.Controls;

/// <summary>
/// Attached properties the control templates read, so a view can say "this button has that icon" or
/// "this chip means Attack" without per-view templates or colours.
/// </summary>
public static class Ui
{
    /// <summary>Clears the text box the command is targeted at (the clear button of a search box).</summary>
    public static readonly RoutedUICommand ClearText = new("Clear", nameof(ClearText), typeof(Ui));

    /// <summary>Icon glyph shown by buttons, menu items and text boxes.</summary>
    public static readonly DependencyProperty IconProperty = DependencyProperty.RegisterAttached(
        "Icon", typeof(string), typeof(Ui), new PropertyMetadata(null));

    /// <summary>Hint shown in an empty text box.</summary>
    public static readonly DependencyProperty PlaceholderProperty = DependencyProperty.RegisterAttached(
        "Placeholder", typeof(string), typeof(Ui), new PropertyMetadata(null));

    /// <summary>Marks an input as invalid.</summary>
    public static readonly DependencyProperty HasErrorProperty = DependencyProperty.RegisterAttached(
        "HasError", typeof(bool), typeof(Ui), new PropertyMetadata(false));

    /// <summary>Shows a clear button while the text box holds text.</summary>
    public static readonly DependencyProperty ClearableProperty = DependencyProperty.RegisterAttached(
        "Clearable", typeof(bool), typeof(Ui), new PropertyMetadata(false, OnClearableChanged));

    /// <summary>Maintained by <see cref="ClearableProperty"/>: whether the text box holds text.</summary>
    public static readonly DependencyProperty HasTextProperty = DependencyProperty.RegisterAttached(
        "HasText", typeof(bool), typeof(Ui), new PropertyMetadata(false));

    /// <summary>Marks the text box Ctrl+F focuses on the visible page.</summary>
    public static readonly DependencyProperty IsPageSearchProperty = DependencyProperty.RegisterAttached(
        "IsPageSearch", typeof(bool), typeof(Ui), new PropertyMetadata(false));

    /// <summary>Background while the pointer is over a button.</summary>
    public static readonly DependencyProperty HoverBackgroundProperty = DependencyProperty.RegisterAttached(
        "HoverBackground", typeof(Brush), typeof(Ui), new PropertyMetadata(null));

    /// <summary>Border while the pointer is over a button.</summary>
    public static readonly DependencyProperty HoverBorderProperty = DependencyProperty.RegisterAttached(
        "HoverBorder", typeof(Brush), typeof(Ui), new PropertyMetadata(null));

    /// <summary>Background while a button is pressed.</summary>
    public static readonly DependencyProperty PressedBackgroundProperty = DependencyProperty.RegisterAttached(
        "PressedBackground", typeof(Brush), typeof(Ui), new PropertyMetadata(null));

    /// <summary>What an element means: the colour tokens follow from this.</summary>
    public static readonly DependencyProperty ToneProperty = DependencyProperty.RegisterAttached(
        "Tone", typeof(Tone), typeof(Ui), new PropertyMetadata(Tone.Neutral));

    /// <summary>Small count shown inside a filter chip.</summary>
    public static readonly DependencyProperty BadgeProperty = DependencyProperty.RegisterAttached(
        "Badge", typeof(string), typeof(Ui), new PropertyMetadata(null));

    static Ui()
    {
        CommandManager.RegisterClassCommandBinding(
            typeof(TextBox),
            new CommandBinding(ClearText, (sender, _) =>
            {
                var box = (TextBox)sender;
                box.Clear();
                box.Focus();
            }));
    }

    /// <summary>Gets <see cref="IconProperty"/>.</summary>
    public static string? GetIcon(DependencyObject element) => (string?)element.GetValue(IconProperty);

    /// <summary>Sets <see cref="IconProperty"/>.</summary>
    public static void SetIcon(DependencyObject element, string? value) => element.SetValue(IconProperty, value);

    /// <summary>Gets <see cref="PlaceholderProperty"/>.</summary>
    public static string? GetPlaceholder(DependencyObject element) => (string?)element.GetValue(PlaceholderProperty);

    /// <summary>Sets <see cref="PlaceholderProperty"/>.</summary>
    public static void SetPlaceholder(DependencyObject element, string? value) => element.SetValue(PlaceholderProperty, value);

    /// <summary>Gets <see cref="HasErrorProperty"/>.</summary>
    public static bool GetHasError(DependencyObject element) => (bool)element.GetValue(HasErrorProperty);

    /// <summary>Sets <see cref="HasErrorProperty"/>.</summary>
    public static void SetHasError(DependencyObject element, bool value) => element.SetValue(HasErrorProperty, value);

    /// <summary>Gets <see cref="ClearableProperty"/>.</summary>
    public static bool GetClearable(DependencyObject element) => (bool)element.GetValue(ClearableProperty);

    /// <summary>Sets <see cref="ClearableProperty"/>.</summary>
    public static void SetClearable(DependencyObject element, bool value) => element.SetValue(ClearableProperty, value);

    /// <summary>Gets <see cref="HasTextProperty"/>.</summary>
    public static bool GetHasText(DependencyObject element) => (bool)element.GetValue(HasTextProperty);

    /// <summary>Sets <see cref="HasTextProperty"/>.</summary>
    public static void SetHasText(DependencyObject element, bool value) => element.SetValue(HasTextProperty, value);

    /// <summary>Gets <see cref="IsPageSearchProperty"/>.</summary>
    public static bool GetIsPageSearch(DependencyObject element) => (bool)element.GetValue(IsPageSearchProperty);

    /// <summary>Sets <see cref="IsPageSearchProperty"/>.</summary>
    public static void SetIsPageSearch(DependencyObject element, bool value) => element.SetValue(IsPageSearchProperty, value);

    /// <summary>Gets <see cref="HoverBackgroundProperty"/>.</summary>
    public static Brush? GetHoverBackground(DependencyObject element) => (Brush?)element.GetValue(HoverBackgroundProperty);

    /// <summary>Sets <see cref="HoverBackgroundProperty"/>.</summary>
    public static void SetHoverBackground(DependencyObject element, Brush? value) => element.SetValue(HoverBackgroundProperty, value);

    /// <summary>Gets <see cref="HoverBorderProperty"/>.</summary>
    public static Brush? GetHoverBorder(DependencyObject element) => (Brush?)element.GetValue(HoverBorderProperty);

    /// <summary>Sets <see cref="HoverBorderProperty"/>.</summary>
    public static void SetHoverBorder(DependencyObject element, Brush? value) => element.SetValue(HoverBorderProperty, value);

    /// <summary>Gets <see cref="PressedBackgroundProperty"/>.</summary>
    public static Brush? GetPressedBackground(DependencyObject element) => (Brush?)element.GetValue(PressedBackgroundProperty);

    /// <summary>Sets <see cref="PressedBackgroundProperty"/>.</summary>
    public static void SetPressedBackground(DependencyObject element, Brush? value) => element.SetValue(PressedBackgroundProperty, value);

    /// <summary>Gets <see cref="ToneProperty"/>.</summary>
    public static Tone GetTone(DependencyObject element) => (Tone)element.GetValue(ToneProperty);

    /// <summary>Sets <see cref="ToneProperty"/>.</summary>
    public static void SetTone(DependencyObject element, Tone value) => element.SetValue(ToneProperty, value);

    /// <summary>Gets <see cref="BadgeProperty"/>.</summary>
    public static string? GetBadge(DependencyObject element) => (string?)element.GetValue(BadgeProperty);

    /// <summary>Sets <see cref="BadgeProperty"/>.</summary>
    public static void SetBadge(DependencyObject element, string? value) => element.SetValue(BadgeProperty, value);

    /// <summary>Finds the first descendant accepted by <paramref name="match"/>, skipping collapsed subtrees.</summary>
    public static T? FindVisible<T>(DependencyObject root, Func<T, bool> match)
        where T : DependencyObject
    {
        var count = VisualTreeHelper.GetChildrenCount(root);
        for (var i = 0; i < count; i++)
        {
            var child = VisualTreeHelper.GetChild(root, i);
            if (child is UIElement { Visibility: not Visibility.Visible })
            {
                continue;
            }

            if (child is T candidate && match(candidate))
            {
                return candidate;
            }

            if (FindVisible(child, match) is { } nested)
            {
                return nested;
            }
        }

        return null;
    }

    /// <summary>Walks up the visual tree to the first ancestor of the given type.</summary>
    public static T? FindAncestor<T>(DependencyObject? current)
        where T : DependencyObject
    {
        while (current is not null)
        {
            if (current is T match)
            {
                return match;
            }

            current = current is Visual or System.Windows.Media.Media3D.Visual3D
                ? VisualTreeHelper.GetParent(current)
                : LogicalTreeHelper.GetParent(current);
        }

        return null;
    }

    private static void OnClearableChanged(DependencyObject element, DependencyPropertyChangedEventArgs e)
    {
        if (element is not TextBox box)
        {
            return;
        }

        box.TextChanged -= OnClearableTextChanged;
        if ((bool)e.NewValue)
        {
            box.TextChanged += OnClearableTextChanged;
            SetHasText(box, box.Text.Length > 0);
        }
    }

    private static void OnClearableTextChanged(object sender, TextChangedEventArgs e)
    {
        var box = (TextBox)sender;
        SetHasText(box, box.Text.Length > 0);
    }
}
