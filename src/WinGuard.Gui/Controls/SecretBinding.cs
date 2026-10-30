using System.Windows;
using System.Windows.Controls;

namespace WinGuard.Gui.Controls;

/// <summary>
/// Two-way binding for <see cref="PasswordBox.Password"/>, which WPF deliberately leaves unbindable.
/// Used so SMTP passwords and bot tokens are masked on screen, where an RDP session may be recorded.
/// </summary>
public static class SecretBinding
{
    /// <summary>The bound secret.</summary>
    public static readonly DependencyProperty SecretProperty = DependencyProperty.RegisterAttached(
        "Secret",
        typeof(string),
        typeof(SecretBinding),
        new FrameworkPropertyMetadata(string.Empty, FrameworkPropertyMetadataOptions.BindsTwoWayByDefault, OnSecretChanged));

    private static readonly DependencyProperty HookedProperty = DependencyProperty.RegisterAttached(
        "Hooked", typeof(bool), typeof(SecretBinding), new PropertyMetadata(false));

    /// <summary>Gets <see cref="SecretProperty"/>.</summary>
    public static string GetSecret(DependencyObject element) => (string)element.GetValue(SecretProperty);

    /// <summary>Sets <see cref="SecretProperty"/>.</summary>
    public static void SetSecret(DependencyObject element, string value) => element.SetValue(SecretProperty, value);

    private static void OnSecretChanged(DependencyObject element, DependencyPropertyChangedEventArgs e)
    {
        if (element is not PasswordBox box)
        {
            return;
        }

        if (!(bool)box.GetValue(HookedProperty))
        {
            box.SetValue(HookedProperty, true);
            box.PasswordChanged += OnPasswordChanged;
        }

        var value = e.NewValue as string ?? string.Empty;
        if (box.Password != value)
        {
            box.Password = value;
        }
    }

    private static void OnPasswordChanged(object sender, RoutedEventArgs e)
    {
        var box = (PasswordBox)sender;
        if (GetSecret(box) != box.Password)
        {
            SetSecret(box, box.Password);
        }
    }
}
