using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using WinGuard.Gui.Controls;
using WinGuard.Gui.Services;
using WinGuard.Gui.ViewModels;

namespace WinGuard.Gui.Views;

/// <summary>
/// The console's frame: rail, state banner, pages, toasts and the dialog layer. It sits apart from the
/// window so it can be measured and rendered off-screen. The code-behind only does what is purely
/// visual: the rail's width, the sliding selection bar, and moving focus in and out of the dialog.
/// </summary>
public partial class ShellView : System.Windows.Controls.UserControl
{
    /// <summary>Whether the rail shows icons only.</summary>
    public static readonly DependencyProperty IsCompactProperty = DependencyProperty.Register(
        nameof(IsCompact), typeof(bool), typeof(ShellView), new PropertyMetadata(false, OnCompactChanged));

    private const double CompactBelow = 1180;
    private const double RailWidth = 208;
    private const double CompactRailWidth = 60;

    private DialogCenter? _dialogs;
    private IInputElement? _focusBeforeDialog;

    /// <summary>Initializes the view.</summary>
    public ShellView()
    {
        InitializeComponent();
        Loaded += (_, _) => PlaceIndicator(animate: false);
        SizeChanged += (_, e) => IsCompact = e.NewSize.Width < CompactBelow;
        DataContextChanged += OnDataContextChanged;
    }

    /// <summary>Gets or sets <see cref="IsCompactProperty"/>.</summary>
    public bool IsCompact
    {
        get => (bool)GetValue(IsCompactProperty);
        set => SetValue(IsCompactProperty, value);
    }

    /// <summary>Moves keyboard focus to the visible page's search box (Ctrl+F).</summary>
    public void FocusPageSearch()
    {
        var box = Ui.FindVisible<TextBox>(Pages, Ui.GetIsPageSearch);
        if (box is not null)
        {
            box.Focus();
            box.SelectAll();
        }
    }

    private static void OnCompactChanged(DependencyObject sender, DependencyPropertyChangedEventArgs e)
    {
        var shell = (ShellView)sender;
        var compact = (bool)e.NewValue;
        var hidden = compact ? Visibility.Collapsed : Visibility.Visible;
        shell.Rail.Width = compact ? CompactRailWidth : RailWidth;
        shell.Wordmark.Visibility = hidden;
        shell.RailFacts.Visibility = hidden;
        shell.ThemeLabel.Visibility = hidden;
        shell.UpdateLabel.Visibility = hidden;
        shell.UpdateButton.HorizontalContentAlignment = compact ? HorizontalAlignment.Center : HorizontalAlignment.Left;
        shell.ThemeButton.HorizontalContentAlignment = compact ? HorizontalAlignment.Center : HorizontalAlignment.Left;
        shell.Dispatcher.BeginInvoke(DispatcherPriority.Loaded, () => shell.PlaceIndicator(animate: false));
    }

    private void OnNavSelectionChanged(object sender, SelectionChangedEventArgs e) =>
        Dispatcher.BeginInvoke(DispatcherPriority.Loaded, () => PlaceIndicator(animate: true));

    private void PlaceIndicator(bool animate)
    {
        if (NavList.SelectedItem is null
            || NavList.ItemContainerGenerator.ContainerFromItem(NavList.SelectedItem) is not ListBoxItem container
            || !container.IsVisible)
        {
            return;
        }

        var y = container.TranslatePoint(default, NavArea).Y;
        if (animate)
        {
            Motion.To(NavIndicatorShift, TranslateTransform.YProperty, y);
        }
        else
        {
            NavIndicatorShift.BeginAnimation(TranslateTransform.YProperty, null);
            NavIndicatorShift.Y = y;
        }
    }

    private void OnDataContextChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        if (_dialogs is not null)
        {
            _dialogs.PropertyChanged -= OnDialogsChanged;
        }

        _dialogs = (e.NewValue as MainViewModel)?.Dialogs;
        if (_dialogs is not null)
        {
            _dialogs.PropertyChanged += OnDialogsChanged;
        }
    }

    private void OnDialogsChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName != nameof(DialogCenter.Current) || _dialogs is null)
        {
            return;
        }

        if (_dialogs.Current is { } dialog)
        {
            _focusBeforeDialog ??= Keyboard.FocusedElement;

            // Destructive questions default to the safe answer: Enter must not unblock anything.
            Dispatcher.BeginInvoke(DispatcherPriority.Loaded, () =>
            {
                Button target = dialog.IsDestructive ? DialogCancel : DialogConfirm;
                target.Focus();
                Keyboard.Focus(target);
            });
        }
        else
        {
            _focusBeforeDialog?.Focus();
            _focusBeforeDialog = null;
        }
    }
}
