using System.Windows;
using System.Windows.Controls;

namespace WinGuard.Gui.Controls;

/// <summary>
/// Keeps each page alive once it has been opened and only flips visibility. A plain ContentControl
/// rebuilds the view on every navigation, which throws away grid sort, selection and scroll position.
/// Collapsed pages are not measured or rendered, so keeping them costs memory but no layout time.
/// </summary>
public sealed class PageHost : Grid
{
    /// <summary>The view-model to show; its view is found through the DataTemplates in scope.</summary>
    public static readonly DependencyProperty PageProperty = DependencyProperty.Register(
        nameof(Page), typeof(object), typeof(PageHost), new PropertyMetadata(null, OnPageChanged));

    private readonly Dictionary<object, ContentPresenter> _pages = [];

    /// <summary>Gets or sets <see cref="PageProperty"/>.</summary>
    public object? Page
    {
        get => GetValue(PageProperty);
        set => SetValue(PageProperty, value);
    }

    private static void OnPageChanged(DependencyObject sender, DependencyPropertyChangedEventArgs e) =>
        ((PageHost)sender).Show(e.NewValue);

    private void Show(object? page)
    {
        foreach (var presenter in _pages.Values)
        {
            presenter.Visibility = Visibility.Collapsed;
        }

        if (page is null)
        {
            return;
        }

        if (!_pages.TryGetValue(page, out var current))
        {
            current = new ContentPresenter { Content = page };
            _pages[page] = current;
            Children.Add(current);
        }

        current.Visibility = Visibility.Visible;
    }
}
