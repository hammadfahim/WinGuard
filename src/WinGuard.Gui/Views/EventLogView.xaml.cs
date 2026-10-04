using System.Collections.Specialized;
using System.Windows;
using System.Windows.Controls;
using WinGuard.Gui.ViewModels;

namespace WinGuard.Gui.Views;

/// <summary>
/// Event Log view (PLAN.md §9.3). The code-behind only implements auto-scroll: when the list is at
/// the bottom (and auto-scroll is enabled) new rows are scrolled into view.
/// </summary>
public partial class EventLogView : System.Windows.Controls.UserControl
{
    private bool _isAtBottom = true;

    /// <summary>Initializes the view and hooks auto-scroll.</summary>
    public EventLogView()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        EventsList.AddHandler(ScrollViewer.ScrollChangedEvent, new ScrollChangedEventHandler(OnScrollChanged));
        if (EventsList.Items is INotifyCollectionChanged collection)
        {
            collection.CollectionChanged += OnCollectionChanged;
        }

        ScrollToEnd();
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        EventsList.RemoveHandler(ScrollViewer.ScrollChangedEvent, new ScrollChangedEventHandler(OnScrollChanged));
        if (EventsList.Items is INotifyCollectionChanged collection)
        {
            collection.CollectionChanged -= OnCollectionChanged;
        }
    }

    private void OnScrollChanged(object sender, ScrollChangedEventArgs e)
    {
        _isAtBottom = e.VerticalOffset >= e.ExtentHeight - e.ViewportHeight - 2;
    }

    private void OnCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (e.Action is not (NotifyCollectionChangedAction.Add or NotifyCollectionChangedAction.Reset))
        {
            return;
        }

        if (DataContext is EventLogViewModel { AutoScroll: false })
        {
            return;
        }

        if (!_isAtBottom)
        {
            return;
        }

        Dispatcher.BeginInvoke(new Action(ScrollToEnd));
    }

    private void ScrollToEnd()
    {
        if (EventsList.Items.Count == 0)
        {
            return;
        }

        EventsList.ScrollIntoView(EventsList.Items[EventsList.Items.Count - 1]);
    }
}