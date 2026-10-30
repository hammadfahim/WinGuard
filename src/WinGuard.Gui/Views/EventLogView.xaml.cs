using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Threading;
using WinGuard.Gui.Services;
using WinGuard.Gui.ViewModels;

namespace WinGuard.Gui.Views;

/// <summary>
/// Event Log view (PLAN.md §9.3). The code-behind reports whether the list is at the bottom, follows
/// new rows while it is, and scrolls when the view-model asks. The tail logic is in the view-model.
/// </summary>
public partial class EventLogView : System.Windows.Controls.UserControl
{
    private EventLogViewModel? _viewModel;

    /// <summary>Initializes the view.</summary>
    public EventLogView()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
        DataContextChanged += (_, e) => Bind(e.NewValue as EventLogViewModel);
    }

    private void Bind(EventLogViewModel? viewModel)
    {
        if (_viewModel is not null)
        {
            _viewModel.ScrollToEndRequested -= ScrollToEnd;
        }

        _viewModel = viewModel;
        if (_viewModel is not null)
        {
            _viewModel.ScrollToEndRequested += ScrollToEnd;
        }
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        EventsList.AddHandler(ScrollViewer.ScrollChangedEvent, new ScrollChangedEventHandler(OnScrollChanged));
        ScrollToEnd();
    }

    private void OnUnloaded(object sender, RoutedEventArgs e) =>
        EventsList.RemoveHandler(ScrollViewer.ScrollChangedEvent, new ScrollChangedEventHandler(OnScrollChanged));

    private void OnScrollChanged(object sender, ScrollChangedEventArgs e)
    {
        if (_viewModel is null)
        {
            return;
        }

        // Growth alone says nothing about the reader: follow the new rows if we were at the bottom.
        if (e.ExtentHeightChange > 0 && _viewModel.IsFollowing && !_viewModel.IsPaused)
        {
            Dispatcher.BeginInvoke(DispatcherPriority.Background, ScrollToEnd);
            return;
        }

        _viewModel.SetFollowing(e.VerticalOffset >= e.ExtentHeight - e.ViewportHeight - 2);
    }

    private void ScrollToEnd()
    {
        if (EventsList.Items.Count > 0)
        {
            EventsList.ScrollIntoView(EventsList.Items[^1]);
        }
    }

    private void OnListKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.C && Keyboard.Modifiers == ModifierKeys.Control && EventsList.SelectedItems.Count > 0)
        {
            var rows = EventsList.SelectedItems.OfType<EventRowViewModel>().OrderBy(row => row.Dto.Id);
            ClipboardText.TrySet(string.Join(Environment.NewLine, rows.Select(row => row.CopyText)));
            e.Handled = true;
        }
    }
}
