using System.Collections.ObjectModel;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using WinGuard.Core.Ipc;
using WinGuard.Gui.Services;

namespace WinGuard.Gui.ViewModels;

/// <summary>
/// Shell view-model: owns the pipe client, the status poller and all five view-models, exposes the
/// navigation entries and drives the dark/light theme toggle.
/// </summary>
public sealed partial class MainViewModel : ObservableObject
{
    private readonly PipeClient _client;
    private readonly StatusPoller _poller;
    private readonly Dispatcher _dispatcher;

    /// <summary>Creates the shell and starts polling.</summary>
    /// <param name="client">Started pipe client.</param>
    /// <param name="dispatcher">UI dispatcher used to marshal connection-state changes.</param>
    public MainViewModel(PipeClient client, Dispatcher dispatcher)
    {
        _client = client;
        _dispatcher = dispatcher;

        Dashboard = new DashboardViewModel(client);
        BlockedIps = new BlockedIpsViewModel(client);
        EventLog = new EventLogViewModel();
        Settings = new SettingsViewModel(client);
        Lists = new ListsViewModel(client);

        NavigationItems =
        [
            new NavigationItem("Dashboard", Dashboard),
            new NavigationItem("Blocked IPs", BlockedIps),
            new NavigationItem("Event Log", EventLog),
            new NavigationItem("Settings", Settings),
            new NavigationItem("Lists", Lists),
        ];

        _poller = new StatusPoller(client);
        _poller.StatusUpdated += Dashboard.UpdateStatus;
        _poller.EventsReceived += OnEventsReceived;
        _poller.BansReceived += BlockedIps.UpdateBans;
        _poller.Start();

        SelectedNavigation = NavigationItems[0];

        _client.StateChanged += OnClientStateChanged;
        IsConnected = client.IsConnected;
        Dashboard.IsConnected = client.IsConnected;
    }

    /// <summary>Raised when the user toggles the theme (true = dark).</summary>
    public event Action<bool>? ThemeChanged;

    /// <summary>Dashboard view-model.</summary>
    public DashboardViewModel Dashboard { get; }

    /// <summary>Blocked IPs view-model.</summary>
    public BlockedIpsViewModel BlockedIps { get; }

    /// <summary>Event Log view-model.</summary>
    public EventLogViewModel EventLog { get; }

    /// <summary>Settings view-model.</summary>
    public SettingsViewModel Settings { get; }

    /// <summary>Lists view-model.</summary>
    public ListsViewModel Lists { get; }

    /// <summary>Left-navigation entries.</summary>
    public ObservableCollection<NavigationItem> NavigationItems { get; }

    /// <summary>Currently selected navigation entry.</summary>
    [ObservableProperty]
    private NavigationItem? _selectedNavigation;

    /// <summary>Whether the service pipe is connected.</summary>
    [ObservableProperty]
    private bool _isConnected;

    /// <summary>Whether the dark theme is active.</summary>
    [ObservableProperty]
    private bool _isDarkTheme = true;

    /// <summary>View-model currently rendered in the content area.</summary>
    public object? CurrentViewModel => SelectedNavigation?.ViewModel;

    /// <summary>Stops polling and unsubscribes.</summary>
    public void Dispose()
    {
        _client.StateChanged -= OnClientStateChanged;
        _poller.Dispose();
    }

    /// <summary>Switches between the dark and light themes.</summary>
    [RelayCommand]
    private void ToggleTheme()
    {
        IsDarkTheme = !IsDarkTheme;
        ThemeChanged?.Invoke(IsDarkTheme);
    }

    partial void OnSelectedNavigationChanged(NavigationItem? value)
    {
        OnPropertyChanged(nameof(CurrentViewModel));
        _poller.BansViewActive = value?.ViewModel is BlockedIpsViewModel;
    }

    private void OnEventsReceived(IReadOnlyList<EventDto> events)
    {
        Dashboard.AddRecentEvents(events);
        EventLog.AddEvents(events);
    }

    private int _handlingConnection;

    private void OnClientStateChanged(bool connected) =>
        _dispatcher.InvokeAsync(() => _ = HandleConnectionChangedAsync(connected));

    private async Task HandleConnectionChangedAsync(bool connected)
    {
        IsConnected = connected;
        Dashboard.IsConnected = connected;

        if (!connected)
        {
            return;
        }

        // Re-entrancy guard: the loads below can themselves trigger reconnects (every
        // failed request reconnects and re-fires StateChanged), which without this guard
        // becomes a tight connect/disconnect storm when the service keeps refusing us
        // (observed live: ~250% CPU + 2 GB churn while the pill blinked).
        if (Interlocked.Exchange(ref _handlingConnection, 1) == 1)
        {
            return;
        }

        try
        {
            _poller.ResetEventCursor();

            try
            {
                var prereqs = await _client.CheckPrereqsAsync();
                if (prereqs is not null)
                {
                    Dashboard.UpdatePrereqs(prereqs);
                }
            }
            catch
            {
                // Warnings are best-effort.
            }

            try
            {
                await Settings.LoadAsync();
                await Lists.LoadAsync();
            }
            catch
            {
                // Surfaces as the disconnected pill; the next state change retries.
            }
        }
        finally
        {
            Interlocked.Exchange(ref _handlingConnection, 0);
        }
    }
}