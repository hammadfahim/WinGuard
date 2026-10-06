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
public sealed partial class MainViewModel : ObservableObject, IDisposable
{
    private readonly PipeClient _client;
    private readonly StatusPoller _poller;

    /// <summary>Pauses or resumes background polling (call with false while the window is hidden).</summary>
    public void SetWindowActive(bool active)
    {
        _poller.Paused = !active;
        if (active)
        {
            _poller.ResetEventCursor();
        }
    }

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

        // A dashboard toggle changes the settings behind the Settings page's back; reload them so
        // a later Save there does not write the old values over the change.
        Dashboard.SettingsChanged += () => _ = Settings.LoadAsync();

        _client.StateChanged += OnClientStateChanged;
        _client.ProblemChanged += OnClientProblemChanged;
        Dashboard.ConnectionProblem = client.LastProblem ?? string.Empty;

        // The client may already be connected: the event for that connection was raised before we
        // subscribed, so run the on-connect work (load settings, lists, prerequisites) now.
        if (client.IsConnected)
        {
            OnClientStateChanged(true);
        }
    }

    /// <summary>Raised when the user picks another theme.</summary>
    public event Action<ThemeChoice>? ThemeChoiceChanged;

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

    /// <summary>The theme the user picked (System follows Windows).</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ThemeButtonText))]
    private ThemeChoice _themeChoice = ThemeChoice.System;

    /// <summary>
    /// Window caption including this console's version, so it is always visible which build is
    /// on screen (an upgrade can leave an older console running in the tray).
    /// </summary>
    public string WindowTitle { get; } = "WinGuard " + ConsoleVersion;

    /// <summary>This console's version, e.g. "0.1.8".</summary>
    public static string ConsoleVersion { get; } =
        typeof(MainViewModel).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";

    /// <summary>Caption of the theme button.</summary>
    public string ThemeButtonText => "Theme: " + (ThemeChoice switch
    {
        ThemeChoice.Light => "Light",
        ThemeChoice.Dark => "Dark",
        _ => "System",
    });

    /// <summary>View-model currently rendered in the content area.</summary>
    public object? CurrentViewModel => SelectedNavigation?.ViewModel;

    /// <summary>Stops polling and unsubscribes.</summary>
    public void Dispose()
    {
        _client.StateChanged -= OnClientStateChanged;
        _client.ProblemChanged -= OnClientProblemChanged;
        _poller.Dispose();
    }

    /// <summary>Cycles System → Light → Dark.</summary>
    [RelayCommand]
    private void CycleTheme()
    {
        ThemeChoice = ThemeChoice switch
        {
            ThemeChoice.System => ThemeChoice.Light,
            ThemeChoice.Light => ThemeChoice.Dark,
            _ => ThemeChoice.System,
        };
        ThemeChoiceChanged?.Invoke(ThemeChoice);
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
    private bool _reloadRequested;

    private void OnClientProblemChanged(string? problem) =>
        _dispatcher.InvokeAsync(() => Dashboard.ConnectionProblem = problem ?? string.Empty);

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
            _reloadRequested = true;
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

        // A reconnect arrived while the loads above were running: do them once more.
        if (_reloadRequested && _client.IsConnected)
        {
            _reloadRequested = false;
            await HandleConnectionChangedAsync(true);
        }
    }
}