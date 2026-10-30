using System.Collections.ObjectModel;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using WinGuard.Core.Ipc;
using WinGuard.Gui.Services;

namespace WinGuard.Gui.ViewModels;

/// <summary>
/// Shell view-model: owns the pipe client, the status poller and all six page view-models, exposes the
/// navigation entries and the shared toast and dialog channels, and drives the theme toggle.
/// </summary>
public sealed partial class MainViewModel : ObservableObject, IDisposable
{
    private const string NotConnectedReason = "The WinGuard service is not connected. It will be picked up as soon as it runs.";

    private readonly PipeClient _client;
    private readonly StatusPoller _poller;
    private readonly Dispatcher _dispatcher;
    private readonly DispatcherTimer _clock;

    private NavigationItem? _selectedNavigation;
    private int _handlingConnection;
    private bool _reloadRequested;
    private int _slowTicks;

    /// <summary>Creates the shell and starts polling.</summary>
    /// <param name="client">Started pipe client.</param>
    /// <param name="dispatcher">UI dispatcher used to marshal connection-state changes.</param>
    public MainViewModel(PipeClient client, Dispatcher dispatcher)
    {
        _client = client;
        _dispatcher = dispatcher;

        Dashboard = new DashboardViewModel(client, Toasts, Dialogs);
        BlockedIps = new BlockedIpsViewModel(client, Toasts, Dialogs);
        EventLog = new EventLogViewModel(Toasts);
        Statistics = new StatisticsViewModel(client, Toasts);
        Settings = new SettingsViewModel(client, Toasts);
        Lists = new ListsViewModel(client, Toasts, Dialogs);

        NavigationItems =
        [
            new NavigationItem("Dashboard", "", 1, Dashboard),
            new NavigationItem("Blocked IPs", "", 2, BlockedIps),
            new NavigationItem("Event Log", "", 3, EventLog),
            new NavigationItem("Statistics", "", 4, Statistics),
            new NavigationItem("Lists", "", 5, Lists),
            new NavigationItem("Settings", "", 6, Settings),
        ];

        _poller = new StatusPoller(client);
        _poller.StatusUpdated += OnStatusUpdated;
        _poller.EventsReceived += OnEventsReceived;
        _poller.BansReceived += OnBansReceived;
        _poller.SlowTick += OnSlowTick;
        _poller.Start();

        _selectedNavigation = NavigationItems[0];
        _poller.BansViewActive = true;

        // A dashboard toggle changes the settings behind the Settings page's back; reload them so
        // a later Save there does not write the old values over the change.
        Dashboard.SettingsChanged += () => _ = Settings.LoadAsync();
        Dashboard.ShowBansRequested += search =>
        {
            if (search is not null)
            {
                BlockedIps.Show(search);
            }

            SelectedNavigation = NavigationItems[1];
        };
        Dashboard.ShowEngineRequested += source =>
        {
            EventLog.ShowEngine(source);
            SelectedNavigation = NavigationItems[2];
        };
        Dashboard.ShowStatisticsRequested += () => SelectedNavigation = NavigationItems[3];
        Dashboard.ShowSettingsRequested += section =>
        {
            Settings.Show(section);
            SelectedNavigation = NavigationItems[5];
        };

        Statistics.Loaded += Dashboard.UpdateStatistics;
        Settings.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(SettingsViewModel.IsDirty))
            {
                NavigationItems[5].HasAttention = Settings.IsDirty;
            }
        };

        _client.StateChanged += OnClientStateChanged;
        _client.ProblemChanged += OnClientProblemChanged;
        Dashboard.ConnectionProblem = client.LastProblem ?? string.Empty;

        _clock = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _clock.Tick += OnClockTick;
        _clock.Start();

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

    /// <summary>Statistics view-model.</summary>
    public StatisticsViewModel Statistics { get; }

    /// <summary>Settings view-model.</summary>
    public SettingsViewModel Settings { get; }

    /// <summary>Lists view-model.</summary>
    public ListsViewModel Lists { get; }

    /// <summary>In-app notifications.</summary>
    public ToastCenter Toasts { get; } = new();

    /// <summary>In-app confirmations.</summary>
    public DialogCenter Dialogs { get; } = new();

    /// <summary>Left-navigation entries.</summary>
    public ObservableCollection<NavigationItem> NavigationItems { get; }

    /// <summary>
    /// Currently selected navigation entry. Leaving Settings with unsaved edits asks first, so a
    /// navigation request may leave this unchanged.
    /// </summary>
    public NavigationItem? SelectedNavigation
    {
        get => _selectedNavigation;
        set
        {
            if (value is null || ReferenceEquals(value, _selectedNavigation))
            {
                return;
            }

            if (ReferenceEquals(_selectedNavigation?.ViewModel, Settings) && Settings.IsDirty)
            {
                _ = GuardedNavigateAsync(value);

                // The list has already moved its own selection: put it back until the user decides.
                _dispatcher.BeginInvoke(() => OnPropertyChanged(nameof(SelectedNavigation)));
                return;
            }

            Commit(value);
        }
    }

    /// <summary>Whether the service pipe is connected.</summary>
    [ObservableProperty]
    private bool _isConnected;

    /// <summary>The theme the user picked (System follows Windows).</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ThemeButtonText))]
    private ThemeChoice _themeChoice = ThemeChoice.System;

    /// <summary>
    /// Window caption including this console's version and the machine, so it is always visible which
    /// build and which server is on screen (an RDP session often sits next to another one).
    /// </summary>
    public string WindowTitle { get; } = $"WinGuard {ConsoleVersion} - {Environment.MachineName}";

    /// <summary>This console's version, e.g. "0.1.8".</summary>
    public static string ConsoleVersion { get; } =
        typeof(MainViewModel).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";

    /// <summary>The machine this console manages, shown in the rail.</summary>
    public string MachineName { get; } = Environment.MachineName;

    /// <summary>Console version text for the rail.</summary>
    public string ConsoleVersionText { get; } = "Console " + ConsoleVersion;

    /// <summary>Caption of the theme button.</summary>
    public string ThemeButtonText => ThemeChoice switch
    {
        ThemeChoice.Light => "Light",
        ThemeChoice.Dark => "Dark",
        _ => "System",
    };

    /// <summary>View-model currently rendered in the content area.</summary>
    public object? CurrentViewModel => SelectedNavigation?.ViewModel;

    /// <summary>Pauses or resumes background polling (call with false while the window is hidden).</summary>
    public void SetWindowActive(bool active)
    {
        _poller.Paused = !active;
        if (active)
        {
            _clock.Start();

            // The event cursor stayed put, so this reads everything that arrived meanwhile.
            _ = _poller.PollNowAsync();
        }
        else
        {
            _clock.Stop();
        }
    }

    /// <summary>
    /// Asks before quitting with unsaved settings. The answer decides whether the application exits.
    /// </summary>
    public async Task<bool> ConfirmExitAsync()
    {
        if (!Settings.IsDirty)
        {
            return true;
        }

        return await ResolveUnsavedAsync("Quit") != DialogChoice.Cancel;
    }

    /// <summary>Stops polling and unsubscribes.</summary>
    public void Dispose()
    {
        _client.StateChanged -= OnClientStateChanged;
        _client.ProblemChanged -= OnClientProblemChanged;
        _clock.Stop();
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

    /// <summary>Opens a page by its Ctrl+N number.</summary>
    [RelayCommand]
    private void NavigateTo(string? shortcut)
    {
        // A dialog is modal: the page behind it must not change.
        if (Dialogs.Current is null && int.TryParse(shortcut, out var number) && number >= 1 && number <= NavigationItems.Count)
        {
            SelectedNavigation = NavigationItems[number - 1];
        }
    }

    /// <summary>F5: re-reads everything the visible page shows.</summary>
    [RelayCommand]
    private async Task RefreshAsync()
    {
        if (!_client.IsConnected)
        {
            await RetryConnectionAsync();
            return;
        }

        await _poller.PollNowAsync();
        switch (CurrentViewModel)
        {
            case StatisticsViewModel statistics:
                await statistics.LoadAsync();
                break;
            case ListsViewModel lists:
                await lists.LoadAsync();
                break;
            case SettingsViewModel settings:
                await settings.LoadAsync();
                break;
            case DashboardViewModel:
                await CheckPrereqsAsync();
                await Statistics.LoadAsync();
                break;
        }
    }

    /// <summary>Ctrl+S: saves settings while they are on screen.</summary>
    [RelayCommand]
    private async Task SaveAsync()
    {
        if (ReferenceEquals(CurrentViewModel, Settings) && Settings.IsDirty)
        {
            await Settings.TrySaveAsync();
        }
    }

    /// <summary>Tries the connection and the prerequisites again right now.</summary>
    [RelayCommand]
    private async Task RetryConnectionAsync()
    {
        if (_client.IsConnected)
        {
            await CheckPrereqsAsync();
            await _poller.PollNowAsync();
            return;
        }

        if (!await _client.TryReconnectNowAsync())
        {
            Toasts.Warning("Still not connected", _client.LastProblem ?? "The WinGuard service is not running.");
        }
    }

    private void Commit(NavigationItem value)
    {
        _selectedNavigation = value;
        OnPropertyChanged(nameof(SelectedNavigation));
        OnPropertyChanged(nameof(CurrentViewModel));
        _poller.BansViewActive = value.ViewModel is BlockedIpsViewModel or DashboardViewModel;
        if (value.ViewModel is BlockedIpsViewModel)
        {
            BlockedIps.Tick();
        }
    }

    private async Task GuardedNavigateAsync(NavigationItem target)
    {
        if (await ResolveUnsavedAsync("Leave") != DialogChoice.Cancel)
        {
            Commit(target);
        }
    }

    /// <summary>Save, discard or stay. Cancel means stay; a failed save counts as staying.</summary>
    private async Task<DialogChoice> ResolveUnsavedAsync(string verb)
    {
        var choice = await Dialogs.ShowAsync(new DialogRequest(
            Tone.Warn,
            "Save your changes?",
            "Some settings have not been saved. They are lost if you continue without saving.",
            "Save and continue")
        {
            AlternateText = "Discard changes",
            CancelText = verb == "Quit" ? "Keep editing" : "Stay here",
        });

        switch (choice)
        {
            case DialogChoice.Confirm:
                return await Settings.TrySaveAsync() ? DialogChoice.Confirm : DialogChoice.Cancel;
            case DialogChoice.Alternate:
                await Settings.DiscardAsync();
                return DialogChoice.Alternate;
            default:
                return DialogChoice.Cancel;
        }
    }

    private void OnClockTick(object? sender, EventArgs e)
    {
        Toasts.Prune(DateTime.UtcNow);
        if (ReferenceEquals(CurrentViewModel, BlockedIps))
        {
            BlockedIps.Tick();
        }
    }

    private void OnStatusUpdated(ServiceStatusDto status)
    {
        Dashboard.UpdateStatus(status);
        BlockedIps.IsReportOnly = status.ReportOnly;
        NavigationItems[1].Badge = status.ActiveBans > 0 ? status.ActiveBans.ToString("N0") : string.Empty;
    }

    private void OnEventsReceived(EventBatch batch)
    {
        Dashboard.AddEvents(batch.Events);
        EventLog.AddEvents(batch);
    }

    private void OnBansReceived(IReadOnlyList<BanDto> bans)
    {
        Dashboard.UpdateBans(bans);
        BlockedIps.UpdateBans(bans);
    }

    private void OnSlowTick()
    {
        _ = Statistics.LoadAsync();
        if (++_slowTicks % 2 == 0)
        {
            _ = CheckPrereqsAsync();
        }
    }

    private async Task CheckPrereqsAsync()
    {
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
    }

    private void OnClientProblemChanged(string? problem) =>
        _dispatcher.InvokeAsync(() =>
        {
            Dashboard.ConnectionProblem = problem ?? string.Empty;
            Dashboard.ConnectionSettled = true;
        });

    private void OnClientStateChanged(bool connected) =>
        _dispatcher.InvokeAsync(() => _ = HandleConnectionChangedAsync(connected));

    private async Task HandleConnectionChangedAsync(bool connected)
    {
        IsConnected = connected;
        Dashboard.IsConnected = connected;
        Dashboard.ConnectionSettled = true;

        if (!connected)
        {
            MarkDisconnected(NotConnectedReason);
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
            EventLog.SetConnected();
            BlockedIps.SetConnecting();
            await _poller.PollNowAsync();
            await CheckPrereqsAsync();

            try
            {
                await Settings.LoadAsync();
                await Lists.LoadAsync();
                await Statistics.LoadAsync();
            }
            catch
            {
                // Surfaces in the banner; the next state change retries.
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

    /// <summary>Shows the shared error state on pages that have nothing to show yet.</summary>
    /// <param name="reason">Why nothing is available.</param>
    public void MarkDisconnected(string reason)
    {
        BlockedIps.SetDisconnected(reason);
        EventLog.SetDisconnected(reason);
        Statistics.SetDisconnected(reason);
        Lists.SetDisconnected(reason);
        Settings.SetDisconnected(reason);
    }
}
