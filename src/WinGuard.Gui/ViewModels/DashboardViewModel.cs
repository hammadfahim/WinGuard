using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using WinGuard.Core.Config;
using WinGuard.Core.Ipc;
using WinGuard.Core.Model;
using WinGuard.Gui.Services;

namespace WinGuard.Gui.ViewModels;

/// <summary>
/// Dashboard view-model (PLAN.md §9.1): service-connection pill with an elevated Start button,
/// four protocol tiles with enable toggles, prerequisite warnings and a recent-activity strip.
/// </summary>
public sealed partial class DashboardViewModel : ObservableObject
{
    private const int RecentEventCount = 5;

    private readonly PipeClient _client;

    /// <summary>Creates the dashboard view-model.</summary>
    /// <param name="client">Pipe client used for settings updates.</param>
    public DashboardViewModel(PipeClient client)
    {
        _client = client;
        Tiles.Add(new EngineTileViewModel(ProtocolSource.Rdp, SourceLabels.Rdp, ToggleEngineAsync));
        Tiles.Add(new EngineTileViewModel(ProtocolSource.MsSql, SourceLabels.MsSql, ToggleEngineAsync));
        Tiles.Add(new EngineTileViewModel(ProtocolSource.Ftp, SourceLabels.Ftp, ToggleEngineAsync));
        Tiles.Add(new EngineTileViewModel(ProtocolSource.Custom, SourceLabels.Custom, ToggleEngineAsync));
    }

    /// <summary>Raised after this view changed the service settings (so other views can reload them).</summary>
    public event Action? SettingsChanged;

    /// <summary>Shown when the service speaks a different IPC version than this GUI.</summary>
    [ObservableProperty]
    private string _versionMismatchText = string.Empty;

    /// <summary>The four per-protocol tiles.</summary>
    public ObservableCollection<EngineTileViewModel> Tiles { get; } = [];

    /// <summary>The newest five events.</summary>
    public ObservableCollection<EventRowViewModel> RecentEvents { get; } = [];

    /// <summary>Prerequisite warnings from <see cref="PrereqsDto"/>.</summary>
    public ObservableCollection<string> Warnings { get; } = [];

    /// <summary>Whether the service pipe is connected.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ConnectionText))]
    private bool _isConnected;

    /// <summary>
    /// Why the service cannot be used although it is running (for example: it refused this
    /// console). Empty when the service is simply not running, or when everything is fine.
    /// </summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ConnectionText))]
    [NotifyPropertyChangedFor(nameof(DisconnectedText))]
    private string _connectionProblem = string.Empty;

    /// <summary>Whether any prerequisite warnings exist.</summary>
    [ObservableProperty]
    private bool _hasWarnings;

    /// <summary>Whether the recent-activity strip has entries.</summary>
    [ObservableProperty]
    private bool _hasRecentEvents;

    /// <summary>Service version text (e.g. "v0.1.0").</summary>
    [ObservableProperty]
    private string _versionText = string.Empty;

    /// <summary>Service start time in local time.</summary>
    [ObservableProperty]
    private string _startedText = string.Empty;

    /// <summary>Total active bans as text.</summary>
    [ObservableProperty]
    private string _totalActiveBansText = "0";

    /// <summary>Feedback for the Start-service button / settings toggles.</summary>
    [ObservableProperty]
    private string _serviceActionMessage = string.Empty;

    /// <summary>True when the service runs in report-only (monitoring) mode.</summary>
    [ObservableProperty]
    private bool _reportOnly;

    /// <summary>Pill caption.</summary>
    public string ConnectionText => IsConnected
        ? "Connected"
        : string.IsNullOrEmpty(ConnectionProblem) ? "Service not running" : "Not connected";

    /// <summary>Explanation shown while disconnected.</summary>
    public string DisconnectedText => string.IsNullOrEmpty(ConnectionProblem)
        ? "The WinGuard service is not running. Start it to begin protection."
        : "The WinGuard service is running, but this console cannot use it:";

    /// <summary>Applies a fresh status snapshot to the tiles and header.</summary>
    /// <param name="status">Status from the service.</param>
    public void UpdateStatus(ServiceStatusDto status)
    {
        VersionText = string.IsNullOrWhiteSpace(status.Version)
            ? string.Empty
            : $"Service v{status.Version} · console v{MainViewModel.ConsoleVersion}";
        StartedText = status.StartedUtc == default
            ? string.Empty
            : "Started " + status.StartedUtc.ToLocalTime().ToString("g");
        TotalActiveBansText = status.ActiveBans.ToString();
        ReportOnly = status.ReportOnly;
        VersionMismatchText = status.ProtocolVersion == PipeConstants.ProtocolVersion
            ? string.Empty
            : "The service and this console are from different WinGuard versions; some features may not work. Reinstall so both match.";

        foreach (var engine in status.Engines)
        {
            var tile = Tiles.FirstOrDefault(t => t.Source == engine.Source);
            tile?.Update(engine);
        }
    }

    /// <summary>Applies prerequisite check results to the warnings banner.</summary>
    /// <param name="prereqs">Result of CheckPrereqs.</param>
    public void UpdatePrereqs(PrereqsDto prereqs)
    {
        Warnings.Clear();

        // The service already words one warning per failed prerequisite; show those as they are.
        foreach (var warning in prereqs.Warnings)
        {
            if (!string.IsNullOrWhiteSpace(warning))
            {
                Warnings.Add(warning);
            }
        }

        HasWarnings = Warnings.Count > 0;
    }

    /// <summary>Prepends newly received events (newest-first input) and trims to five entries.</summary>
    /// <param name="events">Events from the poller.</param>
    public void AddRecentEvents(IReadOnlyList<EventDto> events)
    {
        foreach (var dto in events.Reverse())
        {
            RecentEvents.Insert(0, new EventRowViewModel(dto));
        }

        while (RecentEvents.Count > RecentEventCount)
        {
            RecentEvents.RemoveAt(RecentEvents.Count - 1);
        }

        HasRecentEvents = RecentEvents.Count > 0;
    }

    /// <summary>Runs <c>sc start WinGuardService</c> (this console already runs elevated) and reports the outcome.</summary>
    [RelayCommand]
    private async Task StartServiceAsync()
    {
        ServiceActionMessage = "Starting the service…";
        try
        {
            var exitCode = await Task.Run(() =>
            {
                var startInfo = new ProcessStartInfo
                {
                    // Full path, so a file named sc.exe elsewhere on the search path is never run.
                    FileName = Path.Combine(Environment.SystemDirectory, "sc.exe"),
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };
                startInfo.ArgumentList.Add("start");
                startInfo.ArgumentList.Add(Defaults.ServiceName);

                using var process = Process.Start(startInfo);
                if (process is null)
                {
                    return -1;
                }

                process.WaitForExit(15_000);
                return process.HasExited ? process.ExitCode : 0;
            });

            if (exitCode is 0 or 1056)
            {
                // Do not make the user wait for the background retry loop.
                await Task.Delay(1500);
                if (await _client.TryReconnectNowAsync())
                {
                    ServiceActionMessage = "Connected to the service.";
                    return;
                }
            }

            ServiceActionMessage = exitCode switch
            {
                0 => "Service start requested; it connects within a few seconds.",
                1056 => "The service is already running. If this console still cannot connect, the reason is shown above; the service log is in %ProgramData%\\WinGuard\\Logs.",
                1060 => "The WinGuard service is not installed. Run the installer, or winguard-svc.exe --install.",
                _ => $"The service could not be started (sc.exe exit code {exitCode}).",
            };
        }
        catch (Exception ex)
        {
            ServiceActionMessage = "Could not start the service: " + ex.Message;
        }
    }

    private async Task ToggleEngineAsync(EngineTileViewModel tile, bool enabled)
    {
        var settings = await _client.GetSettingsAsync();
        if (settings is null)
        {
            ServiceActionMessage = "Cannot change settings: the service is not running.";
            return;
        }

        switch (tile.Source)
        {
            case ProtocolSource.Rdp:
                settings.Rdp.Enabled = enabled;
                break;
            case ProtocolSource.MsSql:
                settings.MsSql.Enabled = enabled;
                break;
            case ProtocolSource.Ftp:
                settings.Ftp.Enabled = enabled;
                break;
            case ProtocolSource.Custom:
                if (settings.CustomSources.Count == 0)
                {
                    ServiceActionMessage = "No custom log sources are configured yet. Add one under Settings.";
                    return;
                }

                // There is no global Custom toggle in WinGuardSettings; enable/disable every source.
                foreach (var source in settings.CustomSources)
                {
                    source.Enabled = enabled;
                }

                break;
        }

        try
        {
            await _client.UpdateSettingsAsync(settings);
            ServiceActionMessage = $"{tile.Name} engine {(enabled ? "enabled" : "disabled")}.";
            SettingsChanged?.Invoke();
        }
        catch (Exception ex)
        {
            ServiceActionMessage = "Update failed: " + ex.Message;
        }
    }
}