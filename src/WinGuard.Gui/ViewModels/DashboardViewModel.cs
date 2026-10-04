using System.Collections.ObjectModel;
using System.Diagnostics;
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
        Tiles.Add(new EngineTileViewModel(ProtocolSource.Rdp, "RDP", ToggleEngineAsync));
        Tiles.Add(new EngineTileViewModel(ProtocolSource.MsSql, "MS SQL", ToggleEngineAsync));
        Tiles.Add(new EngineTileViewModel(ProtocolSource.Ftp, "FTP", ToggleEngineAsync));
        Tiles.Add(new EngineTileViewModel(ProtocolSource.Custom, "Custom", ToggleEngineAsync));
    }

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

    /// <summary>Pill caption.</summary>
    public string ConnectionText => IsConnected ? "Connected" : "Service not running";

    /// <summary>Applies a fresh status snapshot to the tiles and header.</summary>
    /// <param name="status">Status from the service.</param>
    public void UpdateStatus(ServiceStatusDto status)
    {
        VersionText = string.IsNullOrWhiteSpace(status.Version) ? string.Empty : "v" + status.Version;
        StartedText = status.StartedUtc == default
            ? string.Empty
            : "Started " + status.StartedUtc.ToLocalTime().ToString("g");
        TotalActiveBansText = status.ActiveBans.ToString();

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

        if (!prereqs.AuditLogonFailureEnabled)
        {
            Warnings.Add("Windows failed-logon auditing is disabled. Run: auditpol /set /subcategory:\"{0CCE9215-69AE-11D9-BED3-505054503030}\" /success:enable /failure:enable (the GUID form also works on localized Windows)");
        }

        if (!prereqs.FirewallServiceRunning)
        {
            Warnings.Add("The Windows Defender Firewall service (MpsSvc) is not running; blocks will not take effect.");
        }

        if (!prereqs.RdpCoreTsChannelEnabled)
        {
            Warnings.Add("The RdpCoreTS/Operational channel is unavailable; RDP TLS/NLA fallback detection is disabled.");
        }

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

    /// <summary>Launches an elevated <c>sc start WinGuardService</c> (the only elevated operation).</summary>
    [RelayCommand]
    private void StartService()
    {
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = "start " + Defaults.ServiceName,
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden,
            };
            Process.Start(startInfo);
            ServiceActionMessage = "Elevation requested — Windows will prompt to start the service.";
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
        }
        catch (Exception ex)
        {
            ServiceActionMessage = "Update failed: " + ex.Message;
        }
    }
}