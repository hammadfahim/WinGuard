using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using WinGuard.Core.Ipc;
using WinGuard.Core.Model;

namespace WinGuard.Gui.ViewModels;

/// <summary>
/// Statistics view-model: per-day activity chart (last N days), per-protocol totals, the most
/// persistent attackers and the append-only ban history. All data comes from the service's
/// ban-history and daily-statistics tables via the statistics IPC call.
/// </summary>
public sealed partial class StatisticsViewModel : ObservableObject
{
    private readonly PipeClient _client;

    /// <summary>Chart plot height in (logical) pixels; bar heights scale against it.</summary>
    private const int ChartHeight = 90;

    /// <summary>Creates the view-model.</summary>
    public StatisticsViewModel(PipeClient client)
    {
        _client = client;
    }

    /// <summary>One bar group per day: detections (accent) and bans (error color).</summary>
    public ObservableCollection<StatDayRow> Days { get; } = [];

    /// <summary>Per-protocol totals over the window.</summary>
    public ObservableCollection<StatSourceRow> Sources { get; } = [];

    /// <summary>Most-banned IPs over the history window.</summary>
    public ObservableCollection<TopOffenderRow> TopOffenders { get; } = [];

    /// <summary>Ban history rows, newest first.</summary>
    public ObservableCollection<BanHistoryRow> History { get; } = [];

    /// <summary>Selectable chart windows (days).</summary>
    public ObservableCollection<int> DayOptions { get; } = [7, 30, 90];

    /// <summary>Selected chart window in days.</summary>
    [ObservableProperty]
    private int _selectedDays = 30;

    /// <summary>Summary line ("1 234 detections · 45 bans since …").</summary>
    [ObservableProperty]
    private string _summaryText = string.Empty;

    /// <summary>User-visible status.</summary>
    [ObservableProperty]
    private string _statusMessage = string.Empty;

    /// <summary>True while loading.</summary>
    [ObservableProperty]
    private bool _isBusy;

    /// <summary>Loads (or reloads) the statistics from the service.</summary>
    [RelayCommand]
    public async Task LoadAsync()
    {
        if (IsBusy)
        {
            return;
        }

        IsBusy = true;
        try
        {
            var statistics = await _client.GetStatisticsAsync(SelectedDays);
            if (statistics is null)
            {
                StatusMessage = "Statistics are unavailable: the service is not running.";
                return;
            }

            Populate(statistics);
            StatusMessage = string.Empty;
        }
        catch (Exception ex)
        {
            StatusMessage = "Could not load statistics: " + ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>Reload when the window size changes.</summary>
    partial void OnSelectedDaysChanged(int value) => _ = LoadAsync();

    private void Populate(StatisticsDto statistics)
    {
        // ---- per-day chart ----
        var byDay = statistics.Daily
            .GroupBy(entry => entry.DayUtc.Date)
            .OrderBy(group => group.Key)
            .ToList();

        var max = Math.Max(1, byDay.Count == 0 ? 1 : byDay.Max(group => group.Sum(entry => entry.Detections)));
        Days.Clear();
        var showEvery = Math.Max(1, (int)Math.Ceiling(byDay.Count / 30.0));
        for (var index = 0; index < byDay.Count; index++)
        {
            var group = byDay[index];
            var detections = group.Sum(entry => entry.Detections);
            var bans = group.Sum(entry => entry.Bans);
            Days.Add(new StatDayRow(
                group.Key,
                detections,
                bans,
                DetectionBar: (int)Math.Round(ChartHeight * detections / (double)max),
                BanBar: (int)Math.Round(ChartHeight * bans / (double)max),
                Label: index % showEvery == 0 ? group.Key.ToString("MM-dd", CultureInfo.InvariantCulture) : string.Empty));
        }

        // ---- per-source totals ----
        var bySource = statistics.Daily
            .GroupBy(entry => entry.Source)
            .OrderBy(group => (int)group.Key);
        Sources.Clear();
        foreach (var group in bySource)
        {
            Sources.Add(new StatSourceRow(
                SourceLabels.For(group.Key),
                group.Sum(entry => entry.Detections),
                group.Sum(entry => entry.Bans)));
        }

        // ---- top offenders ----
        TopOffenders.Clear();
        foreach (var offender in statistics.TopOffenders)
        {
            TopOffenders.Add(new TopOffenderRow(
                offender.IpAddress,
                offender.BanCount,
                offender.MaxOffense,
                offender.LastSeenUtc == DateTime.MinValue ? "—" : offender.LastSeenUtc.ToLocalTime().ToString("g", CultureInfo.InvariantCulture)));
        }

        // ---- history ----
        // The history list comes from a dedicated call so it can show more rows than the DTO carries.
        _ = LoadHistoryAsync();

        var totalDetections = statistics.Daily.Sum(entry => entry.Detections);
        var totalBans = statistics.Daily.Sum(entry => entry.Bans);
        var since = DateTime.UtcNow.Date.AddDays(-(SelectedDays - 1)).ToLocalTime().ToString("d", CultureInfo.InvariantCulture);
        SummaryText = $"{totalDetections.ToString("N0", CultureInfo.InvariantCulture)} detections · " +
                      $"{totalBans.ToString("N0", CultureInfo.InvariantCulture)} bans · {statistics.TotalActiveBans} active ban(s) · since {since} · " +
                      $"{statistics.HistoryRows.ToString("N0", CultureInfo.InvariantCulture)} history rows kept";
    }

    private async Task LoadHistoryAsync()
    {
        try
        {
            var history = await _client.ListBanHistoryAsync(100);
            History.Clear();
            if (history is null)
            {
                return;
            }

            foreach (var row in history)
            {
                History.Add(new BanHistoryRow(
                    row.TimestampUtc.ToLocalTime().ToString("g", CultureInfo.InvariantCulture),
                    row.Action,
                    row.IpAddress,
                    SourceLabels.For(row.Source),
                    row.OffenseCount,
                    row.IsPermanent ? "permanent" : row.DurationTicks is { } ticks ? new TimeSpan(ticks).ToString("d\\.hh\\:mm\\:ss", CultureInfo.InvariantCulture) : "—",
                    row.Note));
            }
        }
        catch (Exception)
        {
            // The chart is still useful without history rows.
        }
    }
}

/// <summary>One day of the chart: bar heights pre-scaled by the view-model.</summary>
public sealed record StatDayRow(DateTime Day, int Detections, int Bans, int DetectionBar, int BanBar, string Label)
{
    /// <summary>Tooltip text.</summary>
    public string ToolTipText => $"{Day:yyyy-MM-dd}: {Detections} detections, {Bans} bans";
}

/// <summary>Per-protocol totals over the window.</summary>
public sealed record StatSourceRow(string Source, int Detections, int Bans);

/// <summary>One "most persistent attacker" row.</summary>
public sealed record TopOffenderRow(string IpAddress, int BanCount, int MaxOffense, string LastSeenText);

/// <summary>One ban-history row (display-formatted).</summary>
public sealed record BanHistoryRow(string TimeText, string Action, string IpAddress, string SourceText, int OffenseCount, string Duration, string? Note);
