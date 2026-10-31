using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using WinGuard.Core.Ipc;
using WinGuard.Core.Model;
using WinGuard.Gui.Services;

namespace WinGuard.Gui.ViewModels;

/// <summary>One engine in the legend and the breakdown; toggling it filters the charts.</summary>
public sealed partial class EngineBreakdown : ObservableObject
{
    private readonly Action _changed;

    /// <summary>Creates an entry.</summary>
    public EngineBreakdown(ProtocolSource source, string name, int slot, Action changed)
    {
        Source = source;
        Name = name;
        Slot = slot;
        _changed = changed;
    }

    /// <summary>The engine.</summary>
    public ProtocolSource Source { get; }

    /// <summary>Display name.</summary>
    public string Name { get; }

    /// <summary>Fixed chart colour: follows the engine, never its rank.</summary>
    public int Slot { get; }

    /// <summary>Whether the engine is drawn.</summary>
    [ObservableProperty]
    private bool _isOn = true;

    /// <summary>Detections in the window.</summary>
    [ObservableProperty]
    private string _detectionsText = "0";

    /// <summary>Bans in the window.</summary>
    [ObservableProperty]
    private string _bansText = "0";

    /// <summary>Share of all detections, 0..1.</summary>
    [ObservableProperty]
    private double _share;

    /// <summary>"42%".</summary>
    [ObservableProperty]
    private string _shareText = "0%";

    partial void OnIsOnChanged(bool value) => _changed();
}

/// <summary>A headline figure for the chosen range.</summary>
public sealed partial class StatTile : ObservableObject
{
    /// <summary>Creates a tile.</summary>
    public StatTile(string title) => Title = title;

    /// <summary>What the figure is.</summary>
    public string Title { get; }

    /// <summary>The figure.</summary>
    [ObservableProperty]
    private string _value = "–";

    /// <summary>A line of context.</summary>
    [ObservableProperty]
    private string _detail = string.Empty;

    /// <summary>What the figure means, when it means more than a count.</summary>
    [ObservableProperty]
    private Tone _tone = Tone.Neutral;
}

/// <summary>
/// Statistics view-model: per-day charts for a 7/30/90-day range, a per-engine breakdown that doubles
/// as a chart filter, the most persistent attackers and the append-only ban history. All data comes
/// from the service's ban-history and daily-statistics tables.
/// </summary>
public sealed partial class StatisticsViewModel : ObservableObject
{
    /// <summary>A logon from an address with failures or a ban; a history row, not a ban.</summary>
    public const string SuspiciousLogonAction = nameof(BanHistoryAction.SuspiciousLogon);

    private const int HistoryLimit = 500;

    private readonly PipeClient _client;
    private readonly ToastCenter _toasts;

    // Only the latest request may land: a slower answer for an old range must not overwrite a newer one.
    private int _loadVersion;
    private bool _hasData;
    private IReadOnlyList<DailyStatDto> _daily = [];
    private int _shownDays = 30;
    private DateTime _today = DateTime.Today;

    /// <summary>Creates the view-model.</summary>
    public StatisticsViewModel(PipeClient client, ToastCenter toasts)
    {
        _client = client;
        _toasts = toasts;
        Engines =
        [
            new EngineBreakdown(ProtocolSource.Rdp, SourceLabels.Rdp, 0, RebuildCharts),
            new EngineBreakdown(ProtocolSource.MsSql, SourceLabels.MsSql, 1, RebuildCharts),
            new EngineBreakdown(ProtocolSource.Ftp, SourceLabels.Ftp, 2, RebuildCharts),
            new EngineBreakdown(ProtocolSource.Custom, SourceLabels.Custom, 3, RebuildCharts),
        ];
    }

    /// <summary>Raised after fresh statistics arrive, so the dashboard can reuse them.</summary>
    public event Action<StatisticsDto>? Loaded;

    /// <summary>The four engines, in fixed order.</summary>
    public IReadOnlyList<EngineBreakdown> Engines { get; }

    /// <summary>Total detections tile.</summary>
    public StatTile DetectionsTile { get; } = new("Detections");

    /// <summary>Total bans tile.</summary>
    public StatTile BansTile { get; } = new("Bans");

    /// <summary>Busiest day tile.</summary>
    public StatTile PeakTile { get; } = new("Busiest day");

    /// <summary>Active bans tile.</summary>
    public StatTile ActiveTile { get; } = new("Active bans");

    /// <summary>Suspicious logons tile. They are rare, so a table row alone would bury them.</summary>
    public StatTile SuspiciousTile { get; } = new("Suspicious logons");

    /// <summary>Most-banned IPs.</summary>
    public ObservableCollection<TopOffenderRow> TopOffenders { get; } = [];

    /// <summary>Ban history rows, newest first.</summary>
    public ObservableCollection<BanHistoryRow> History { get; } = [];

    /// <summary>Detections per day, stacked by engine.</summary>
    [ObservableProperty]
    private ChartData _detectionsChart = ChartData.Empty;

    /// <summary>Bans per day, stacked by engine. A chart of its own: bans are far fewer than detections.</summary>
    [ObservableProperty]
    private ChartData _bansChart = ChartData.Empty;

    /// <summary>Selected chart window in days.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Is7Days))]
    [NotifyPropertyChangedFor(nameof(Is30Days))]
    [NotifyPropertyChangedFor(nameof(Is90Days))]
    private int _selectedDays = 30;

    /// <summary>True on the ban-history table; false on top offenders.</summary>
    [ObservableProperty]
    private bool _showHistory = true;

    /// <summary>Which shared state the page is in.</summary>
    [ObservableProperty]
    private ViewState _state = ViewState.Loading;

    /// <summary>Why statistics are unavailable.</summary>
    [ObservableProperty]
    private string _errorText = string.Empty;

    /// <summary>What the charts say, for screen readers.</summary>
    [ObservableProperty]
    private string _chartSummary = string.Empty;

    /// <summary>Whether the 7-day range is selected.</summary>
    public bool Is7Days
    {
        get => SelectedDays == 7;
        set
        {
            if (value)
            {
                SelectedDays = 7;
            }
        }
    }

    /// <summary>Whether the 30-day range is selected.</summary>
    public bool Is30Days
    {
        get => SelectedDays == 30;
        set
        {
            if (value)
            {
                SelectedDays = 30;
            }
        }
    }

    /// <summary>Whether the 90-day range is selected.</summary>
    public bool Is90Days
    {
        get => SelectedDays == 90;
        set
        {
            if (value)
            {
                SelectedDays = 90;
            }
        }
    }

    /// <summary>Loads (or reloads) the statistics from the service.</summary>
    [RelayCommand]
    public async Task LoadAsync()
    {
        var version = ++_loadVersion;
        var days = SelectedDays;
        if (!_hasData)
        {
            State = ViewState.Loading;
        }

        try
        {
            var statistics = await _client.GetStatisticsAsync(days);
            var history = await _client.ListBanHistoryAsync(HistoryLimit);
            if (version != _loadVersion)
            {
                return;
            }

            if (statistics is null)
            {
                SetDisconnected("Statistics come from the service, which is not answering.");
                return;
            }

            // The service buckets statistics by its local day.
            Apply(statistics, days, DateTime.Today);
            if (history is not null)
            {
                ApplyHistory(history);
            }

            Loaded?.Invoke(statistics);
        }
        catch (Exception ex)
        {
            if (version == _loadVersion)
            {
                if (_hasData)
                {
                    _toasts.Error("Could not refresh statistics", ex.Message);
                }
                else
                {
                    SetDisconnected(ex.Message);
                }
            }
        }
    }

    /// <summary>Marks the page unavailable; figures on hand stay visible.</summary>
    public void SetDisconnected(string reason)
    {
        if (!_hasData)
        {
            ErrorText = reason;
            State = ViewState.Error;
        }
    }

    /// <summary>Shows a loaded response.</summary>
    /// <param name="statistics">The response.</param>
    /// <param name="days">The range it was requested for.</param>
    /// <param name="todayUtc">Today, as the service counts days.</param>
    public void Apply(StatisticsDto statistics, int days, DateTime todayUtc)
    {
        _hasData = true;
        _daily = statistics.Daily;
        _shownDays = days;
        _today = todayUtc.Date;

        foreach (var engine in Engines)
        {
            var rows = statistics.Daily.Where(entry => entry.Source == engine.Source).ToList();
            engine.DetectionsText = rows.Sum(entry => entry.Detections).ToString("N0", CultureInfo.CurrentCulture);
            engine.BansText = rows.Sum(entry => entry.Bans).ToString("N0", CultureInfo.CurrentCulture);
        }

        var totalDetections = statistics.Daily.Sum(entry => (long)entry.Detections);
        foreach (var engine in Engines)
        {
            var count = statistics.Daily.Where(entry => entry.Source == engine.Source).Sum(entry => (long)entry.Detections);
            engine.Share = totalDetections == 0 ? 0 : count / (double)totalDetections;
            engine.ShareText = engine.Share.ToString("P0", CultureInfo.CurrentCulture);
        }

        var rowsForOffenders = statistics.TopOffenders.Select(offender => new TopOffenderRow(
            offender.IpAddress,
            offender.BanCount,
            offender.MaxOffense,
            TimeText.AsUtc(offender.LastSeenUtc),
            offender.LastSeenUtc == default ? "–" : TimeText.Full(offender.LastSeenUtc))).ToList();
        ReplaceIfChanged(TopOffenders, rowsForOffenders);

        ActiveTile.Value = statistics.TotalActiveBans.ToString("N0", CultureInfo.CurrentCulture);
        ActiveTile.Detail = $"{statistics.HistoryRows:N0} history rows kept";

        RebuildCharts();
        State = totalDetections == 0 && statistics.TopOffenders.Count == 0 && statistics.TotalActiveBans == 0 && History.Count == 0
            ? ViewState.Empty
            : ViewState.Ready;
    }

    /// <summary>Shows the ban history.</summary>
    public void ApplyHistory(IReadOnlyList<BanHistoryDto> history)
    {
        var rows = history.Select(row => new BanHistoryRow(
            TimeText.AsUtc(row.TimestampUtc),
            TimeText.Stamp(row.TimestampUtc),
            row.Action,
            ActionTone(row.Action),
            row.IpAddress,
            SourceLabels.For(row.Source),
            row.OffenseCount,
            row.DurationTicks ?? (row.IsPermanent ? long.MaxValue : 0),
            row.IsPermanent ? "Permanent" : row.DurationTicks is { } ticks ? DurationText.Format(new TimeSpan(ticks)) : "–",
            row.Note ?? string.Empty)).ToList();
        ReplaceIfChanged(History, rows);

        var since = _today.AddDays(-(_shownDays - 1));
        var suspicious = rows.Where(row => row.Action == SuspiciousLogonAction && TimeText.ToLocal(row.TimeUtc).Date >= since).ToList();
        SuspiciousTile.Value = suspicious.Count.ToString("N0", CultureInfo.CurrentCulture);
        SuspiciousTile.Tone = suspicious.Count > 0 ? Tone.Attack : Tone.Neutral;
        SuspiciousTile.Detail = suspicious.Count > 0
            ? $"Latest {TimeText.Ago(suspicious[0].TimeUtc, DateTime.UtcNow)}"
            : "None in this range";

        if (rows.Count > 0 && State == ViewState.Empty)
        {
            State = ViewState.Ready;
        }
    }

    partial void OnSelectedDaysChanged(int value) => _ = LoadAsync();

    private static Tone ActionTone(string action) => action switch
    {
        "Banned" or SuspiciousLogonAction => Tone.Attack,
        "Unbanned" => Tone.Protected,
        "Updated" => Tone.Accent,
        _ => Tone.Neutral,
    };

    private static void ReplaceIfChanged<T>(ObservableCollection<T> target, IReadOnlyList<T> rows)
    {
        // These tables refresh every 30 s; unchanged data must leave their selection and scroll alone.
        if (target.SequenceEqual(rows))
        {
            return;
        }

        target.Clear();
        foreach (var row in rows)
        {
            target.Add(row);
        }
    }

    /// <summary>Redraws from the loaded data for the engines switched on, with no round trip.</summary>
    private void RebuildCharts()
    {
        var days = _shownDays;
        var first = _today.AddDays(-(days - 1));

        // The service only stores days with activity. Every calendar day is plotted, so a quiet week
        // shows as a gap instead of vanishing and pulling its neighbours together.
        var heads = new string[days];
        var axis = new string[days];
        for (var i = 0; i < days; i++)
        {
            var day = first.AddDays(i);
            heads[i] = day.ToString("ddd d MMM", CultureInfo.CurrentCulture);
            axis[i] = day.ToString("d MMM", CultureInfo.CurrentCulture);
        }

        var shown = Engines.Where(engine => engine.IsOn).ToList();
        var detections = new List<ChartSeries>();
        var bans = new List<ChartSeries>();
        foreach (var engine in shown)
        {
            var detectionValues = new double[days];
            var banValues = new double[days];
            foreach (var entry in _daily.Where(entry => entry.Source == engine.Source))
            {
                var index = (entry.DayUtc.Date - first).Days;
                if (index >= 0 && index < days)
                {
                    detectionValues[index] += entry.Detections;
                    banValues[index] += entry.Bans;
                }
            }

            detections.Add(new ChartSeries(engine.Name, engine.Slot, detectionValues));
            bans.Add(new ChartSeries(engine.Name, engine.Slot, banValues));
        }

        DetectionsChart = new ChartData(heads, axis, detections);
        BansChart = new ChartData(heads, axis, bans);

        var detectionTotal = detections.Sum(series => series.Values.Sum());
        var banTotal = bans.Sum(series => series.Values.Sum());
        DetectionsTile.Value = detectionTotal.ToString("N0", CultureInfo.CurrentCulture);
        DetectionsTile.Detail = $"{detectionTotal / days:N1} a day";
        BansTile.Value = banTotal.ToString("N0", CultureInfo.CurrentCulture);
        BansTile.Detail = detectionTotal == 0 ? string.Empty : $"{detectionTotal / Math.Max(1, banTotal):N1} detections per ban";

        var peak = -1;
        var peakValue = 0d;
        for (var i = 0; i < days; i++)
        {
            var value = DetectionsChart.StackAt(i);
            if (value > peakValue)
            {
                peakValue = value;
                peak = i;
            }
        }

        PeakTile.Value = peak < 0 ? "–" : peakValue.ToString("N0", CultureInfo.CurrentCulture);
        PeakTile.Detail = peak < 0 ? "No detections in this range" : heads[peak];
        ChartSummary = $"{detectionTotal:N0} detections and {banTotal:N0} bans in the last {days} days. Use the left and right arrow keys to read each day.";
    }
}

/// <summary>One "most persistent attacker" row.</summary>
public sealed record TopOffenderRow(string IpAddress, int BanCount, int MaxOffense, DateTime LastSeenUtc, string LastSeenText);

/// <summary>One ban-history row; raw values are kept next to the text so columns sort properly.</summary>
public sealed record BanHistoryRow(
    DateTime TimeUtc,
    string TimeText,
    string Action,
    Tone Tone,
    string IpAddress,
    string SourceText,
    int OffenseCount,
    long DurationTicks,
    string Duration,
    string Note)
{
    /// <summary>The action as shown.</summary>
    public string ActionText => Action == StatisticsViewModel.SuspiciousLogonAction ? "Suspicious logon" : Action;
}
