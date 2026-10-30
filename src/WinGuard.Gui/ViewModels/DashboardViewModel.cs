using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using WinGuard.Core.Config;
using WinGuard.Core.Ipc;
using WinGuard.Core.Model;
using WinGuard.Gui.Services;

namespace WinGuard.Gui.ViewModels;

/// <summary>One headline number. A tile is also a link to the page behind the number.</summary>
public sealed partial class KpiTile : ObservableObject
{
    /// <summary>Creates a tile.</summary>
    public KpiTile(string title, string glyph)
    {
        Title = title;
        Glyph = glyph;
    }

    /// <summary>What the number is.</summary>
    public string Title { get; }

    /// <summary>Icon.</summary>
    public string Glyph { get; }

    /// <summary>The number.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(AccessibleName))]
    private string _value = "–";

    /// <summary>A line of context.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(AccessibleName))]
    private string _detail = string.Empty;

    /// <summary>Recent trend, oldest first; null hides it.</summary>
    [ObservableProperty]
    private IReadOnlyList<double>? _trend;

    /// <summary>What a screen reader announces.</summary>
    public string AccessibleName => $"{Title}: {Value}. {Detail}";
}

/// <summary>One row of the recent-blocks feed.</summary>
public sealed partial class RecentBlockRow : ObservableObject
{
    private readonly DateTime _bannedUtc;

    /// <summary>Creates a row.</summary>
    public RecentBlockRow(BanDto dto)
    {
        IpAddress = dto.IpAddress;
        SourceText = SourceLabels.For(dto.Source);
        OffenseText = dto.OffenseCount <= 1 ? "1st offense" : Ordinal(dto.OffenseCount) + " offense";
        IsPermanent = dto.IsPermanent || dto.ExpiresUtc == DateTime.MaxValue;
        _bannedUtc = TimeText.AsUtc(dto.BannedAtUtc);
        Tick(DateTime.UtcNow);
    }

    /// <summary>Blocked address or prefix.</summary>
    public string IpAddress { get; }

    /// <summary>Engine that caught it.</summary>
    public string SourceText { get; }

    /// <summary>"3rd offense".</summary>
    public string OffenseText { get; }

    /// <summary>Whether the ban never expires.</summary>
    public bool IsPermanent { get; }

    /// <summary>"4m ago".</summary>
    [ObservableProperty]
    private string _agoText = string.Empty;

    /// <summary>Re-reads the relative time.</summary>
    public void Tick(DateTime nowUtc) => AgoText = TimeText.Ago(_bannedUtc, nowUtc);

    private static string Ordinal(int n) => (n % 100) switch
    {
        11 or 12 or 13 => n + "th",
        _ => (n % 10) switch
        {
            1 => n + "st",
            2 => n + "nd",
            3 => n + "rd",
            _ => n + "th",
        },
    };
}

/// <summary>One row of the top-attackers list.</summary>
/// <param name="IpAddress">Attacker.</param>
/// <param name="BanCount">How many times it was banned.</param>
/// <param name="Fraction">Share of the largest count, for the bar.</param>
/// <param name="LastSeenText">When it last appeared.</param>
public sealed record TopAttackerRow(string IpAddress, int BanCount, double Fraction, string LastSeenText)
{
    /// <summary>"12 bans".</summary>
    public string BanText => BanCount == 1 ? "1 ban" : $"{BanCount:N0} bans";
}

/// <summary>A small fact under the hero status.</summary>
/// <param name="Text">The fact.</param>
/// <param name="Tone">Its meaning.</param>
public sealed record StatusFact(string Text, Tone Tone);

/// <summary>
/// Dashboard view-model (PLAN.md §9.1): the protection hero, KPI tiles, a live activity chart,
/// engine tiles that link to their events, the recent-blocks feed and the top attackers.
/// </summary>
public sealed partial class DashboardViewModel : ObservableObject
{
    private const int RecentBlockCount = 6;
    private const int TopAttackerCount = 5;
    private const int TrendDays = 14;

    private readonly PipeClient _client;
    private readonly ToastCenter _toasts;
    private readonly DialogCenter _dialogs;
    private readonly LiveActivityTracker _activity = new(60);
    private readonly HashSet<long> _countedBlocks = [];

    private int _enginesEnabled;
    private int _enginesRunning;
    private int _activeBans;
    private bool? _firewallRunning;
    private DateTime? _lastBlockUtc;
    private IReadOnlyList<BanDto> _bans = [];

    /// <summary>Creates the dashboard view-model.</summary>
    /// <param name="client">Pipe client used for settings updates.</param>
    /// <param name="toasts">Where results are reported.</param>
    /// <param name="dialogs">Where disabling an engine is confirmed.</param>
    public DashboardViewModel(PipeClient client, ToastCenter toasts, DialogCenter dialogs)
    {
        _client = client;
        _toasts = toasts;
        _dialogs = dialogs;

        Tiles.Add(new EngineTileViewModel(ProtocolSource.Rdp, SourceLabels.Rdp, "", SourceLabels.Rdp, ToggleEngineAsync));
        Tiles.Add(new EngineTileViewModel(ProtocolSource.MsSql, SourceLabels.MsSql, "", SourceLabels.MsSql, ToggleEngineAsync));
        Tiles.Add(new EngineTileViewModel(ProtocolSource.Ftp, SourceLabels.Ftp, "", SourceLabels.Ftp, ToggleEngineAsync));
        Tiles.Add(new EngineTileViewModel(ProtocolSource.Custom, SourceLabels.Custom, "", "Custom sources", ToggleEngineAsync));

        ActiveBansKpi = new KpiTile("Active bans", "");
        DetectionsKpi = new KpiTile("Detections today", "");
        BansTodayKpi = new KpiTile("Blocks today", "");
        RepeatKpi = new KpiTile("Repeat offenders", "");

        Evaluate();
        RebuildActivity();
    }

    /// <summary>Raised after this view changed the service settings (so other views can reload them).</summary>
    public event Action? SettingsChanged;

    /// <summary>Asks the shell to open the Blocked IPs page; the text, when given, is searched for.</summary>
    public event Action<string?>? ShowBansRequested;

    /// <summary>Asks the shell to open the Event Log filtered to one engine.</summary>
    public event Action<ProtocolSource>? ShowEngineRequested;

    /// <summary>Asks the shell to open the Statistics page.</summary>
    public event Action? ShowStatisticsRequested;

    /// <summary>Asks the shell to open a Settings section.</summary>
    public event Action<string>? ShowSettingsRequested;

    /// <summary>The four per-protocol tiles.</summary>
    public ObservableCollection<EngineTileViewModel> Tiles { get; } = [];

    /// <summary>The newest blocks.</summary>
    public ObservableCollection<RecentBlockRow> RecentBlocks { get; } = [];

    /// <summary>The most persistent attackers.</summary>
    public ObservableCollection<TopAttackerRow> TopAttackers { get; } = [];

    /// <summary>Prerequisite warnings from <see cref="PrereqsDto"/>.</summary>
    public ObservableCollection<string> Warnings { get; } = [];

    /// <summary>Facts under the hero: firewall, auditing, engines.</summary>
    public ObservableCollection<StatusFact> Facts { get; } = [];

    /// <summary>Active bans tile.</summary>
    public KpiTile ActiveBansKpi { get; }

    /// <summary>Detections today tile.</summary>
    public KpiTile DetectionsKpi { get; }

    /// <summary>Blocks today tile.</summary>
    public KpiTile BansTodayKpi { get; }

    /// <summary>Repeat offenders tile.</summary>
    public KpiTile RepeatKpi { get; }

    /// <summary>Per-minute activity for the last hour.</summary>
    [ObservableProperty]
    private ChartData _liveActivity = ChartData.Empty;

    /// <summary>Summary of the live chart, for screen readers and the caption.</summary>
    [ObservableProperty]
    private string _liveSummary = string.Empty;

    /// <summary>The overall state.</summary>
    [ObservableProperty]
    private ProtectionSummary _protection = new(ProtectionKind.Connecting, Tone.Neutral, "", "Connecting", "Looking for the WinGuard service.");

    /// <summary>The hero's supporting line.</summary>
    [ObservableProperty]
    private string _heroLine = string.Empty;

    /// <summary>Shown when the service speaks a different IPC version than this GUI.</summary>
    [ObservableProperty]
    private string _versionMismatchText = string.Empty;

    /// <summary>Whether the service pipe is connected.</summary>
    [ObservableProperty]
    private bool _isConnected;

    /// <summary>The first connection attempt is over.</summary>
    [ObservableProperty]
    private bool _connectionSettled;

    /// <summary>
    /// Why the service cannot be used although it is running (for example: it refused this
    /// console). Empty when the service is simply not running, or when everything is fine.
    /// </summary>
    [ObservableProperty]
    private string _connectionProblem = string.Empty;

    /// <summary>Whether any prerequisite warnings exist.</summary>
    [ObservableProperty]
    private bool _hasWarnings;

    /// <summary>Whether the recent-blocks feed has entries.</summary>
    [ObservableProperty]
    private bool _hasRecentBlocks;

    /// <summary>Whether any attacker is known.</summary>
    [ObservableProperty]
    private bool _hasTopAttackers;

    /// <summary>Service version text (e.g. "Service 0.2.0").</summary>
    [ObservableProperty]
    private string _versionText = string.Empty;

    /// <summary>Service start time in local time.</summary>
    [ObservableProperty]
    private string _startedText = string.Empty;

    /// <summary>True when the service runs in report-only (monitoring) mode.</summary>
    [ObservableProperty]
    private bool _reportOnly;

    /// <summary>True while the service is being started.</summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(StartServiceCommand))]
    private bool _isStartingService;

    /// <summary>Applies a fresh status snapshot to the tiles and header.</summary>
    /// <param name="status">Status from the service.</param>
    public void UpdateStatus(ServiceStatusDto status)
    {
        var now = DateTime.UtcNow;
        VersionText = string.IsNullOrWhiteSpace(status.Version) ? string.Empty : "Service " + status.Version;
        StartedText = status.StartedUtc == default ? string.Empty : "Running since " + TimeText.Full(status.StartedUtc);
        ReportOnly = status.ReportOnly;
        VersionMismatchText = status.ProtocolVersion == PipeConstants.ProtocolVersion
            ? string.Empty
            : "The service and this console are from different WinGuard versions; some features may not work. Reinstall so both match.";

        foreach (var engine in status.Engines)
        {
            Tiles.FirstOrDefault(t => t.Source == engine.Source)?.Update(engine);
        }

        _activeBans = status.ActiveBans;
        _enginesEnabled = status.Engines.Count(engine => engine.Enabled);
        _enginesRunning = status.Engines.Count(engine => engine.Enabled && engine.Running);

        var detections = status.Engines.Sum(engine => (long)engine.DetectionsToday);
        ActiveBansKpi.Value = status.ActiveBans.ToString("N0", CultureInfo.CurrentCulture);
        DetectionsKpi.Value = detections.ToString("N0", CultureInfo.CurrentCulture);

        if (_activity.Sample(now, detections))
        {
            RebuildActivity();
        }

        DetectionsKpi.Detail = $"{_activity.DetectionsLastHour:N0} in the last hour";
        Evaluate();
        TickTimes(now);
    }

    /// <summary>Applies prerequisite check results.</summary>
    /// <param name="prereqs">Result of CheckPrereqs.</param>
    public void UpdatePrereqs(PrereqsDto prereqs)
    {
        _firewallRunning = prereqs.FirewallServiceRunning;

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

        Facts.Clear();
        Facts.Add(new StatusFact(prereqs.FirewallServiceRunning ? "Windows Firewall on" : "Windows Firewall off", prereqs.FirewallServiceRunning ? Tone.Protected : Tone.Attack));
        Facts.Add(new StatusFact(prereqs.AuditLogonFailureEnabled ? "Logon auditing on" : "Logon auditing off", prereqs.AuditLogonFailureEnabled ? Tone.Protected : Tone.Warn));
        Evaluate();
    }

    /// <summary>Counts new blocks into the live chart.</summary>
    /// <param name="events">Events from the poller, oldest first.</param>
    public void AddEvents(IReadOnlyList<EventDto> events)
    {
        var now = DateTime.UtcNow;
        var changed = false;
        foreach (var dto in events)
        {
            // The cursor can legitimately hand a row over twice after a store reset.
            if (EventRowViewModel.IsBlock(dto) && _countedBlocks.Add(dto.Id))
            {
                changed |= _activity.AddBlock(TimeText.AsUtc(dto.TimestampUtc), now);
            }
        }

        if (changed)
        {
            RebuildActivity();
        }

        if (_countedBlocks.Count > 4096)
        {
            _countedBlocks.Clear();
        }
    }

    /// <summary>Refreshes everything derived from the ban list.</summary>
    /// <param name="bans">Fresh ban DTOs.</param>
    public void UpdateBans(IReadOnlyList<BanDto> bans)
    {
        _bans = bans;
        var ordered = bans.OrderByDescending(ban => TimeText.AsUtc(ban.BannedAtUtc)).ToList();
        _lastBlockUtc = ordered.Count == 0 ? null : TimeText.AsUtc(ordered[0].BannedAtUtc);

        var newest = ordered.Take(RecentBlockCount).ToList();
        var same = newest.Count == RecentBlocks.Count
            && newest.Zip(RecentBlocks).All(pair => pair.First.IpAddress == pair.Second.IpAddress);
        if (!same)
        {
            RecentBlocks.Clear();
            foreach (var ban in newest)
            {
                RecentBlocks.Add(new RecentBlockRow(ban));
            }
        }

        HasRecentBlocks = RecentBlocks.Count > 0;

        var permanent = bans.Count(ban => ban.IsPermanent || ban.ExpiresUtc == DateTime.MaxValue);
        ActiveBansKpi.Detail = permanent == 0 ? "All expire on their own" : $"{permanent:N0} permanent";

        var repeat = bans.Count(ban => ban.OffenseCount > 1);
        RepeatKpi.Value = repeat.ToString("N0", CultureInfo.CurrentCulture);
        RepeatKpi.Detail = bans.Count == 0 ? "None banned right now" : $"of {bans.Count:N0} active bans";
        Evaluate();
    }

    /// <summary>Applies the statistics the Statistics page just loaded.</summary>
    /// <param name="statistics">The loaded statistics.</param>
    public void UpdateStatistics(StatisticsDto statistics)
    {
        var today = DateTime.UtcNow.Date;
        var byDay = statistics.Daily
            .GroupBy(entry => entry.DayUtc.Date)
            .ToDictionary(group => group.Key, group => (double)group.Sum(entry => entry.Bans));

        var trend = new double[TrendDays];
        for (var i = 0; i < TrendDays; i++)
        {
            trend[i] = byDay.GetValueOrDefault(today.AddDays(i - TrendDays + 1));
        }

        var todayBans = (long)trend[^1];
        BansTodayKpi.Value = todayBans.ToString("N0", CultureInfo.CurrentCulture);
        BansTodayKpi.Detail = $"{trend.Sum() - todayBans:N0} in the previous {TrendDays - 1} days";
        BansTodayKpi.Trend = trend;

        var top = statistics.TopOffenders.Take(TopAttackerCount).ToList();
        var most = Math.Max(1, top.Count == 0 ? 1 : top.Max(offender => offender.BanCount));
        var rows = top.Select(offender => new TopAttackerRow(
            offender.IpAddress,
            offender.BanCount,
            offender.BanCount / (double)most,
            offender.LastSeenUtc == default ? string.Empty : TimeText.Ago(offender.LastSeenUtc, DateTime.UtcNow))).ToList();

        if (!rows.SequenceEqual(TopAttackers))
        {
            TopAttackers.Clear();
            foreach (var row in rows)
            {
                TopAttackers.Add(row);
            }
        }

        HasTopAttackers = TopAttackers.Count > 0;
    }

    partial void OnIsConnectedChanged(bool value)
    {
        if (!value)
        {
            _firewallRunning = null;
        }

        Evaluate();
    }

    partial void OnConnectionProblemChanged(string value) => Evaluate();

    partial void OnConnectionSettledChanged(bool value) => Evaluate();

    /// <summary>Opens the Blocked IPs page.</summary>
    [RelayCommand]
    private void OpenBans(string? search) => ShowBansRequested?.Invoke(search);

    /// <summary>Opens the Event Log on one engine.</summary>
    [RelayCommand]
    private void OpenEngine(EngineTileViewModel? tile)
    {
        if (tile is not null)
        {
            ShowEngineRequested?.Invoke(tile.Source);
        }
    }

    /// <summary>Opens the Statistics page.</summary>
    [RelayCommand]
    private void OpenStatistics() => ShowStatisticsRequested?.Invoke();

    /// <summary>Opens a Settings section.</summary>
    [RelayCommand]
    private void OpenSettings(string? section) => ShowSettingsRequested?.Invoke(section ?? string.Empty);

    /// <summary>Opens the setting behind the current state.</summary>
    [RelayCommand]
    private void ReviewState() =>
        ShowSettingsRequested?.Invoke(Protection.Kind == ProtectionKind.ReportOnly ? "Ban policy" : SourceLabels.Rdp);

    private bool CanStartService() => !IsStartingService;

    /// <summary>Runs <c>sc start WinGuardService</c> (this console already runs elevated) and reports the outcome.</summary>
    [RelayCommand(CanExecute = nameof(CanStartService))]
    private async Task StartServiceAsync()
    {
        IsStartingService = true;
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
                    _toasts.Success("Connected to the service");
                    return;
                }
            }

            switch (exitCode)
            {
                case 0:
                    _toasts.Info("Service start requested", "It connects within a few seconds.");
                    break;
                case 1056:
                    _toasts.Warning("Already running", "If this console still cannot connect, the reason is in the banner. The service log is in %ProgramData%\\WinGuard\\Logs.");
                    break;
                case 1060:
                    _toasts.Error("Service not installed", "Run the installer, or winguard-svc.exe --install.");
                    break;
                default:
                    _toasts.Error("Could not start the service", $"sc.exe exit code {exitCode}.");
                    break;
            }
        }
        catch (Exception ex)
        {
            _toasts.Error("Could not start the service", ex.Message);
        }
        finally
        {
            IsStartingService = false;
        }
    }

    private void TickTimes(DateTime now)
    {
        foreach (var row in RecentBlocks)
        {
            row.Tick(now);
        }

        HeroLine = BuildHeroLine(now);
    }

    private string BuildHeroLine(DateTime now)
    {
        if (!IsConnected)
        {
            return string.Empty;
        }

        var parts = new List<string> { DescribeBans(_activeBans, Protection.Kind) };
        if (_lastBlockUtc is { } last)
        {
            parts.Add((Protection.Kind == ProtectionKind.ReportOnly ? "last recorded " : "last block ") + TimeText.Ago(last, now));
        }

        return string.Join(" · ", parts);
    }

    /// <summary>
    /// Words the ban count truthfully. "Blocked" is only true while the firewall enforces bans: in
    /// report-only they are merely recorded, and with the firewall off they do nothing.
    /// </summary>
    private static string DescribeBans(int count, ProtectionKind kind) => kind switch
    {
        ProtectionKind.ReportOnly => count == 1 ? "1 ban recorded, not enforced" : $"{count:N0} bans recorded, not enforced",
        ProtectionKind.FirewallOff => count == 1 ? "1 ban not in force" : $"{count:N0} bans not in force",
        _ => count == 1 ? "1 address blocked" : $"{count:N0} addresses blocked",
    };

    private void Evaluate()
    {
        Protection = ProtectionEvaluator.Evaluate(new ProtectionInputs(
            IsConnected,
            ConnectionSettled,
            string.IsNullOrEmpty(ConnectionProblem) ? null : ConnectionProblem,
            ReportOnly,
            _firewallRunning,
            _enginesEnabled,
            _enginesRunning,
            _activeBans));

        // The line below the headline depends on the state, so a change of state must reword it.
        HeroLine = BuildHeroLine(DateTime.UtcNow);
    }

    private void RebuildActivity()
    {
        var count = _activity.Minutes;
        var newest = _activity.NewestMinute == default ? DateTime.UtcNow : _activity.NewestMinute;
        var heads = new string[count];
        var axis = new string[count];
        for (var i = 0; i < count; i++)
        {
            var minute = TimeText.ToLocal(DateTime.SpecifyKind(newest.AddMinutes(i - count + 1), DateTimeKind.Utc));
            heads[i] = minute.ToString("t", CultureInfo.CurrentCulture);
            axis[i] = i == count - 1 ? "now" : $"-{count - 1 - i}m";
        }

        LiveActivity = new ChartData(
            heads,
            axis,
            [new ChartSeries("Detections", 0, _activity.Detections.ToArray())],
            new ChartSeries("Blocks", 0, _activity.Blocks.ToArray()));

        LiveSummary = $"{_activity.DetectionsLastHour:N0} detections and {_activity.Blocks.Sum():N0} blocks in the last hour";
    }

    private async Task ToggleEngineAsync(EngineTileViewModel tile, bool enabled)
    {
        if (!enabled && !await _dialogs.ConfirmAsync(
                Tone.Attack,
                $"Disable the {tile.Name} engine?",
                "WinGuard stops watching this engine's logs, so attacks on it go unnoticed. Existing bans stay in force.",
                "Disable engine"))
        {
            tile.Revert(true);
            return;
        }

        var settings = await _client.GetSettingsAsync();
        if (settings is null)
        {
            tile.Revert(!enabled);
            _toasts.Error("Cannot change settings", "The service is not running.");
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
                    tile.Revert(!enabled);
                    _toasts.Info("No custom log sources yet", "Add one under Settings, Custom sources.");
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
            _toasts.Success($"{tile.Name} engine {(enabled ? "enabled" : "disabled")}");
            SettingsChanged?.Invoke();
        }
        catch (Exception ex)
        {
            tile.Revert(!enabled);
            _toasts.Error("Update failed", ex.Message);
        }
    }
}
