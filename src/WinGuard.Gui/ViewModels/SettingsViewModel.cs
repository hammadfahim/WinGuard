using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using WinGuard.Core.Config;
using WinGuard.Gui.Services;

namespace WinGuard.Gui.ViewModels;

/// <summary>
/// Settings view-model (PLAN.md §9.4). Bound to a working copy of <see cref="WinGuardSettings"/>
/// fetched via GetSettings. Durations are edited as text and validated on save so invalid input
/// produces a clear message instead of a crash. All edits are pushed back with UpdateSettings.
/// </summary>
public sealed partial class SettingsViewModel : ObservableObject
{
    private readonly PipeClient _client;
    private WinGuardSettings _baseSettings = new();

    // Until the live settings have been fetched the editors show defaults; saving then would
    // overwrite the service's real configuration with them.
    private bool _loaded;

    /// <summary>Creates the view-model and seeds the ban-tier editor with the defaults.</summary>
    /// <param name="client">Pipe client used to load and save settings.</param>
    public SettingsViewModel(PipeClient client)
    {
        _client = client;
        SetTiers(["24:00:00", "7.00:00:00", "30.00:00:00"]);
    }

    /// <summary>FTP server kinds available in the sources grid.</summary>
    public static FtpServerKind[] FtpKinds { get; } = Enum.GetValues<FtpServerKind>();

    // ---- global engine ----

    /// <summary>Failed attempts before a ban (text).</summary>
    [ObservableProperty]
    private string _thresholdText = "5";

    /// <summary>Rolling count window, e.g. 00:10:00 (text).</summary>
    [ObservableProperty]
    private string _countWindowText = "00:10:00";

    /// <summary>Idle time before counters reset, e.g. 1.00:00:00 (text).</summary>
    [ObservableProperty]
    private string _expireTimeText = "1.00:00:00";

    /// <summary>Housekeeping cadence, e.g. 00:00:15 (text).</summary>
    [ObservableProperty]
    private string _housekeepingText = "00:00:15";

    /// <summary>Maximum ban duration cap, e.g. 365.00:00:00 (text).</summary>
    [ObservableProperty]
    private string _maxBanDurationText = "365.00:00:00";

    /// <summary>Flush firewall rules at service start.</summary>
    [ObservableProperty]
    private bool _clearBansOnStartup;

    /// <summary>Process private / loopback IPs instead of ignoring them.</summary>
    [ObservableProperty]
    private bool _processInternalIPs;

    /// <summary>Comma-separated ports to block; empty = all ports.</summary>
    [ObservableProperty]
    private string _blockedPortsText = string.Empty;

    /// <summary>Days of event history the service keeps (text).</summary>
    [ObservableProperty]
    private string _eventRetentionDaysText = "30";

    /// <summary>Editable escalation tiers (text rows).</summary>
    public ObservableCollection<StringRowViewModel> BanTiers { get; } = [];

    // ---- RDP ----

    /// <summary>RDP engine enabled.</summary>
    [ObservableProperty]
    private bool _rdpEnabled = true;

    /// <summary>Also use the RdpCoreTS/Operational 140 fallback.</summary>
    [ObservableProperty]
    private bool _rdpUseRdpCoreTsFallback = true;

    /// <summary>RDP threshold override (empty = global).</summary>
    [ObservableProperty]
    private string _rdpThresholdText = string.Empty;

    /// <summary>RDP count-window override (empty = global).</summary>
    [ObservableProperty]
    private string _rdpCountWindowText = string.Empty;

    /// <summary>RDP 4625 exclusion rules.</summary>
    public ObservableCollection<StringRowViewModel> RdpExclusions { get; } = [];

    // ---- MS SQL ----

    /// <summary>MS SQL engine enabled.</summary>
    [ObservableProperty]
    private bool _msSqlEnabled = true;

    /// <summary>MS SQL threshold override (empty = global).</summary>
    [ObservableProperty]
    private string _msSqlThresholdText = string.Empty;

    /// <summary>MS SQL count-window override (empty = global).</summary>
    [ObservableProperty]
    private string _msSqlCountWindowText = string.Empty;

    /// <summary>Substrings that mark an 18456 as non-bruteforce.</summary>
    public ObservableCollection<StringRowViewModel> MsSqlIgnorePatterns { get; } = [];

    // ---- FTP ----

    /// <summary>FTP engine enabled.</summary>
    [ObservableProperty]
    private bool _ftpEnabled = true;

    /// <summary>FTP threshold override (empty = global).</summary>
    [ObservableProperty]
    private string _ftpThresholdText = string.Empty;

    /// <summary>FTP count-window override (empty = global).</summary>
    [ObservableProperty]
    private string _ftpCountWindowText = string.Empty;

    /// <summary>FTP file-tail poll interval, e.g. 00:00:03 (text).</summary>
    [ObservableProperty]
    private string _ftpPollIntervalText = "00:00:03";

    /// <summary>FTP log sources.</summary>
    public ObservableCollection<FtpSourceRow> FtpSources { get; } = [];

    /// <summary>Selected FTP source row.</summary>
    [ObservableProperty]
    private FtpSourceRow? _selectedFtpSource;

    // ---- custom ----

    /// <summary>Custom log sources.</summary>
    public ObservableCollection<CustomSourceRow> CustomSources { get; } = [];

    /// <summary>Selected custom source row.</summary>
    [ObservableProperty]
    private CustomSourceRow? _selectedCustomSource;

    // ---- UI state ----

    /// <summary>User-visible validation error(s).</summary>
    [ObservableProperty]
    private string _errorMessage = string.Empty;

    /// <summary>User-visible status message.</summary>
    [ObservableProperty]
    private string _statusMessage = string.Empty;

    /// <summary>True while loading or saving.</summary>
    [ObservableProperty]
    private bool _isBusy;

    /// <summary>Fetches the live settings and populates the editors.</summary>
    public async Task LoadAsync()
    {
        IsBusy = true;
        try
        {
            var settings = await _client.GetSettingsAsync();
            if (settings is null)
            {
                StatusMessage = "Settings are unavailable: the service is not running.";
                return;
            }

            settings.Normalize();
            _baseSettings = settings;
            _loaded = true;
            PopulateFrom(settings);
            ErrorMessage = string.Empty;
            StatusMessage = "Settings loaded.";
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>Validates and pushes the working copy to the service.</summary>
    [RelayCommand]
    private async Task SaveAsync()
    {
        if (!_loaded)
        {
            ErrorMessage = "The current settings have not been loaded from the service yet. Press Reset to load them, then edit and save.";
            StatusMessage = string.Empty;
            return;
        }

        var errors = new List<string>();
        var settings = _baseSettings.Clone();

        if (!int.TryParse(EventRetentionDaysText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var retentionDays) || retentionDays is < 1 or > 3650)
        {
            errors.Add("Event history must be a whole number of days between 1 and 3650.");
        }

        if (!int.TryParse(ThresholdText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var threshold) || threshold < 1)
        {
            errors.Add("Failed login threshold must be a whole number >= 1.");
        }

        if (!TryParseDuration(CountWindowText, out var countWindow) || countWindow <= TimeSpan.Zero)
        {
            errors.Add("Count window must be a positive duration (e.g. 00:10:00).");
        }

        if (!TryParseDuration(ExpireTimeText, out var expireTime) || expireTime <= TimeSpan.Zero)
        {
            errors.Add("Expire time must be a positive duration (e.g. 1.00:00:00).");
        }

        if (!TryParseDuration(HousekeepingText, out var housekeeping) || housekeeping < TimeSpan.FromSeconds(1))
        {
            errors.Add("Housekeeping interval must be at least one second (e.g. 00:00:15).");
        }

        if (!TryParseDuration(MaxBanDurationText, out var maxBan) || maxBan <= TimeSpan.Zero)
        {
            errors.Add("Max ban duration must be a positive duration (e.g. 365.00:00:00).");
        }

        if (!TryParseDuration(FtpPollIntervalText, out var ftpPoll) || ftpPoll < TimeSpan.FromSeconds(1))
        {
            errors.Add("FTP poll interval must be at least one second (e.g. 00:00:03).");
        }

        var tiers = new List<TimeSpan>();
        for (var i = 0; i < BanTiers.Count; i++)
        {
            if (!TryParseDuration(BanTiers[i].Value, out var tier) || tier <= TimeSpan.Zero)
            {
                errors.Add($"Ban tier #{i + 1} is not a valid positive duration.");
            }
            else
            {
                tiers.Add(tier);
            }
        }

        if (tiers.Count == 0)
        {
            errors.Add("At least one ban tier is required.");
        }

        if (!TryParsePorts(BlockedPortsText, out var ports, out var portsError))
        {
            errors.Add(portsError!);
        }

        var rdpThreshold = ParseOptionalThreshold(RdpThresholdText, "RDP threshold", errors);
        var rdpWindow = ParseOptionalDuration(RdpCountWindowText, "RDP count window", errors);
        var msSqlThreshold = ParseOptionalThreshold(MsSqlThresholdText, "MS SQL threshold", errors);
        var msSqlWindow = ParseOptionalDuration(MsSqlCountWindowText, "MS SQL count window", errors);
        var ftpThreshold = ParseOptionalThreshold(FtpThresholdText, "FTP threshold", errors);
        var ftpWindow = ParseOptionalDuration(FtpCountWindowText, "FTP count window", errors);

        if (errors.Count > 0)
        {
            ErrorMessage = string.Join(Environment.NewLine, errors);
            StatusMessage = string.Empty;
            return;
        }

        settings.FailedLoginThreshold = threshold;
        settings.CountWindow = countWindow;
        settings.ExpireTime = expireTime;
        settings.HousekeepingInterval = housekeeping;
        settings.MaxBanDuration = maxBan;
        settings.ClearBansOnStartup = ClearBansOnStartup;
        settings.ProcessInternalIPs = ProcessInternalIPs;
        settings.EventRetentionDays = retentionDays;
        settings.BlockedPorts = ports;
        settings.BanTiers = tiers.ToArray();

        settings.Rdp.Enabled = RdpEnabled;
        settings.Rdp.UseRdpCoreTsFallback = RdpUseRdpCoreTsFallback;
        settings.Rdp.Threshold = rdpThreshold;
        settings.Rdp.CountWindow = rdpWindow;
        settings.Rdp.ExclusionRules = Collect(RdpExclusions);

        settings.MsSql.Enabled = MsSqlEnabled;
        settings.MsSql.Threshold = msSqlThreshold;
        settings.MsSql.CountWindow = msSqlWindow;
        settings.MsSql.IgnoreMessagePatterns = Collect(MsSqlIgnorePatterns);

        settings.Ftp.Enabled = FtpEnabled;
        settings.Ftp.Threshold = ftpThreshold;
        settings.Ftp.CountWindow = ftpWindow;
        settings.Ftp.PollInterval = ftpPoll;
        settings.Ftp.Sources = FtpSources
            .Where(row => !string.IsNullOrWhiteSpace(row.Name) || !string.IsNullOrWhiteSpace(row.Path))
            .Select(row => new FtpLogSource { Name = row.Name.Trim(), Kind = row.Kind, Path = row.Path.Trim() })
            .ToList();

        settings.CustomSources = CustomSources
            .Where(row => !string.IsNullOrWhiteSpace(row.Name) || !string.IsNullOrWhiteSpace(row.PathGlob) || !string.IsNullOrWhiteSpace(row.Regex))
            .Select(row => new CustomLogSource
            {
                Name = row.Name.Trim(),
                Enabled = row.Enabled,
                PathGlob = row.PathGlob.Trim(),
                Regex = row.Regex.Trim(),
            })
            .ToList();

        IsBusy = true;
        try
        {
            // Show what the service actually stored (it normalizes, e.g. caps very long durations).
            var saved = await _client.UpdateSettingsAsync(settings) ?? settings;
            saved.Normalize();
            _baseSettings = saved;
            PopulateFrom(saved);
            ErrorMessage = string.Empty;
            StatusMessage = "Settings saved.";
        }
        catch (Exception ex)
        {
            ErrorMessage = "Save failed: " + ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>Discards edits by re-fetching the live settings.</summary>
    [RelayCommand]
    private Task ResetAsync() => LoadAsync();

    /// <summary>Sets the default 24h / 7d / 30d escalation tiers.</summary>
    [RelayCommand]
    private void PresetTiersDefault() => SetTiers(["24:00:00", "7.00:00:00", "30.00:00:00"]);

    /// <summary>Sets a single 24-hour tier.</summary>
    [RelayCommand]
    private void PresetTiers24h() => SetTiers(["24:00:00"]);

    /// <summary>Sets a single 7-day tier.</summary>
    [RelayCommand]
    private void PresetTiers7d() => SetTiers(["7.00:00:00"]);

    /// <summary>Sets a single 30-day tier.</summary>
    [RelayCommand]
    private void PresetTiers30d() => SetTiers(["30.00:00:00"]);

    /// <summary>Adds an empty ban-tier row.</summary>
    [RelayCommand]
    private void AddTier() => BanTiers.Add(new StringRowViewModel("24:00:00"));

    /// <summary>Removes a ban-tier row.</summary>
    [RelayCommand]
    private void RemoveTier(StringRowViewModel? row)
    {
        if (row is not null)
        {
            BanTiers.Remove(row);
        }
    }

    /// <summary>Adds an empty RDP exclusion rule.</summary>
    [RelayCommand]
    private void AddExclusion() => RdpExclusions.Add(new StringRowViewModel(string.Empty));

    /// <summary>Removes an RDP exclusion rule.</summary>
    [RelayCommand]
    private void RemoveExclusion(StringRowViewModel? row)
    {
        if (row is not null)
        {
            RdpExclusions.Remove(row);
        }
    }

    /// <summary>Adds an empty MSSQL ignore pattern.</summary>
    [RelayCommand]
    private void AddIgnorePattern() => MsSqlIgnorePatterns.Add(new StringRowViewModel(string.Empty));

    /// <summary>Removes an MSSQL ignore pattern.</summary>
    [RelayCommand]
    private void RemoveIgnorePattern(StringRowViewModel? row)
    {
        if (row is not null)
        {
            MsSqlIgnorePatterns.Remove(row);
        }
    }

    /// <summary>Adds the IIS FTP log folders found on this machine that are not listed yet.</summary>
    [RelayCommand]
    private void DetectIisFtp()
    {
        var added = 0;
        try
        {
            var root = Environment.ExpandEnvironmentVariables(@"%SystemDrive%\inetpub\logs\LogFiles");
            if (System.IO.Directory.Exists(root))
            {
                foreach (var folder in System.IO.Directory.EnumerateDirectories(root, "FTPSVC*"))
                {
                    if (FtpSources.Any(row => string.Equals(row.Path.Trim(), folder, StringComparison.OrdinalIgnoreCase)))
                    {
                        continue;
                    }

                    FtpSources.Add(new FtpSourceRow { Name = "IIS " + System.IO.Path.GetFileName(folder), Kind = FtpServerKind.IisFtp, Path = folder });
                    added++;
                }
            }
        }
        catch (Exception ex)
        {
            ErrorMessage = "Could not look for IIS FTP logs: " + ex.Message;
            return;
        }

        StatusMessage = added > 0
            ? $"Added {added} IIS FTP log folder(s). Press Save settings to apply."
            : "No new IIS FTP log folders were found under %SystemDrive%\\inetpub\\logs\\LogFiles.";
    }

    /// <summary>Adds an FTP log source row.</summary>
    [RelayCommand]
    private void AddFtpSource()
    {
        var row = new FtpSourceRow();
        FtpSources.Add(row);
        SelectedFtpSource = row;
    }

    /// <summary>Removes the selected FTP log source row.</summary>
    [RelayCommand]
    private void RemoveFtpSource()
    {
        if (SelectedFtpSource is not null)
        {
            FtpSources.Remove(SelectedFtpSource);
            SelectedFtpSource = null;
        }
    }

    /// <summary>Adds a custom log source row.</summary>
    [RelayCommand]
    private void AddCustomSource()
    {
        var row = new CustomSourceRow();
        CustomSources.Add(row);
        SelectedCustomSource = row;
    }

    /// <summary>Removes the selected custom log source row.</summary>
    [RelayCommand]
    private void RemoveCustomSource()
    {
        if (SelectedCustomSource is not null)
        {
            CustomSources.Remove(SelectedCustomSource);
            SelectedCustomSource = null;
        }
    }

    private void PopulateFrom(WinGuardSettings settings)
    {
        ThresholdText = settings.FailedLoginThreshold.ToString(CultureInfo.InvariantCulture);
        CountWindowText = settings.CountWindow.ToString();
        ExpireTimeText = settings.ExpireTime.ToString();
        HousekeepingText = settings.HousekeepingInterval.ToString();
        MaxBanDurationText = settings.MaxBanDuration.ToString();
        ClearBansOnStartup = settings.ClearBansOnStartup;
        ProcessInternalIPs = settings.ProcessInternalIPs;
        EventRetentionDaysText = settings.EventRetentionDays.ToString(CultureInfo.InvariantCulture);
        BlockedPortsText = string.Join(", ", settings.BlockedPorts);

        SetTiers(settings.BanTiers.Select(tier => tier.ToString()));

        RdpEnabled = settings.Rdp.Enabled;
        RdpUseRdpCoreTsFallback = settings.Rdp.UseRdpCoreTsFallback;
        RdpThresholdText = settings.Rdp.Threshold?.ToString(CultureInfo.InvariantCulture) ?? string.Empty;
        RdpCountWindowText = settings.Rdp.CountWindow?.ToString() ?? string.Empty;
        Replace(RdpExclusions, settings.Rdp.ExclusionRules);

        MsSqlEnabled = settings.MsSql.Enabled;
        MsSqlThresholdText = settings.MsSql.Threshold?.ToString(CultureInfo.InvariantCulture) ?? string.Empty;
        MsSqlCountWindowText = settings.MsSql.CountWindow?.ToString() ?? string.Empty;
        Replace(MsSqlIgnorePatterns, settings.MsSql.IgnoreMessagePatterns);

        FtpEnabled = settings.Ftp.Enabled;
        FtpThresholdText = settings.Ftp.Threshold?.ToString(CultureInfo.InvariantCulture) ?? string.Empty;
        FtpCountWindowText = settings.Ftp.CountWindow?.ToString() ?? string.Empty;
        FtpPollIntervalText = settings.Ftp.PollInterval.ToString();
        FtpSources.Clear();
        foreach (var source in settings.Ftp.Sources)
        {
            FtpSources.Add(new FtpSourceRow { Name = source.Name, Kind = source.Kind, Path = source.Path });
        }

        CustomSources.Clear();
        foreach (var source in settings.CustomSources)
        {
            CustomSources.Add(new CustomSourceRow
            {
                Name = source.Name,
                Enabled = source.Enabled,
                PathGlob = source.PathGlob,
                Regex = source.Regex,
            });
        }
    }

    private void SetTiers(IEnumerable<string> values)
    {
        BanTiers.Clear();
        foreach (var value in values)
        {
            BanTiers.Add(new StringRowViewModel(value));
        }
    }

    private static void Replace(ObservableCollection<StringRowViewModel> target, IEnumerable<string> values)
    {
        target.Clear();
        foreach (var value in values)
        {
            target.Add(new StringRowViewModel(value));
        }
    }

    private static string[] Collect(IEnumerable<StringRowViewModel> rows) =>
        rows.Select(row => row.Value.Trim())
            .Where(value => value.Length > 0)
            .ToArray();

    private static int? ParseOptionalThreshold(string? text, string label, List<string> errors)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        if (!int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) || value < 1)
        {
            errors.Add($"{label} must be a whole number >= 1, or left empty for the global setting.");
            return null;
        }

        return value;
    }

    private static TimeSpan? ParseOptionalDuration(string? text, string label, List<string> errors)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        if (!TryParseDuration(text, out var value) || value <= TimeSpan.Zero)
        {
            errors.Add($"{label} must be a positive duration (e.g. 00:10:00), or left empty for the global setting.");
            return null;
        }

        return value;
    }

    private static bool TryParseDuration(string? text, out TimeSpan value)
    {
        value = default;
        return !string.IsNullOrWhiteSpace(text) &&
               TimeSpan.TryParse(text.Trim(), CultureInfo.InvariantCulture, out value);
    }

    private static bool TryParsePorts(string? text, out string[] ports, out string? error)
    {
        ports = [];
        error = null;
        if (string.IsNullOrWhiteSpace(text))
        {
            return true;
        }

        var parsed = new List<string>();
        foreach (var part in text.Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!int.TryParse(part, NumberStyles.Integer, CultureInfo.InvariantCulture, out var port) || port is < 1 or > 65535)
            {
                error = $"Blocked port '{part}' is not a valid port (1-65535).";
                return false;
            }

            parsed.Add(port.ToString(CultureInfo.InvariantCulture));
        }

        ports = parsed.ToArray();
        return true;
    }
}