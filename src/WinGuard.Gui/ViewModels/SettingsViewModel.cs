using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using WinGuard.Core.Config;
using WinGuard.Core.Ipc;
using WinGuard.Gui.Services;

namespace WinGuard.Gui.ViewModels;

/// <summary>One page of settings, with its entry in the side navigation.</summary>
public sealed partial class SettingsSection : ObservableObject
{
    /// <summary>Creates a section.</summary>
    public SettingsSection(string title, string glyph, string description, params SettingField[] fields)
    {
        Title = title;
        Glyph = glyph;
        Description = description;
        Fields = fields;
    }

    /// <summary>Heading.</summary>
    public string Title { get; }

    /// <summary>Icon.</summary>
    public string Glyph { get; }

    /// <summary>What lives here.</summary>
    public string Description { get; }

    /// <summary>The fields, in order.</summary>
    public IReadOnlyList<SettingField> Fields { get; }

    /// <summary>Whether the page body shows this section.</summary>
    [ObservableProperty]
    private bool _isShown;

    /// <summary>Whether the side navigation lists this section.</summary>
    [ObservableProperty]
    private bool _isListed = true;

    /// <summary>Whether a field differs from what was loaded.</summary>
    [ObservableProperty]
    private bool _isDirty;

    /// <summary>How many fields are invalid.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasErrors))]
    private int _errorCount;

    /// <summary>Whether a field is invalid.</summary>
    public bool HasErrors => ErrorCount > 0;

    /// <summary>Re-reads dirty and error state from the fields.</summary>
    public void Refresh()
    {
        IsDirty = Fields.Any(field => field.IsDirty);
        ErrorCount = Fields.Count(field => field.HasError);
    }
}

/// <summary>
/// Settings view-model (PLAN.md §9.4): sections with side navigation and search, a dirty-state bar with
/// Save and Discard, inline validation and friendly durations. Fields hold text and validate as they
/// change; <see cref="BuildSettings"/> turns them into the object pushed with UpdateSettings.
/// </summary>
public sealed partial class SettingsViewModel : ObservableObject
{
    private readonly PipeClient _client;
    private readonly ToastCenter _toasts;
    private WinGuardSettings _baseSettings = new();

    // Until the live settings have been fetched the editors show defaults; saving then would
    // overwrite the service's real configuration with them.
    private bool _loaded;
    private bool _applying;

    /// <summary>Creates the view-model.</summary>
    /// <param name="client">Pipe client used to load and save settings.</param>
    /// <param name="toasts">Where results are reported.</param>
    public SettingsViewModel(PipeClient client, ToastCenter toasts)
    {
        _client = client;
        _toasts = toasts;

        FtpSources = new FtpSourcesField(toasts);

        Sections =
        [
            new SettingsSection(
                "Detection", "", "When a failed login counts, and how many it takes.",
                Threshold, CountWindow, ExpireTime, BacklogReplay, ProcessInternalIps),
            new SettingsSection(
                "Ban policy", "", "What happens to an address once it crosses the threshold.",
                ReportOnly, BanTiers, MaxBanDuration, BlockedPorts, Ipv6Prefix),
            new SettingsSection(
                SourceLabels.Rdp, "", "Failed Windows logons from Security event 4625 and the RdpCoreTS log.",
                RdpEnabled, RdpFallback, RdpThreshold, RdpWindow, RdpExclusions),
            new SettingsSection(
                SourceLabels.MsSql, "", "Failed SQL Server logins from Application event 18456.",
                MsSqlEnabled, MsSqlThreshold, MsSqlWindow, MsSqlIgnore),
            new SettingsSection(
                SourceLabels.Ftp, "", "Failed logins read from IIS FTP and FileZilla logs.",
                FtpEnabled, FtpThreshold, FtpWindow, FtpPoll, FtpSources),
            new SettingsSection(
                "Custom sources", "", "Any other log, read with your own regex.",
                CustomSources),
            new SettingsSection(
                "Notifications", "", "Alerts when an attacker is blocked or unblocked. Opt-in and rate-limited.",
                NotificationsEnabled, WebhookUrl, TelegramToken, TelegramChat, SmtpHost, SmtpPort, SmtpTls, SmtpUser, SmtpPassword, SmtpFrom, SmtpTo, RateLimit, WindowsEventLog),
            new SettingsSection(
                "Service", "", "Housekeeping and limits. The defaults suit most servers.",
                Housekeeping, EventRetention, MaxAddressesPerRule, ClearBansOnStartup),
        ];

        foreach (var field in Sections.SelectMany(section => section.Fields))
        {
            field.Changed += OnFieldChanged;
        }

        _selectedSection = Sections[0];
        ApplySectionVisibility();
        Apply(new WinGuardSettings(), markLoaded: false);
    }

    /// <summary>The sections, in navigation order.</summary>
    public IReadOnlyList<SettingsSection> Sections { get; }

    // ---- detection ----

    /// <summary>Failed attempts before a ban.</summary>
    public NumberField Threshold { get; } = new("Failed-login threshold", "Failed attempts from one address before it is banned.", 1, 100_000);

    /// <summary>Rolling count window.</summary>
    public DurationField CountWindow { get; } = new("Count window", "Attempts older than this stop counting towards the threshold.", TimeSpan.FromSeconds(1));

    /// <summary>Idle time before counters reset.</summary>
    public DurationField ExpireTime { get; } = new("Forget after", "An address that stays quiet this long starts again from zero.", TimeSpan.FromSeconds(1));

    /// <summary>Minutes of event-log history replayed at service start.</summary>
    public NumberField BacklogReplay { get; } = new("Backlog replay (minutes)", "How far back the service re-reads the event logs when it starts, covering failures logged while it was stopped. 0 turns this off.", 0, 1440);

    /// <summary>Process private / loopback IPs.</summary>
    public ToggleField ProcessInternalIps { get; } = new("Process internal addresses", "Also count private, loopback and link-local addresses.", "Internal addresses can now be banned, including your own network. Make sure your management hosts are whitelisted.");

    // ---- ban policy ----

    /// <summary>Monitoring mode.</summary>
    public ToggleField ReportOnly { get; } = new("Report-only mode", "Count failures and record would-be bans, without touching the firewall. A safe way to trial thresholds on a production server.", "Nothing is being blocked. Recorded bans are enforced the moment this is switched off.");

    /// <summary>Escalation ladder.</summary>
    public BanTiersField BanTiers { get; } = new();

    /// <summary>Maximum ban duration.</summary>
    public DurationField MaxBanDuration { get; } = new("Longest ban", "Caps every timed tier. Permanent bans are not affected.", TimeSpan.FromSeconds(1));

    /// <summary>Ports to block.</summary>
    public TextField BlockedPorts { get; } = new("Blocked ports", "Leave empty to block every port, which is the cheapest rule. Otherwise a list such as 3389, 1433, 5000-5100.", "All ports", SettingChecks.PortsError);

    /// <summary>IPv6 aggregation.</summary>
    public NumberField Ipv6Prefix { get; } = new("IPv6 aggregate prefix", "0 bans single addresses. 64 bans the whole /64, so rotating addresses inside it cannot evade a ban. Allowed: 0, or 32 to 64.", 0, 64);

    // ---- RDP ----

    /// <summary>RDP engine enabled.</summary>
    public ToggleField RdpEnabled { get; } = new("Enabled", "Watch for failed Windows logons.");

    /// <summary>RdpCoreTS fallback.</summary>
    public ToggleField RdpFallback { get; } = new("Use the RdpCoreTS fallback", "Also read RdpCoreTS/Operational event 140, which sees TLS and NLA failures that 4625 misses.");

    /// <summary>RDP threshold override.</summary>
    public NumberField RdpThreshold { get; } = new("Threshold override", "Leave empty to use the global threshold.", 1, 100_000, optional: true, placeholder: "Global");

    /// <summary>RDP window override.</summary>
    public DurationField RdpWindow { get; } = new("Count window override", "Leave empty to use the global count window.", TimeSpan.FromSeconds(1), optional: true, placeholder: "Global");

    /// <summary>RDP exclusion rules.</summary>
    public StringListField RdpExclusions { get; } = new("Exclusion rules", "Failures matching a rule are ignored. Comma = AND within a rule, separate rows = OR, * is a wildcard, != negates.", "Add rule", "LogonType=2, TargetUserName=backup-*");

    // ---- MS SQL ----

    /// <summary>MS SQL engine enabled.</summary>
    public ToggleField MsSqlEnabled { get; } = new("Enabled", "Watch for failed SQL Server logins. Login auditing must include failed logins.");

    /// <summary>MS SQL threshold override.</summary>
    public NumberField MsSqlThreshold { get; } = new("Threshold override", "Leave empty to use the global threshold.", 1, 100_000, optional: true, placeholder: "Global");

    /// <summary>MS SQL window override.</summary>
    public DurationField MsSqlWindow { get; } = new("Count window override", "Leave empty to use the global count window.", TimeSpan.FromSeconds(1), optional: true, placeholder: "Global");

    /// <summary>MS SQL ignore patterns.</summary>
    public StringListField MsSqlIgnore { get; } = new("Ignore message patterns", "Failures whose message contains one of these texts are not brute force, and do not count.", "Add pattern", "Failed to open the explicitly specified database");

    // ---- FTP ----

    /// <summary>FTP engine enabled.</summary>
    public ToggleField FtpEnabled { get; } = new("Enabled", "Watch the FTP log sources below.");

    /// <summary>FTP threshold override.</summary>
    public NumberField FtpThreshold { get; } = new("Threshold override", "Leave empty to use the global threshold.", 1, 100_000, optional: true, placeholder: "Global");

    /// <summary>FTP window override.</summary>
    public DurationField FtpWindow { get; } = new("Count window override", "Leave empty to use the global count window.", TimeSpan.FromSeconds(1), optional: true, placeholder: "Global");

    /// <summary>File poll interval.</summary>
    public DurationField FtpPoll { get; } = new("Poll interval", "How often log files are read. Custom sources share this interval.", TimeSpan.FromSeconds(1));

    /// <summary>FTP log sources.</summary>
    public FtpSourcesField FtpSources { get; }

    // ---- custom ----

    /// <summary>Custom log sources.</summary>
    public CustomSourcesField CustomSources { get; } = new();

    // ---- notifications ----

    /// <summary>Master switch for outbound notifications.</summary>
    public ToggleField NotificationsEnabled { get; } = new("Send notifications", "Master switch for webhook, Telegram and e-mail. WinGuard only ever contacts the destinations below.");

    /// <summary>Webhook address.</summary>
    public TextField WebhookUrl { get; } = new("Webhook URL", "Receives a JSON POST for each event, for example a Slack or Teams incoming webhook.", "https://", SettingChecks.UrlError);

    /// <summary>Telegram token.</summary>
    public SecretField TelegramToken { get; } = new("Telegram bot token", "From @BotFather. Leave empty to turn Telegram off.");

    /// <summary>Telegram chat.</summary>
    public TextField TelegramChat { get; } = new("Telegram chat id", "The chat notifications go to.");

    /// <summary>SMTP relay host.</summary>
    public TextField SmtpHost { get; } = new("SMTP host", "Your mail relay. Leave empty to turn e-mail off.", "smtp.example.com");

    /// <summary>SMTP port.</summary>
    public NumberField SmtpPort { get; } = new("SMTP port", "Usually 25, 465 or 587.", 1, 65535);

    /// <summary>SMTP TLS.</summary>
    public ToggleField SmtpTls { get; } = new("Use TLS", "Encrypt the connection to the relay.");

    /// <summary>SMTP user.</summary>
    public TextField SmtpUser { get; } = new("SMTP username", "Leave empty for an anonymous relay.");

    /// <summary>SMTP password.</summary>
    public SecretField SmtpPassword { get; } = new("SMTP password", "Stored in the settings database, which only SYSTEM and Administrators can read.");

    /// <summary>SMTP sender.</summary>
    public TextField SmtpFrom { get; } = new("From address", "Who the mail appears to come from.", "winguard@example.com");

    /// <summary>SMTP recipient.</summary>
    public TextField SmtpTo { get; } = new("To address", "Who receives the mail.", "admin@example.com");

    /// <summary>Notification rate limit.</summary>
    public NumberField RateLimit { get; } = new("Rate limit (per minute)", "The most notifications sent per minute across all channels, so an attack cannot flood them.", 1, 1000);

    /// <summary>Windows Event Log output.</summary>
    public ToggleField WindowsEventLog { get; } = new("Write to the Windows Event Log", "Record events under the WinGuard source in the Application log, for SIEM and Windows Event Forwarding.");

    // ---- service ----

    /// <summary>Housekeeping cadence.</summary>
    public DurationField Housekeeping { get; } = new("Housekeeping interval", "How often expired bans are lifted and the firewall is reconciled.", TimeSpan.FromSeconds(1));

    /// <summary>Event retention.</summary>
    public NumberField EventRetention { get; } = new("Event history (days)", "How long entries stay in the Event Log.", 1, 3650);

    /// <summary>Addresses per firewall rule.</summary>
    public NumberField MaxAddressesPerRule { get; } = new("Addresses per firewall rule", "WinGuard batches into numbered rules automatically. Windows' practical limit is 1000.", 1, 1000);

    /// <summary>Flush at startup.</summary>
    public ToggleField ClearBansOnStartup { get; } = new("Clear all bans on service start", "Flush firewall rules at start instead of reconciling them.", "Every active ban is lifted each time the service starts.");

    // ---- page state ----

    /// <summary>The section shown in the page body.</summary>
    [ObservableProperty]
    private SettingsSection _selectedSection;

    /// <summary>Search over every field.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsSearching))]
    private string _searchText = string.Empty;

    /// <summary>Whether anything differs from what was loaded.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanSave))]
    [NotifyPropertyChangedFor(nameof(DirtyText))]
    [NotifyCanExecuteChangedFor(nameof(SaveCommand))]
    [NotifyCanExecuteChangedFor(nameof(DiscardCommand))]
    private bool _isDirty;

    /// <summary>How many fields are invalid.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanSave))]
    [NotifyPropertyChangedFor(nameof(DirtyText))]
    [NotifyPropertyChangedFor(nameof(HasErrors))]
    [NotifyCanExecuteChangedFor(nameof(SaveCommand))]
    private int _errorCount;

    /// <summary>Which shared state the page is in.</summary>
    [ObservableProperty]
    private ViewState _state = ViewState.Loading;

    /// <summary>Why the settings are unavailable.</summary>
    [ObservableProperty]
    private string _errorText = string.Empty;

    /// <summary>True while saving.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanSave))]
    [NotifyCanExecuteChangedFor(nameof(SaveCommand))]
    private bool _isSaving;

    /// <summary>The service's settings changed while there were unsaved edits here.</summary>
    [ObservableProperty]
    private bool _remoteChangePending;

    /// <summary>Whether the search box holds text.</summary>
    public bool IsSearching => !string.IsNullOrWhiteSpace(SearchText);

    /// <summary>Whether a field is invalid.</summary>
    public bool HasErrors => ErrorCount > 0;

    /// <summary>Whether Save is available.</summary>
    public bool CanSave => IsDirty && ErrorCount == 0 && !IsSaving && _loaded;

    /// <summary>The message on the dirty bar.</summary>
    public string DirtyText
    {
        get
        {
            if (ErrorCount > 0)
            {
                return ErrorCount == 1 ? "Fix 1 problem to save" : $"Fix {ErrorCount} problems to save";
            }

            var sections = Sections?.Count(section => section.IsDirty) ?? 0;
            return sections <= 1 ? "Unsaved changes" : $"Unsaved changes in {sections} sections";
        }
    }

    /// <summary>
    /// Fetches the live settings. Unsaved edits are never overwritten: a reload that arrives while the
    /// page is dirty (a reconnect, or an engine toggled on the dashboard) only raises a notice.
    /// </summary>
    public async Task LoadAsync()
    {
        if (!_loaded)
        {
            State = ViewState.Loading;
        }

        var settings = await _client.GetSettingsAsync();
        if (settings is null)
        {
            SetDisconnected("Settings come from the service, which is not answering.");
            return;
        }

        if (IsDirty)
        {
            RemoteChangePending = true;
            return;
        }

        Apply(settings);
    }

    /// <summary>Marks the page unavailable; settings on hand stay visible.</summary>
    public void SetDisconnected(string reason)
    {
        if (!_loaded)
        {
            ErrorText = reason;
            State = ViewState.Error;
        }
    }

    /// <summary>Shows loaded settings and treats them as the clean state.</summary>
    public void Apply(WinGuardSettings settings, bool markLoaded = true)
    {
        settings.Normalize();
        _baseSettings = settings;
        _applying = true;

        Threshold.Set(settings.FailedLoginThreshold);
        CountWindow.Set(settings.CountWindow);
        ExpireTime.Set(settings.ExpireTime);
        BacklogReplay.Set(settings.EventBacklogReplayMinutes);
        ProcessInternalIps.IsOn = settings.ProcessInternalIPs;

        ReportOnly.IsOn = settings.ReportOnly;
        BanTiers.Set(settings.BanTiers);
        MaxBanDuration.Set(settings.MaxBanDuration);
        BlockedPorts.Text = string.Join(", ", settings.BlockedPorts);
        Ipv6Prefix.Set(settings.Ipv6AggregatePrefixLength);

        RdpEnabled.IsOn = settings.Rdp.Enabled;
        RdpFallback.IsOn = settings.Rdp.UseRdpCoreTsFallback;
        RdpThreshold.Set(settings.Rdp.Threshold);
        RdpWindow.Set(settings.Rdp.CountWindow);
        RdpExclusions.Set(settings.Rdp.ExclusionRules);

        MsSqlEnabled.IsOn = settings.MsSql.Enabled;
        MsSqlThreshold.Set(settings.MsSql.Threshold);
        MsSqlWindow.Set(settings.MsSql.CountWindow);
        MsSqlIgnore.Set(settings.MsSql.IgnoreMessagePatterns);

        FtpEnabled.IsOn = settings.Ftp.Enabled;
        FtpThreshold.Set(settings.Ftp.Threshold);
        FtpWindow.Set(settings.Ftp.CountWindow);
        FtpPoll.Set(settings.Ftp.PollInterval);
        FtpSources.Set(settings.Ftp.Sources);

        CustomSources.Set(settings.CustomSources);

        var notifications = settings.Notifications;
        var smtp = notifications.Smtp ?? new SmtpSettings();
        NotificationsEnabled.IsOn = notifications.Enabled;
        WebhookUrl.Text = notifications.WebhookUrl ?? string.Empty;
        TelegramToken.Text = notifications.TelegramBotToken ?? string.Empty;
        TelegramChat.Text = notifications.TelegramChatId ?? string.Empty;
        SmtpHost.Text = smtp.Host ?? string.Empty;
        SmtpPort.Set(smtp.Port > 0 ? smtp.Port : 25);
        SmtpTls.IsOn = smtp.EnableSsl;
        SmtpUser.Text = smtp.Username ?? string.Empty;
        SmtpPassword.Text = smtp.Password ?? string.Empty;
        SmtpFrom.Text = smtp.From ?? string.Empty;
        SmtpTo.Text = smtp.To ?? string.Empty;
        RateLimit.Set(notifications.RateLimitPerMinute);
        WindowsEventLog.IsOn = notifications.WriteToWindowsEventLog;

        Housekeeping.Set(settings.HousekeepingInterval);
        EventRetention.Set(settings.EventRetentionDays);
        MaxAddressesPerRule.Set(settings.MaxAddressesPerRule);
        ClearBansOnStartup.IsOn = settings.ClearBansOnStartup;

        foreach (var field in Sections.SelectMany(section => section.Fields))
        {
            field.MarkClean();
        }

        _applying = false;
        if (markLoaded)
        {
            _loaded = true;
            RemoteChangePending = false;
            State = ViewState.Ready;
        }

        RefreshState();
    }

    /// <summary>Turns the fields into the settings to push. Only call while there are no errors.</summary>
    public WinGuardSettings BuildSettings()
    {
        var settings = _baseSettings.Clone();

        settings.FailedLoginThreshold = Threshold.Number ?? settings.FailedLoginThreshold;
        settings.CountWindow = CountWindow.Duration ?? settings.CountWindow;
        settings.ExpireTime = ExpireTime.Duration ?? settings.ExpireTime;
        settings.EventBacklogReplayMinutes = BacklogReplay.Number ?? settings.EventBacklogReplayMinutes;
        settings.ProcessInternalIPs = ProcessInternalIps.IsOn;

        settings.ReportOnly = ReportOnly.IsOn;
        settings.BanTiers = BanTiers.Values;
        settings.MaxBanDuration = MaxBanDuration.Duration ?? settings.MaxBanDuration;
        settings.BlockedPorts = SettingChecks.SplitPorts(BlockedPorts.Value);
        settings.Ipv6AggregatePrefixLength = Ipv6Prefix.Number ?? 0;

        settings.Rdp.Enabled = RdpEnabled.IsOn;
        settings.Rdp.UseRdpCoreTsFallback = RdpFallback.IsOn;
        settings.Rdp.Threshold = RdpThreshold.Number;
        settings.Rdp.CountWindow = RdpWindow.Duration;
        settings.Rdp.ExclusionRules = RdpExclusions.Values;

        settings.MsSql.Enabled = MsSqlEnabled.IsOn;
        settings.MsSql.Threshold = MsSqlThreshold.Number;
        settings.MsSql.CountWindow = MsSqlWindow.Duration;
        settings.MsSql.IgnoreMessagePatterns = MsSqlIgnore.Values;

        settings.Ftp.Enabled = FtpEnabled.IsOn;
        settings.Ftp.Threshold = FtpThreshold.Number;
        settings.Ftp.CountWindow = FtpWindow.Duration;
        settings.Ftp.PollInterval = FtpPoll.Duration ?? settings.Ftp.PollInterval;
        settings.Ftp.Sources = FtpSources.Rows
            .Where(row => !string.IsNullOrWhiteSpace(row.Name) || !string.IsNullOrWhiteSpace(row.Path))
            .Select(row => new FtpLogSource { Name = row.Name.Trim(), Kind = row.Kind, Path = row.Path.Trim() })
            .ToList();

        settings.CustomSources = CustomSources.Rows
            .Where(row => !string.IsNullOrWhiteSpace(row.Name) || !string.IsNullOrWhiteSpace(row.PathGlob) || !string.IsNullOrWhiteSpace(row.Regex))
            .Select(row => new CustomLogSource
            {
                Name = row.Name.Trim(),
                Enabled = row.Enabled,
                PathGlob = row.PathGlob.Trim(),
                Regex = row.Regex.Trim(),
            })
            .ToList();

        settings.Notifications = new NotificationSettings
        {
            Enabled = NotificationsEnabled.IsOn,
            WebhookUrl = WebhookUrl.Value,
            TelegramBotToken = TelegramToken.Value,
            TelegramChatId = TelegramChat.Value,
            RateLimitPerMinute = RateLimit.Number ?? settings.Notifications.RateLimitPerMinute,
            WriteToWindowsEventLog = WindowsEventLog.IsOn,
            Smtp = new SmtpSettings
            {
                Host = SmtpHost.Value,
                Port = SmtpPort.Number ?? 25,
                EnableSsl = SmtpTls.IsOn,
                Username = SmtpUser.Text,
                Password = SmtpPassword.Text,
                From = SmtpFrom.Value,
                To = SmtpTo.Value,
            },
        };

        settings.HousekeepingInterval = Housekeeping.Duration ?? settings.HousekeepingInterval;
        settings.EventRetentionDays = EventRetention.Number ?? settings.EventRetentionDays;
        settings.MaxAddressesPerRule = MaxAddressesPerRule.Number ?? settings.MaxAddressesPerRule;
        settings.ClearBansOnStartup = ClearBansOnStartup.IsOn;
        return settings;
    }

    /// <summary>Saves; returns whether the settings are now saved, for the leave-page prompt.</summary>
    public async Task<bool> TrySaveAsync()
    {
        if (!_loaded)
        {
            _toasts.Warning("Settings not loaded yet", "Connect to the service, then edit and save.");
            return false;
        }

        if (ErrorCount > 0)
        {
            ShowFirstProblem();
            return false;
        }

        var settings = BuildSettings();

        // The same rules the service applies, caught before the round trip.
        var problems = SettingsValidator.Validate(settings);
        if (problems.Count > 0)
        {
            _toasts.Error("Settings not saved", problems[0]);
            return false;
        }

        IsSaving = true;
        try
        {
            // Show what the service actually stored (it normalizes, e.g. caps very long durations).
            var saved = await _client.UpdateSettingsAsync(settings) ?? settings;
            Apply(saved);
            _toasts.Success("Settings saved", "The service is using them now.");
            return true;
        }
        catch (Exception ex)
        {
            _toasts.Error("Save failed", ex.Message);
            return false;
        }
        finally
        {
            IsSaving = false;
        }
    }

    /// <summary>Opens a section by title.</summary>
    public void Show(string title)
    {
        SearchText = string.Empty;
        var section = Sections.FirstOrDefault(candidate => candidate.Title == title);
        if (section is not null)
        {
            SelectedSection = section;
        }
    }

    /// <summary>Validates and pushes the working copy to the service.</summary>
    [RelayCommand(CanExecute = nameof(CanSave))]
    private Task SaveAsync() => TrySaveAsync();

    /// <summary>Throws away edits and shows the service's current settings.</summary>
    [RelayCommand(CanExecute = nameof(IsDirty))]
    public async Task DiscardAsync()
    {
        // Restores at once from what was loaded: a dead pipe must not leave Discard hanging on a
        // connect timeout. The service's copy follows, and only lands if nothing was edited since.
        Apply(_baseSettings);
        _toasts.Info("Changes discarded");

        if (_client.IsConnected && await _client.GetSettingsAsync() is { } settings && !IsDirty)
        {
            Apply(settings);
        }
    }

    /// <summary>Loads again after a failure.</summary>
    [RelayCommand]
    private Task ReloadAsync() => LoadAsync();

    partial void OnSearchTextChanged(string value) => ApplySectionVisibility();

    partial void OnSelectedSectionChanged(SettingsSection value)
    {
        // While searching every matching section is on screen, so picking one means "go there".
        if (IsSearching)
        {
            SearchText = string.Empty;
        }
        else
        {
            ApplySectionVisibility();
        }
    }

    private void OnFieldChanged()
    {
        if (!_applying)
        {
            RefreshState();
        }
    }

    private void RefreshState()
    {
        foreach (var section in Sections)
        {
            section.Refresh();
        }

        IsDirty = Sections.Any(section => section.IsDirty);
        ErrorCount = Sections.Sum(section => section.ErrorCount);
        OnPropertyChanged(nameof(DirtyText));
        OnPropertyChanged(nameof(CanSave));
        SaveCommand.NotifyCanExecuteChanged();
        DiscardCommand.NotifyCanExecuteChanged();
    }

    private void ShowFirstProblem()
    {
        var section = Sections.FirstOrDefault(candidate => candidate.HasErrors);
        if (section is not null)
        {
            SearchText = string.Empty;
            SelectedSection = section;
        }
    }

    private void ApplySectionVisibility()
    {
        var query = SearchText?.Trim() ?? string.Empty;
        foreach (var section in Sections)
        {
            if (query.Length == 0)
            {
                foreach (var field in section.Fields)
                {
                    field.IsShown = true;
                }

                section.IsListed = true;
                section.IsShown = ReferenceEquals(section, SelectedSection);
                continue;
            }

            var titleMatches = section.Title.Contains(query, StringComparison.OrdinalIgnoreCase);
            foreach (var field in section.Fields)
            {
                field.IsShown = titleMatches || field.Matches(query);
            }

            section.IsListed = section.Fields.Any(field => field.IsShown);
            section.IsShown = section.IsListed;
        }
    }
}
