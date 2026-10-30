using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Engine;
using WinGuard.Core.Firewall;
using WinGuard.Core.Ipc;
using WinGuard.Core.Model;
using WinGuard.Core.Monitoring;
using WinGuard.Core.Tests.Fakes;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>The metrics file: its format, how it gets to disk, and that none of it can hurt the engine.</summary>
public sealed class PrometheusTextfileTests : IDisposable
{
    private static readonly DateTimeOffset T0 = new(2026, 3, 1, 12, 0, 0, TimeSpan.Zero);

    private readonly string _folder = Path.Combine(Path.GetTempPath(), "winguard-metrics-" + Guid.NewGuid().ToString("N"));

    public PrometheusTextfileTests() => Directory.CreateDirectory(_folder);

    public void Dispose() => Directory.Delete(_folder, recursive: true);

    private string Target => Path.Combine(_folder, "winguard.prom");

    private static MetricsSnapshot Snapshot(int activeBans = 3, int? firewallRules = 2) => new(
        T0.UtcDateTime,
        activeBans,
        [
            new EngineMetrics("rdp", true, 12, 2),
            new EngineMetrics("mssql", false, 0, 0),
            new EngineMetrics("manual", null, 0, 1),
        ],
        firewallRules,
        ReportOnly: false,
        Disarmed: true,
        NotificationsEnabled: true,
        SyslogEnabled: false);

    private sealed class RecordingLogger : ILogger
    {
        private readonly List<string> _warnings = [];

        public List<string> Warnings
        {
            get
            {
                lock (_warnings)
                {
                    return _warnings.ToList();
                }
            }
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (logLevel == LogLevel.Warning)
            {
                lock (_warnings)
                {
                    _warnings.Add(formatter(state, exception));
                }
            }
        }
    }

    // ---- the format ----

    [Fact]
    public void The_file_is_the_prometheus_text_format()
    {
        var expected = string.Join('\n',
            "# HELP winguard_active_bans Bans currently in force.",
            "# TYPE winguard_active_bans gauge",
            "winguard_active_bans 3",
            "# HELP winguard_engine_active_bans Bans currently in force, by the engine that caused them.",
            "# TYPE winguard_engine_active_bans gauge",
            "winguard_engine_active_bans{engine=\"rdp\"} 2",
            "winguard_engine_active_bans{engine=\"mssql\"} 0",
            "winguard_engine_active_bans{engine=\"manual\"} 1",
            "# HELP winguard_engine_detections_today Failed logins seen today, by engine; starts again at midnight.",
            "# TYPE winguard_engine_detections_today gauge",
            "winguard_engine_detections_today{engine=\"rdp\"} 12",
            "winguard_engine_detections_today{engine=\"mssql\"} 0",
            "winguard_engine_detections_today{engine=\"manual\"} 0",
            "# HELP winguard_engine_enabled 1 when the engine is enabled.",
            "# TYPE winguard_engine_enabled gauge",
            "winguard_engine_enabled{engine=\"rdp\"} 1",
            "winguard_engine_enabled{engine=\"mssql\"} 0",
            "# HELP winguard_firewall_rules WinGuard rules in the Windows firewall.",
            "# TYPE winguard_firewall_rules gauge",
            "winguard_firewall_rules 2",
            "# HELP winguard_last_housekeeping_timestamp_seconds Unix time of the last housekeeping pass.",
            "# TYPE winguard_last_housekeeping_timestamp_seconds gauge",
            "winguard_last_housekeeping_timestamp_seconds 1772366400",
            "# HELP winguard_report_only 1 in report-only mode: bans are recorded, not enforced.",
            "# TYPE winguard_report_only gauge",
            "winguard_report_only 0",
            "# HELP winguard_disarmed 1 during a break-glass window: nothing is enforced.",
            "# TYPE winguard_disarmed gauge",
            "winguard_disarmed 1",
            "# HELP winguard_notifications_enabled 1 when notifications are enabled.",
            "# TYPE winguard_notifications_enabled gauge",
            "winguard_notifications_enabled 1",
            "# HELP winguard_syslog_enabled 1 when syslog output is enabled.",
            "# TYPE winguard_syslog_enabled gauge",
            "winguard_syslog_enabled 0",
            string.Empty);

        Assert.Equal(expected, PrometheusTextfileWriter.Format(Snapshot()));
    }

    [Fact]
    public void A_rule_count_that_is_not_known_is_left_out_not_reported_as_zero()
    {
        Assert.DoesNotContain("winguard_firewall_rules", PrometheusTextfileWriter.Format(Snapshot(firewallRules: null)));
    }

    [Fact]
    public void Each_metric_family_is_declared_exactly_once()
    {
        var types = PrometheusTextfileWriter.Format(Snapshot())
            .Split('\n')
            .Where(line => line.StartsWith("# TYPE ", StringComparison.Ordinal))
            .ToList();

        Assert.Equal(types.Count, types.Distinct().Count());
    }

    // ---- getting it to disk ----

    [Fact]
    public async Task The_file_ends_in_a_line_feed_with_no_bom_and_no_carriage_return()
    {
        var writer = new PrometheusTextfileWriter(NullLogger.Instance);

        writer.Publish(Snapshot(), Target);
        await writer.FlushAsync();

        var bytes = await File.ReadAllBytesAsync(Target);
        Assert.Equal((byte)'#', bytes[0]);
        Assert.Equal((byte)'\n', bytes[^1]);
        Assert.DoesNotContain((byte)'\r', bytes);
    }

    [Fact]
    public async Task A_new_snapshot_replaces_the_file_and_leaves_nothing_else_behind()
    {
        var writer = new PrometheusTextfileWriter(NullLogger.Instance);

        writer.Publish(Snapshot(activeBans: 1), Target);
        await writer.FlushAsync();
        writer.Publish(Snapshot(activeBans: 7), Target);
        await writer.FlushAsync();

        Assert.Contains("winguard_active_bans 7\n", await File.ReadAllTextAsync(Target));
        Assert.Equal([Target], Directory.GetFileSystemEntries(_folder));
    }

    [Fact]
    public async Task The_newest_snapshot_wins_when_several_arrive_at_once()
    {
        var writer = new PrometheusTextfileWriter(NullLogger.Instance);

        for (var bans = 0; bans <= 100; bans++)
        {
            writer.Publish(Snapshot(activeBans: bans), Target);
        }

        await writer.FlushAsync();

        Assert.Contains("winguard_active_bans 100\n", await File.ReadAllTextAsync(Target));
    }

    [Fact]
    public async Task A_folder_that_does_not_exist_is_logged_once_and_not_created()
    {
        var logger = new RecordingLogger();
        var writer = new PrometheusTextfileWriter(logger);
        var missing = Path.Combine(_folder, "missing");
        var path = Path.Combine(missing, "winguard.prom");

        for (var pass = 0; pass < 3; pass++)
        {
            writer.Publish(Snapshot(), path);
            await writer.FlushAsync();
        }

        Assert.Single(logger.Warnings);
        Assert.False(Directory.Exists(missing));
    }

    [Fact]
    public async Task A_network_path_that_got_into_the_settings_is_never_touched()
    {
        var logger = new RecordingLogger();
        var writer = new PrometheusTextfileWriter(logger);

        writer.Publish(Snapshot(), @"\\attacker.invalid\share\winguard.prom");
        await writer.FlushAsync();

        Assert.Contains("network", Assert.Single(logger.Warnings));
    }

    [Fact]
    public async Task A_file_the_collector_holds_open_fails_one_pass_and_the_next_one_works()
    {
        var logger = new RecordingLogger();
        var writer = new PrometheusTextfileWriter(logger);
        writer.Publish(Snapshot(activeBans: 1), Target);
        await writer.FlushAsync();

        using (new FileStream(Target, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            writer.Publish(Snapshot(activeBans: 2), Target);
            await writer.FlushAsync();
        }

        Assert.Single(logger.Warnings);
        Assert.Contains("winguard_active_bans 1\n", await File.ReadAllTextAsync(Target));
        Assert.Equal([Target], Directory.GetFileSystemEntries(_folder));

        writer.Publish(Snapshot(activeBans: 3), Target);
        await writer.FlushAsync();

        Assert.Contains("winguard_active_bans 3\n", await File.ReadAllTextAsync(Target));
    }

    [Fact]
    public async Task A_problem_that_comes_back_after_a_success_is_reported_again()
    {
        var logger = new RecordingLogger();
        var writer = new PrometheusTextfileWriter(logger);
        var missing = Path.Combine(_folder, "missing", "winguard.prom");

        writer.Publish(Snapshot(), missing);
        await writer.FlushAsync();
        writer.Publish(Snapshot(), Target);
        await writer.FlushAsync();
        writer.Publish(Snapshot(), missing);
        await writer.FlushAsync();

        Assert.Equal(2, logger.Warnings.Count);
    }

    [Fact]
    public async Task A_target_that_is_a_folder_is_a_logged_failure()
    {
        var logger = new RecordingLogger();
        var writer = new PrometheusTextfileWriter(logger);
        Directory.CreateDirectory(Target);

        writer.Publish(Snapshot(), Target);
        await writer.FlushAsync();

        Assert.Single(logger.Warnings);
        Assert.Equal([Target], Directory.GetFileSystemEntries(_folder));
    }

    // ---- the path ----

    [Theory]
    [InlineData(@"C:\Program Files\windows_exporter\textfile_inputs\winguard.prom")]
    [InlineData(@"C:\metrics\WINGUARD.PROM")]
    [InlineData(@"""C:\metrics\winguard.prom""")]
    [InlineData(@"%SystemDrive%\metrics\winguard.prom")]
    public void Local_prom_files_are_accepted(string path)
    {
        Assert.Null(PrometheusTextfileWriter.PathProblem(path));
    }

    [Theory]
    [InlineData(@"\\server\share\winguard.prom", "network")]
    [InlineData("//server/share/winguard.prom", "network")]
    [InlineData(@"\??\C:\winguard.prom", "network")]
    [InlineData(@"\\.\pipe\winguard.prom", "network")]
    [InlineData(@"\\?\C:\winguard.prom", "network")]
    [InlineData(@"winguard.prom", "full path")]
    [InlineData(@"metrics\winguard.prom", "full path")]
    [InlineData(@"C:winguard.prom", "full path")]
    [InlineData(@"\metrics\winguard.prom", "full path")]
    [InlineData(@"C:\metrics\winguard.txt", ".prom")]
    [InlineData(@"C:\metrics\winguard", ".prom")]
    [InlineData(@"C:\metrics\winguard.prom:stream", ".prom")]
    public void Other_paths_are_refused(string path, string reason)
    {
        Assert.Contains(reason, PrometheusTextfileWriter.PathProblem(path));
    }

    [Fact]
    public void A_variable_that_expands_to_a_network_path_is_refused()
    {
        var name = "WINGUARD_TEST_" + Guid.NewGuid().ToString("N");
        Environment.SetEnvironmentVariable(name, @"\\server\share");
        try
        {
            Assert.Contains("network", PrometheusTextfileWriter.PathProblem($@"%{name}%\winguard.prom"));
        }
        finally
        {
            Environment.SetEnvironmentVariable(name, null);
        }
    }

    [Fact]
    public void The_validator_refuses_a_bad_path_and_leaves_the_empty_one_alone()
    {
        Assert.Empty(SettingsValidator.Validate(new WinGuardSettings()));
        Assert.Empty(SettingsValidator.Validate(new WinGuardSettings { PrometheusTextfilePath = @"C:\metrics\winguard.prom" }));

        var problem = Assert.Single(SettingsValidator.Validate(new WinGuardSettings { PrometheusTextfilePath = @"\\server\share\winguard.prom" }));
        Assert.Contains("Prometheus textfile", problem);
    }

    // ---- the engine ----

    private sealed class RecordingPublisher : IMetricsPublisher
    {
        public List<(MetricsSnapshot Snapshot, string Path)> Published { get; } = [];

        public bool Throw { get; init; }

        public void Publish(MetricsSnapshot snapshot, string path)
        {
            if (Throw)
            {
                throw new InvalidOperationException("the disk is on fire");
            }

            Published.Add((snapshot, path));
        }
    }

    private static async Task<(BanEngine Engine, FakeStore Store, FakeFirewall Firewall)> StartEngineAsync(
        IMetricsPublisher publisher,
        WinGuardSettings settings,
        FakeStore? store = null)
    {
        store ??= new FakeStore();
        var firewall = new FakeFirewall();
        var engine = new BanEngine(store, firewall, () => settings, NullLogger<BanEngine>.Instance, new FakeTimeProvider(T0))
        {
            Metrics = publisher,
        };

        await engine.StartAsync(CancellationToken.None);
        return (engine, store, firewall);
    }

    private static WinGuardSettings Enabled() => new()
    {
        HousekeepingInterval = TimeSpan.FromHours(6),
        PrometheusTextfilePath = @"C:\metrics\winguard.prom",
    };

    [Fact]
    public async Task Housekeeping_hands_over_what_it_knows()
    {
        var publisher = new RecordingPublisher();
        var settings = Enabled();
        settings.ReportOnly = true;
        settings.Notifications.Enabled = true;
        settings.Notifications.Syslog.Enabled = true;
        settings.MsSql.Enabled = false;
        var (engine, _, _) = await StartEngineAsync(publisher, settings);
        await engine.BanNowAsync("203.0.113.7", TimeSpan.FromHours(1), permanent: false, null);
        await engine.ProcessAsync(new FailedLogin { IpAddress = "203.0.113.8", Source = ProtocolSource.Rdp, TimestampUtc = T0.UtcDateTime, UserName = "x" });

        await engine.HousekeepOnceAsync();
        await engine.StopAsync();

        var (snapshot, path) = Assert.Single(publisher.Published);
        Assert.Equal(@"C:\metrics\winguard.prom", path);
        Assert.Equal(T0.UtcDateTime, snapshot.HousekeepingUtc);
        Assert.Equal(1, snapshot.ActiveBans);
        Assert.True(snapshot.ReportOnly);
        Assert.False(snapshot.Disarmed);
        Assert.True(snapshot.NotificationsEnabled);
        Assert.True(snapshot.SyslogEnabled);

        var rdp = Assert.Single(snapshot.Engines, entry => entry.Label == "rdp");
        Assert.Equal(1, rdp.DetectionsToday);
        Assert.True(rdp.Enabled);
        Assert.False(Assert.Single(snapshot.Engines, entry => entry.Label == "mssql").Enabled);

        var manual = Assert.Single(snapshot.Engines, entry => entry.Label == "manual");
        Assert.Equal(1, manual.ActiveBans);
        Assert.Null(manual.Enabled);
    }

    [Fact]
    public async Task A_ban_the_store_refused_still_counts()
    {
        var publisher = new RecordingPublisher();
        var store = new FakeStore();
        var (engine, _, _) = await StartEngineAsync(publisher, Enabled(), store);
        store.FailWrites = true;
        await engine.BanNowAsync("203.0.113.7", TimeSpan.FromHours(1), permanent: false, null);

        await engine.HousekeepOnceAsync();
        store.FailWrites = false;
        await engine.StopAsync();

        Assert.Equal(1, Assert.Single(publisher.Published).Snapshot.ActiveBans);
    }

    [Fact]
    public async Task Without_a_path_nothing_is_published()
    {
        var publisher = new RecordingPublisher();
        var (engine, _, _) = await StartEngineAsync(publisher, new WinGuardSettings { HousekeepingInterval = TimeSpan.FromHours(6) });

        await engine.HousekeepOnceAsync();
        await engine.StopAsync();

        Assert.Empty(publisher.Published);
    }

    [Fact]
    public async Task A_publisher_that_fails_leaves_housekeeping_and_bans_unharmed()
    {
        var (engine, store, firewall) = await StartEngineAsync(new RecordingPublisher { Throw = true }, Enabled());
        await engine.BanNowAsync("203.0.113.7", TimeSpan.FromHours(1), permanent: false, null);

        await engine.HousekeepOnceAsync();
        await engine.StopAsync();

        Assert.Contains("203.0.113.7", firewall.Blocked);
        Assert.NotNull(await store.GetBanAsync("203.0.113.7"));
    }

    [Fact]
    public async Task A_store_that_cannot_list_bans_publishes_nothing_rather_than_a_false_zero()
    {
        var publisher = new RecordingPublisher();
        var store = new FakeStore();
        var (engine, _, _) = await StartEngineAsync(publisher, Enabled(), store);
        store.FailActiveBansRead = true;

        await engine.HousekeepOnceAsync();
        store.FailActiveBansRead = false;
        await engine.StopAsync();

        Assert.Empty(publisher.Published);
    }

    [Fact]
    public async Task The_real_writer_takes_a_pass_from_the_engine_to_the_disk()
    {
        var writer = new PrometheusTextfileWriter(NullLogger.Instance);
        var settings = Enabled();
        settings.PrometheusTextfilePath = Target;
        var (engine, _, _) = await StartEngineAsync(writer, settings);
        await engine.BanNowAsync("203.0.113.7", TimeSpan.FromHours(1), permanent: false, null);

        await engine.HousekeepOnceAsync();
        await writer.FlushAsync();
        await engine.StopAsync();

        var text = await File.ReadAllTextAsync(Target);
        Assert.Contains("winguard_active_bans 1\n", text);
        Assert.Contains("winguard_engine_active_bans{engine=\"manual\"} 1\n", text);
        Assert.Contains($"winguard_last_housekeeping_timestamp_seconds {T0.ToUnixTimeSeconds()}\n", text);
    }

    [Fact]
    public void The_rule_count_comes_from_the_cache_without_reading_the_firewall()
    {
        var store = new CountingRuleStore();
        var firewall = new WindowsFirewall(NullLogger<WindowsFirewall>.Instance, store);

        Assert.Null(firewall.CachedRuleCount);
        Assert.Equal(0, store.Reads);

        firewall.Block("203.0.113.7");
        var reads = store.Reads;

        Assert.Equal(1, firewall.CachedRuleCount);
        Assert.Equal(reads, store.Reads);
    }

    private sealed class CountingRuleStore : IFirewallRuleStore
    {
        public int Reads { get; private set; }

        public IReadOnlyList<FirewallRuleInfo> ReadRules()
        {
            Reads++;
            return [];
        }

        public void Upsert(string name, int protocol, string? localPorts, string remoteAddresses)
        {
        }

        public void Remove(string name)
        {
        }
    }

    // ---- the settings ----

    [Fact]
    public void Everything_is_off_by_default()
    {
        var settings = new WinGuardSettings();

        Assert.Equal(string.Empty, settings.PrometheusTextfilePath);
        Assert.False(settings.Notifications.Syslog.Enabled);
    }

    [Fact]
    public void Settings_saved_by_an_older_version_get_the_defaults()
    {
        var settings = JsonSerializer.Deserialize<WinGuardSettings>("""{"failedLoginThreshold":7,"notifications":{"enabled":true}}""", IpcJson.Options)!;
        settings.Normalize();

        Assert.Equal(string.Empty, settings.PrometheusTextfilePath);
        Assert.False(settings.Notifications.Syslog.Enabled);
        Assert.Equal(SyslogSettings.DefaultPort, settings.Notifications.Syslog.Port);
    }

    [Fact]
    public void Explicit_nulls_cannot_crash_anything()
    {
        var settings = JsonSerializer.Deserialize<WinGuardSettings>("""{"prometheusTextfilePath":null,"notifications":{"syslog":null}}""", IpcJson.Options)!;
        settings.Normalize();

        Assert.Equal(string.Empty, settings.PrometheusTextfilePath);
        Assert.NotNull(settings.Notifications.Syslog);
    }

    [Fact]
    public void The_new_settings_survive_the_round_trip_to_the_console_and_back()
    {
        var settings = new WinGuardSettings { PrometheusTextfilePath = @"C:\metrics\winguard.prom" };
        settings.Notifications.Syslog = new SyslogSettings
        {
            Enabled = true,
            Host = "siem.example.invalid",
            Port = 6514,
            Protocol = SyslogProtocol.Tcp,
            Format = SyslogFormat.Cef,
            Facility = 16,
        };

        var copy = JsonSerializer.Deserialize<WinGuardSettings>(JsonSerializer.Serialize(settings, IpcJson.Options), IpcJson.Options)!;
        var clone = settings.Clone();

        foreach (var result in new[] { copy, clone })
        {
            Assert.Equal(@"C:\metrics\winguard.prom", result.PrometheusTextfilePath);
            Assert.Equal("siem.example.invalid", result.Notifications.Syslog.Host);
            Assert.Equal(6514, result.Notifications.Syslog.Port);
            Assert.Equal(SyslogProtocol.Tcp, result.Notifications.Syslog.Protocol);
            Assert.Equal(SyslogFormat.Cef, result.Notifications.Syslog.Format);
            Assert.Equal(16, result.Notifications.Syslog.Facility);
        }
    }
}
