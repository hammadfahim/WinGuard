using WinGuard.Core.Config;
using WinGuard.Core.Detection;
using WinGuard.Core.Engine;
using WinGuard.Core.Model;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>Regression tests for the third review round.</summary>
public class ReviewRound3Tests
{
    private static readonly DateTimeOffset T0 = new(2026, 3, 1, 12, 0, 0, TimeSpan.Zero);

    // ---------- RDP de-duplication ----------

    [Fact]
    public void A_fast_rdp_attack_counts_once_per_attempt()
    {
        var dedup = new RdpDeduplicator();
        var counted = 0;
        for (var i = 0; i < 20; i++)
        {
            var at = T0.UtcDateTime.AddSeconds(i * 0.5);
            if (!dedup.IsDuplicateAndRecord("203.0.113.9", "4625", at))
            {
                counted++;
            }

            if (!dedup.IsDuplicateAndRecord("203.0.113.9", "140", at.AddMilliseconds(10)))
            {
                counted++;
            }
        }

        Assert.Equal(20, counted);
    }

    [Fact]
    public void A_pair_is_merged_whichever_half_arrives_first()
    {
        var dedup = new RdpDeduplicator();
        var at = T0.UtcDateTime;

        Assert.False(dedup.IsDuplicateAndRecord("203.0.113.9", "140", at));
        Assert.True(dedup.IsDuplicateAndRecord("203.0.113.9", "4625", at.AddMilliseconds(300)));

        // The pair is used up: the next 4625 is a new attempt.
        Assert.False(dedup.IsDuplicateAndRecord("203.0.113.9", "4625", at.AddMilliseconds(600)));
    }

    [Fact]
    public async Task A_fast_rdp_attack_is_banned()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        const string ip = "203.0.113.60";

        for (var i = 0; i < h.Settings.FailedLoginThreshold; i++)
        {
            await h.ProcessAsync(h.Fail(ip, ProtocolSource.Rdp, detector: "4625"));
            await h.ProcessAsync(h.Fail(ip, ProtocolSource.Rdp, detector: "140"));
            h.Time.Advance(TimeSpan.FromMilliseconds(400));
        }

        Assert.NotNull(await h.Store.GetBanAsync(ip));
        Assert.Contains(ip, h.Firewall.Blocked);
    }

    // ---------- exclusion rules and the 140 fallback ----------

    [Fact]
    public async Task An_excluded_4625_also_drops_its_140_counterpart()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        const string ip = "203.0.113.61";

        for (var i = 0; i < 10; i++)
        {
            var excluded = h.Fail(ip, ProtocolSource.Rdp, detector: "4625");
            excluded.IsExcluded = true;
            await h.ProcessAsync(excluded);
            await h.ProcessAsync(h.Fail(ip, ProtocolSource.Rdp, detector: "140"));
            h.Time.Advance(TimeSpan.FromSeconds(5));
        }

        Assert.Null(await h.Store.GetBanAsync(ip));
        Assert.DoesNotContain(h.Store.FailedLogins, f => f.IpAddress == ip);
    }

    [Fact]
    public async Task An_excluded_4625_takes_back_a_140_that_was_counted_first()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        const string ip = "203.0.113.62";

        for (var i = 0; i < 10; i++)
        {
            await h.ProcessAsync(h.Fail(ip, ProtocolSource.Rdp, detector: "140"));
            var excluded = h.Fail(ip, ProtocolSource.Rdp, detector: "4625");
            excluded.IsExcluded = true;
            await h.ProcessAsync(excluded);
            h.Time.Advance(TimeSpan.FromSeconds(5));
        }

        Assert.Null(await h.Store.GetBanAsync(ip));
        Assert.DoesNotContain(h.Store.FailedLogins, f => f.IpAddress == ip);
    }

    [Fact]
    public void Only_ip_rules_are_applied_to_events_that_carry_just_an_ip()
    {
        string[] rules = ["LogonType=2", "TargetUserName!=admin", "IpAddress=198.51.100.*"];

        Assert.True(ExclusionEvaluator.IsExcludedByIpOnlyRules("198.51.100.20", rules));
        Assert.False(ExclusionEvaluator.IsExcludedByIpOnlyRules("203.0.113.5", rules));
    }

    [Fact]
    public void Excluded_4625_is_still_reported_with_the_flag_set()
    {
        var xml = File.ReadAllText(Sample("security-4625.xml"));
        var settings = new WinGuardSettings();
        settings.Rdp.ExclusionRules = ["TargetUserName=administrator"];

        Assert.False(RdpSecurityLogDetector.TryParse(xml, settings, out _));
        Assert.True(RdpSecurityLogDetector.TryParseDetailed(xml, settings, out var failed, out var excluded));
        Assert.True(excluded);
        Assert.Equal("203.0.113.45", failed!.IpAddress);
    }

    // ---------- MSSQL ----------

    [Fact]
    public void Mssql_client_address_cannot_be_spoofed_through_the_login_name()
    {
        var xml = File.ReadAllText(Sample("mssql-18456.xml"));
        const string message =
            "Login failed for user 'x [CLIENT: 8.8.8.8] y'. Reason: Could not find a login matching the name provided. [CLIENT: 203.0.113.77]";

        Assert.True(MsSqlDetector.TryParse(xml, message, new WinGuardSettings(), TestData.SqlInstances, out var failed));
        Assert.Equal("203.0.113.77", failed!.IpAddress);
    }

    // ---------- IP handling ----------

    [Theory]
    [InlineData("010.1.1.1")]
    [InlineData("1.02.3.4")]
    public void Octets_with_leading_zeros_are_rejected(string value)
    {
        Assert.False(IpMatcher.TryNormalize(value, out _));
    }

    [Theory]
    [InlineData("0.0.0.0", false)]
    [InlineData("255.255.255.255", false)]
    [InlineData("224.0.0.1", false)]
    [InlineData("::", false)]
    [InlineData("ff02::1", false)]
    [InlineData("203.0.113.5", true)]
    [InlineData("2001:db8::1", true)]
    public void Only_host_addresses_are_bannable(string value, bool expected)
    {
        Assert.Equal(expected, IpMatcher.IsBannable(value));
    }

    [Fact]
    public async Task Non_host_addresses_never_reach_the_ban_list()
    {
        await using var h = await EngineHarness.StartAsync(T0);

        for (var i = 0; i < 20; i++)
        {
            await h.ProcessAsync(h.Fail("255.255.255.255"));
        }

        Assert.Null(await h.Store.GetBanAsync("255.255.255.255"));
        await Assert.ThrowsAsync<ArgumentException>(() => h.Engine.BanNowAsync("0.0.0.0", null, permanent: true, note: null));
    }

    // ---------- engine ----------

    [Fact]
    public async Task Promoting_an_active_ban_does_not_count_as_a_new_offense()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        const string ip = "203.0.113.63";

        for (var i = 0; i < h.Settings.FailedLoginThreshold; i++)
        {
            await h.ProcessAsync(h.Fail(ip));
        }

        Assert.Equal(1, (await h.Store.GetBanAsync(ip))!.OffenseCount);

        await h.Engine.BanNowAsync(ip, null, permanent: true, note: "promoted");

        var ban = await h.Store.GetBanAsync(ip);
        Assert.True(ban!.IsPermanent);
        Assert.Equal(1, ban.OffenseCount);
    }

    [Fact]
    public async Task Detections_today_keeps_counting_after_a_ban()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        const string ip = "203.0.113.64";

        for (var i = 0; i < h.Settings.FailedLoginThreshold; i++)
        {
            await h.ProcessAsync(h.Fail(ip));
        }

        // The ban cleared the stored attempts; the dashboard figure must not drop with them.
        Assert.NotNull(await h.Store.GetBanAsync(ip));
        Assert.Equal(h.Settings.FailedLoginThreshold, h.Engine.GetDetectionsToday(ProtocolSource.MsSql));
        Assert.Equal(0, h.Engine.GetDetectionsToday(ProtocolSource.Ftp));

        h.Time.Advance(TimeSpan.FromDays(1));
        Assert.Equal(0, h.Engine.GetDetectionsToday(ProtocolSource.MsSql));
    }

    // ---------- log tailing ----------

    [Fact]
    public void A_file_created_under_a_watched_source_is_read_from_its_first_line()
    {
        var dir = NewTempDir();
        try
        {
            var tailer = new LogFileTailer();
            var first = Path.Combine(dir, "a.log");
            File.WriteAllText(first, "history\n");
            Assert.Empty(tailer.ReadNewLines(first)); // existing file: skip to end

            var next = Path.Combine(dir, "b.log");
            File.WriteAllText(next, "one\ntwo\n");
            Assert.Equal(new[] { "one", "two" }, tailer.ReadNewLines(next, readFromStartIfNew: true));
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void Rotation_by_rename_and_recreate_is_detected_even_when_the_new_file_is_larger()
    {
        var dir = NewTempDir();
        try
        {
            var tailer = new LogFileTailer();
            var path = Path.Combine(dir, "app.log");
            File.WriteAllText(path, "old-1\nold-2\n");
            Assert.Empty(tailer.ReadNewLines(path));

            // Same name, same creation time (NTFS tunnelling), larger content: only the file's
            // identity tells the two apart.
            File.Move(path, path + ".1");
            File.WriteAllText(path, "new-1\nnew-2\nnew-3\n");

            Assert.Equal(new[] { "new-1", "new-2", "new-3" }, tailer.ReadNewLines(path));
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Theory]
    [InlineData(@"\\server\share\ftp.log", false)]
    [InlineData(@"\\?\C:\logs\ftp.log", false)]
    [InlineData("//server/share/ftp.log", false)]
    [InlineData(@"C:\inetpub\logs\LogFiles\FTPSVC1", true)]
    [InlineData(@"%SystemDrive%\logs\*.log", true)]
    public void Only_local_paths_are_accepted_as_log_sources(string path, bool expected)
    {
        Assert.Equal(expected, LogFileTailer.IsLocalPath(path));
        if (!expected)
        {
            Assert.Empty(LogFileTailer.ResolveFiles(path));
        }
    }

    // ---------- FileZilla ----------

    [Fact]
    public void FileZilla_server_1x_style_line_is_parsed()
    {
        const string line = "2024-03-01T10:15:20.123Z !! [FTP Session 12 203.0.113.5] 530 Login incorrect.";

        Assert.True(FtpLogDetector.TryParseFileZillaLine(line, out var failed));
        Assert.Equal("203.0.113.5", failed!.IpAddress);
        Assert.Equal(new DateTime(2024, 3, 1, 10, 15, 20, 123, DateTimeKind.Utc), failed.TimestampUtc);
    }

    [Fact]
    public void Text_typed_by_the_ftp_client_cannot_replace_the_session_address()
    {
        const string modern = "2024-03-01T10:15:20.123Z [FTP Session 12 203.0.113.5] USER 8.8.8.8 530 Login incorrect.";
        const string legacy = "(000001) 2026-10-04 09:05:20 - (not logged in) (203.0.113.44)> USER x (8.8.8.8)> 530 Login or password incorrect!";

        Assert.True(FtpLogDetector.TryParseFileZillaLine(modern, out var a));
        Assert.Equal("203.0.113.5", a!.IpAddress);

        // Not a server response at all: the 530 is part of the echoed command, so nothing is counted.
        Assert.False(FtpLogDetector.TryParseFileZillaLine(legacy, out _));
    }

    // ---------- settings validation ----------

    [Fact]
    public void Settings_with_a_bad_regex_or_a_network_path_are_refused()
    {
        var settings = new WinGuardSettings();
        settings.Ftp.Sources.Add(new FtpLogSource { Name = "share", Path = @"\\fileserver\logs" });
        settings.CustomSources.Add(new CustomLogSource { Name = "broken", PathGlob = @"C:\logs\a.log", Regex = "(unclosed" });
        settings.CustomSources.Add(new CustomLogSource { Name = "no-group", PathGlob = @"C:\logs\b.log", Regex = @"failed from \S+" });
        settings.CustomSources.Add(new CustomLogSource { Name = "fine", PathGlob = @"C:\logs\c.log", Regex = @"failed from (?<ipaddress>\S+)" });

        var problems = SettingsValidator.Validate(settings);

        Assert.Equal(3, problems.Count);
        Assert.Contains(problems, p => p.Contains("'share'") && p.Contains("UNC"));
        Assert.Contains(problems, p => p.Contains("'broken'") && p.Contains("invalid regex"));
        Assert.Contains(problems, p => p.Contains("'no-group'") && p.Contains("ipaddress"));
        Assert.Empty(SettingsValidator.Validate(new WinGuardSettings()));
    }

    private static string Sample(string name) => Path.Combine(AppContext.BaseDirectory, "samples", name);

    private static string NewTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "winguard-r3-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }
}
