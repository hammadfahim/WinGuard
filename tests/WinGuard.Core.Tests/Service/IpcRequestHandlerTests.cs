using System.Reflection;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using WinGuard.Core.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Engine;
using WinGuard.Core.Ipc;
using WinGuard.Core.Model;
using WinGuard.Core.Tests.Fakes;
using WinGuard.Service;
using WinGuard.Service.Ipc;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>
/// Every request of the GUI protocol, driven the way the console sends it (one JSON line in, one
/// JSON line out) against the real ban engine with in-memory store and firewall. No pipe involved.
/// </summary>
public sealed class IpcRequestHandlerTests
{
    private static readonly DateTimeOffset T0 = new(2026, 3, 1, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Status_reports_engines_version_and_protocol()
    {
        await using var h = await Harness.StartAsync();

        var status = await h.GetAsync<ServiceStatusDto>(IpcMethods.GetStatus);

        Assert.True(status.ServiceRunning);
        Assert.Equal(PipeConstants.ProtocolVersion, status.ProtocolVersion);
        Assert.Equal(3, status.Version.Split('.').Length);
        Assert.Equal(T0.UtcDateTime, status.StartedUtc);
        Assert.Equal(4, status.Engines.Count);
        Assert.True(status.Engines.Single(e => e.Source == ProtocolSource.Rdp).Enabled);
        Assert.False(status.Engines.Single(e => e.Source == ProtocolSource.Custom).Enabled);
        Assert.All(status.Engines, e => Assert.False(e.Running)); // no detector registered in this test
    }

    [Fact]
    public async Task Block_then_list_then_unblock()
    {
        await using var h = await Harness.StartAsync();

        await h.SendAsync(IpcMethods.BlockNow, new BlockNowParams { Ip = "203.0.113.7", Duration = TimeSpan.FromHours(2), Note = "test" });

        var ban = Assert.Single(await h.GetAsync<List<BanDto>>(IpcMethods.ListBans));
        Assert.Equal("203.0.113.7", ban.IpAddress);
        Assert.False(ban.IsPermanent);
        Assert.Equal(T0.UtcDateTime.AddHours(2), ban.ExpiresUtc);
        Assert.Equal("test", ban.Note);
        Assert.Contains("203.0.113.7", h.Firewall.Blocked);
        Assert.Equal(1, (await h.GetAsync<ServiceStatusDto>(IpcMethods.GetStatus)).ActiveBans);

        await h.SendAsync(IpcMethods.Unblock, new UnblockParams { Ip = "203.0.113.7" });

        Assert.Empty(await h.GetAsync<List<BanDto>>(IpcMethods.ListBans));
        Assert.DoesNotContain("203.0.113.7", h.Firewall.Blocked);
    }

    [Fact]
    public async Task Permanent_block_and_unblock_with_whitelist()
    {
        await using var h = await Harness.StartAsync();

        await h.SendAsync(IpcMethods.BlockNow, new BlockNowParams { Ip = "203.0.113.8", Permanent = true });
        Assert.True(Assert.Single(await h.GetAsync<List<BanDto>>(IpcMethods.ListBans)).IsPermanent);

        await h.SendAsync(IpcMethods.Unblock, new UnblockParams { Ip = "203.0.113.8", AlsoWhitelist = true });

        Assert.Empty(await h.GetAsync<List<BanDto>>(IpcMethods.ListBans));
        var lists = await h.GetAsync<List<ListEntryDto>>(IpcMethods.ListLists);
        Assert.Contains(lists, e => e.Kind == ListKind.Whitelist && e.Value == "203.0.113.8");

        // Whitelisted now: a block request is refused with a reason.
        var refused = await h.CallAsync(IpcMethods.BlockNow, new BlockNowParams { Ip = "203.0.113.8" });
        Assert.False(refused.Ok);
        Assert.Contains("whitelisted", refused.Error);
    }

    [Theory]
    [InlineData("not-an-ip")]
    [InlineData("")]
    [InlineData("203.0.113.0/24")]
    public async Task Block_with_an_invalid_address_is_refused(string ip)
    {
        await using var h = await Harness.StartAsync();

        var response = await h.CallAsync(IpcMethods.BlockNow, new BlockNowParams { Ip = ip });

        Assert.False(response.Ok);
        Assert.Empty(await h.GetAsync<List<BanDto>>(IpcMethods.ListBans));
    }

    [Fact]
    public async Task Whitelisting_a_range_unbans_what_is_inside_it()
    {
        await using var h = await Harness.StartAsync();
        await h.SendAsync(IpcMethods.BlockNow, new BlockNowParams { Ip = "198.51.100.10" });
        await h.SendAsync(IpcMethods.BlockNow, new BlockNowParams { Ip = "203.0.113.10" });

        await h.SendAsync(IpcMethods.WhitelistAdd, new ListValueParams { Value = "198.51.100.5/24" });

        var bans = await h.GetAsync<List<BanDto>>(IpcMethods.ListBans);
        Assert.Equal(new[] { "203.0.113.10" }, bans.Select(b => b.IpAddress));
        var lists = await h.GetAsync<List<ListEntryDto>>(IpcMethods.ListLists);
        Assert.Contains(lists, e => e.Kind == ListKind.Whitelist && e.Value == "198.51.100.0/24");

        await h.SendAsync(IpcMethods.ListRemove, new ListRemoveParams { Kind = ListKind.Whitelist, Value = "198.51.100.0/24" });
        Assert.Empty(await h.GetAsync<List<ListEntryDto>>(IpcMethods.ListLists));
    }

    [Fact]
    public async Task Blacklisting_bans_at_once_and_removing_the_entry_lifts_the_ban()
    {
        await using var h = await Harness.StartAsync();
        await h.SendAsync(IpcMethods.BlockNow, new BlockNowParams { Ip = "203.0.113.50", Permanent = true, Note = "manual" });

        await h.SendAsync(IpcMethods.BlacklistAdd, new ListValueParams { Value = "203.0.113.20" });

        var bans = await h.GetAsync<List<BanDto>>(IpcMethods.ListBans);
        var blacklisted = bans.Single(b => b.IpAddress == "203.0.113.20");
        Assert.True(blacklisted.IsPermanent);
        Assert.Contains("203.0.113.20", h.Firewall.Blocked);

        await h.SendAsync(IpcMethods.ListRemove, new ListRemoveParams { Kind = ListKind.Blacklist, Value = "203.0.113.20" });

        bans = await h.GetAsync<List<BanDto>>(IpcMethods.ListBans);
        Assert.Equal(new[] { "203.0.113.50" }, bans.Select(b => b.IpAddress)); // the manual ban stays
        Assert.DoesNotContain("203.0.113.20", h.Firewall.Blocked);
    }

    [Theory]
    [InlineData("0.0.0.0/0")]
    [InlineData("10.0.0.0/7")]
    [InlineData("2000::/16")]
    [InlineData("example.com")]
    public async Task Too_broad_or_invalid_list_entries_are_refused(string value)
    {
        await using var h = await Harness.StartAsync();

        Assert.False((await h.CallAsync(IpcMethods.WhitelistAdd, new ListValueParams { Value = value })).Ok);
        Assert.False((await h.CallAsync(IpcMethods.BlacklistAdd, new ListValueParams { Value = value })).Ok);
        Assert.Empty(await h.GetAsync<List<ListEntryDto>>(IpcMethods.ListLists));
    }

    [Theory]
    [InlineData(ListKind.Whitelist, "0.0.0.0/0")]
    [InlineData(ListKind.Blacklist, "0.0.0.0/0")]
    [InlineData(ListKind.Whitelist, "2000::/16")]
    [InlineData(ListKind.Blacklist, "not even an address")]
    public async Task An_entry_from_an_older_version_can_be_removed_whatever_it_is(ListKind kind, string stored)
    {
        await using var h = await Harness.StartAsync();
        await h.Store.AddToListAsync(kind, stored);

        await h.SendAsync(IpcMethods.ListRemove, new ListRemoveParams { Kind = kind, Value = stored });

        Assert.Empty(await h.GetAsync<List<ListEntryDto>>(IpcMethods.ListLists));
    }

    [Theory]
    [InlineData("10.1.2.3/7")]    // the same network with host bits set
    [InlineData(" 10.0.0.0/7 ")]
    public async Task A_broad_entry_can_be_named_the_way_add_would_have_written_it(string value)
    {
        await using var h = await Harness.StartAsync();
        await h.Store.AddToListAsync(ListKind.Whitelist, "10.0.0.0/7");

        await h.SendAsync(IpcMethods.ListRemove, new ListRemoveParams { Kind = ListKind.Whitelist, Value = value });

        Assert.Empty(await h.GetAsync<List<ListEntryDto>>(IpcMethods.ListLists));
    }

    [Fact]
    public async Task A_host_stored_as_a_32_bit_range_can_be_named_as_the_host()
    {
        await using var h = await Harness.StartAsync();
        await h.Store.AddToListAsync(ListKind.Blacklist, "203.0.113.5/32");

        await h.SendAsync(IpcMethods.ListRemove, new ListRemoveParams { Kind = ListKind.Blacklist, Value = "203.0.113.5" });

        Assert.Empty(await h.GetAsync<List<ListEntryDto>>(IpcMethods.ListLists));
    }

    [Theory]
    [InlineData("not-an-ip")]
    [InlineData("")]
    public async Task Removing_something_that_is_neither_stored_nor_valid_is_refused(string value)
    {
        await using var h = await Harness.StartAsync();

        var response = await h.CallAsync(IpcMethods.ListRemove, new ListRemoveParams { Kind = ListKind.Whitelist, Value = value });

        Assert.False(response.Ok);
    }

    [Fact]
    public async Task Removing_a_valid_entry_that_is_not_there_stays_a_no_op()
    {
        await using var h = await Harness.StartAsync();

        await h.SendAsync(IpcMethods.ListRemove, new ListRemoveParams { Kind = ListKind.Whitelist, Value = "203.0.113.5" });
    }

    [Fact]
    public async Task A_single_host_written_as_a_range_is_treated_as_that_host()
    {
        await using var h = await Harness.StartAsync();

        await h.SendAsync(IpcMethods.BlacklistAdd, new ListValueParams { Value = "203.0.113.20/32" });

        Assert.Equal("203.0.113.20", Assert.Single(await h.GetAsync<List<ListEntryDto>>(IpcMethods.ListLists)).Value);
        Assert.Equal("203.0.113.20", Assert.Single(await h.GetAsync<List<BanDto>>(IpcMethods.ListBans)).IpAddress);
    }

    [Fact]
    public async Task A_bulk_unban_that_fails_halfway_still_lifts_the_rest_and_names_what_is_left()
    {
        await using var h = await Harness.StartAsync(refuseRemovalOf: "198.51.100.11");
        await h.SendAsync(IpcMethods.BlockNow, new BlockNowParams { Ip = "198.51.100.10" });
        await h.SendAsync(IpcMethods.BlockNow, new BlockNowParams { Ip = "198.51.100.11" });
        await h.SendAsync(IpcMethods.BlockNow, new BlockNowParams { Ip = "198.51.100.12" });

        var response = await h.CallAsync(IpcMethods.WhitelistAdd, new ListValueParams { Value = "198.51.100.0/24" });

        Assert.False(response.Ok);
        Assert.Contains("1 of 3", response.Error);
        Assert.Contains("198.51.100.11", response.Error);
        Assert.Equal(new[] { "198.51.100.11" }, (await h.GetAsync<List<BanDto>>(IpcMethods.ListBans)).Select(b => b.IpAddress));

        // The entry itself was saved, so nothing is half-way: repeating the request is safe.
        Assert.Contains(await h.GetAsync<List<ListEntryDto>>(IpcMethods.ListLists), e => e.Value == "198.51.100.0/24");
    }

    [Fact]
    public async Task Taking_a_range_off_the_blacklist_reports_a_ban_it_could_not_lift()
    {
        await using var h = await Harness.StartAsync(refuseRemovalOf: "203.0.113.21");
        await h.Store.AddToListAsync(ListKind.Blacklist, "203.0.113.0/24");
        await h.Store.UpsertBanAsync(new BanEntry { IpAddress = "203.0.113.20", IsPermanent = true, Note = "blacklist" });
        await h.Store.UpsertBanAsync(new BanEntry { IpAddress = "203.0.113.21", IsPermanent = true, Note = "blacklist" });

        var response = await h.CallAsync(IpcMethods.ListRemove, new ListRemoveParams { Kind = ListKind.Blacklist, Value = "203.0.113.0/24" });

        Assert.False(response.Ok);
        Assert.Contains("203.0.113.21", response.Error);
        Assert.Equal(new[] { "203.0.113.21" }, (await h.GetAsync<List<BanDto>>(IpcMethods.ListBans)).Select(b => b.IpAddress));
    }

    [Fact]
    public async Task An_unblock_the_store_refused_is_not_reported_as_done()
    {
        await using var h = await Harness.StartAsync(refuseRemovalOf: "203.0.113.7");
        await h.SendAsync(IpcMethods.BlockNow, new BlockNowParams { Ip = "203.0.113.7" });

        var response = await h.CallAsync(IpcMethods.Unblock, new UnblockParams { Ip = "203.0.113.7" });

        Assert.False(response.Ok);
        Assert.Contains("203.0.113.7", response.Error);
    }

    [Fact]
    public async Task A_blacklisted_host_is_blocked_even_when_the_database_refuses_the_ban()
    {
        await using var h = await Harness.StartAsync();
        h.Store.FailWrites = true;

        await h.SendAsync(IpcMethods.BlacklistAdd, new ListValueParams { Value = "203.0.113.20" });

        Assert.Contains("203.0.113.20", h.Firewall.Blocked);
    }

    [Fact]
    public async Task A_whitelisted_host_on_the_blacklist_is_no_error()
    {
        await using var h = await Harness.StartAsync();
        await h.SendAsync(IpcMethods.WhitelistAdd, new ListValueParams { Value = "203.0.113.20" });

        await h.SendAsync(IpcMethods.BlacklistAdd, new ListValueParams { Value = "203.0.113.20" });

        Assert.Empty(await h.GetAsync<List<BanDto>>(IpcMethods.ListBans));
    }

    [Fact]
    public async Task A_block_without_a_duration_answers_with_the_configured_tier()
    {
        await using var h = await Harness.StartAsync();
        var settings = await h.GetAsync<WinGuardSettings>(IpcMethods.GetSettings);
        settings.BanTiers = [TimeSpan.FromHours(3), TimeSpan.FromDays(2)];
        await h.SendAsync(IpcMethods.UpdateSettings, new UpdateSettingsParams { Settings = settings });

        var ban = await h.GetAsync<BanDto>(IpcMethods.BlockNow, new BlockNowParams { Ip = "203.0.113.7" });

        Assert.Equal("203.0.113.7", ban.IpAddress);
        Assert.False(ban.IsPermanent);
        Assert.Equal(TimeSpan.FromHours(3), ban.ExpiresUtc - ban.BannedAtUtc);
        Assert.Equal(1, ban.OffenseCount);
    }

    [Fact]
    public async Task A_block_answers_with_the_capped_duration_not_the_requested_one()
    {
        await using var h = await Harness.StartAsync();
        var settings = await h.GetAsync<WinGuardSettings>(IpcMethods.GetSettings);
        settings.MaxBanDuration = TimeSpan.FromDays(10);
        await h.SendAsync(IpcMethods.UpdateSettings, new UpdateSettingsParams { Settings = settings });

        var ban = await h.GetAsync<BanDto>(IpcMethods.BlockNow, new BlockNowParams { Ip = "203.0.113.7", Duration = TimeSpan.FromDays(100) });

        Assert.Equal(TimeSpan.FromDays(10), ban.ExpiresUtc - ban.BannedAtUtc);
    }

    [Fact]
    public async Task Settings_round_trip_and_take_effect()
    {
        await using var h = await Harness.StartAsync();

        var settings = await h.GetAsync<WinGuardSettings>(IpcMethods.GetSettings);
        Assert.Equal(Defaults.FailedLoginThreshold, settings.FailedLoginThreshold);

        settings.FailedLoginThreshold = 2;
        settings.CountWindow = TimeSpan.FromMinutes(3);
        settings.BanTiers = [TimeSpan.FromHours(1), TimeSpan.FromDays(2)];
        settings.BlockedPorts = ["3389", "bogus", "1433"];
        settings.Rdp.ExclusionRules = ["LogonType=2"];
        settings.Ftp.Sources.Add(new FtpLogSource { Name = "iis", Kind = FtpServerKind.IisFtp, Path = @"C:\inetpub\logs\LogFiles\FTPSVC1" });
        settings.CustomSources.Add(new CustomLogSource { Name = "app", PathGlob = @"C:\logs\*.log", Regex = @"failed from (?<ipaddress>\S+)" });
        settings.EventRetentionDays = 7;

        var stored = await h.GetAsync<WinGuardSettings>(IpcMethods.UpdateSettings, new UpdateSettingsParams { Settings = settings });

        Assert.Equal(2, stored.FailedLoginThreshold);
        Assert.Equal(new[] { "3389", "1433" }, stored.BlockedPorts); // normalized by the service
        var reread = await h.GetAsync<WinGuardSettings>(IpcMethods.GetSettings);
        Assert.Equal(TimeSpan.FromMinutes(3), reread.CountWindow);
        Assert.Equal(new[] { TimeSpan.FromHours(1), TimeSpan.FromDays(2) }, reread.BanTiers);
        Assert.Equal(new[] { "LogonType=2" }, reread.Rdp.ExclusionRules);
        Assert.Equal(FtpServerKind.IisFtp, Assert.Single(reread.Ftp.Sources).Kind);
        Assert.Equal("app", Assert.Single(reread.CustomSources).Name);
        Assert.Equal(7, reread.EventRetentionDays);
        Assert.True((await h.GetAsync<ServiceStatusDto>(IpcMethods.GetStatus)).Engines.Single(e => e.Source == ProtocolSource.Custom).Enabled);

        // The engine uses the new threshold at once.
        await h.Engine.ProcessAsync(new FailedLogin { IpAddress = "203.0.113.30", Source = ProtocolSource.MsSql, TimestampUtc = T0.UtcDateTime });
        await h.Engine.ProcessAsync(new FailedLogin { IpAddress = "203.0.113.30", Source = ProtocolSource.MsSql, TimestampUtc = T0.UtcDateTime });
        var ban = Assert.Single(await h.GetAsync<List<BanDto>>(IpcMethods.ListBans));
        Assert.Equal(TimeSpan.FromHours(1), ban.ExpiresUtc - ban.BannedAtUtc);
        Assert.Equal(2, (await h.GetAsync<ServiceStatusDto>(IpcMethods.GetStatus)).Engines.Single(e => e.Source == ProtocolSource.MsSql).DetectionsToday);
    }

    [Fact]
    public async Task Invalid_settings_are_refused_and_nothing_changes()
    {
        await using var h = await Harness.StartAsync();
        var settings = await h.GetAsync<WinGuardSettings>(IpcMethods.GetSettings);
        settings.FailedLoginThreshold = 9;
        settings.Ftp.Sources.Add(new FtpLogSource { Name = "share", Path = @"\\fileserver\logs" });

        var response = await h.CallAsync(IpcMethods.UpdateSettings, new UpdateSettingsParams { Settings = settings });

        Assert.False(response.Ok);
        Assert.Contains("UNC", response.Error);
        Assert.Equal(Defaults.FailedLoginThreshold, (await h.GetAsync<WinGuardSettings>(IpcMethods.GetSettings)).FailedLoginThreshold);
    }

    [Fact]
    public async Task Events_are_listed_newest_first_and_by_cursor()
    {
        await using var h = await Harness.StartAsync();
        await h.SendAsync(IpcMethods.BlockNow, new BlockNowParams { Ip = "203.0.113.41" });
        await h.SendAsync(IpcMethods.BlockNow, new BlockNowParams { Ip = "203.0.113.42" });

        var events = await h.GetAsync<List<EventDto>>(IpcMethods.ListEvents, new ListEventsParams { Limit = 50 });
        Assert.Equal(2, events.Count);
        Assert.All(events, e => Assert.StartsWith("MANUAL BLOCK", e.Message));
        var cursor = events.Max(e => e.Id);
        Assert.True(cursor > 0);

        Assert.Empty(await h.GetAsync<List<EventDto>>(IpcMethods.ListEvents, new ListEventsParams { Limit = 50, AfterId = cursor }));

        await h.SendAsync(IpcMethods.Unblock, new UnblockParams { Ip = "203.0.113.41" });
        var fresh = Assert.Single(await h.GetAsync<List<EventDto>>(IpcMethods.ListEvents, new ListEventsParams { Limit = 50, AfterId = cursor }));
        Assert.StartsWith("MANUAL UNBLOCK", fresh.Message);
    }

    [Fact]
    public async Task Bad_requests_get_an_error_answer_instead_of_breaking_the_session()
    {
        await using var h = await Harness.StartAsync();

        var unknown = await h.CallAsync("NoSuchMethod", null);
        Assert.False(unknown.Ok);
        Assert.Contains("Unknown method", unknown.Error);

        var malformed = JsonSerializer.Deserialize<IpcResponse>((await h.Handler.HandleLineAsync("{ this is not json", default))!, IpcJson.Options)!;
        Assert.False(malformed.Ok);
        Assert.Equal(0, malformed.Id);

        Assert.Null(await h.Handler.HandleLineAsync("   ", default));

        // The session still works afterwards.
        Assert.True((await h.CallAsync(IpcMethods.GetStatus, null)).Ok);
    }

    [Fact]
    public async Task Prerequisite_check_always_answers()
    {
        await using var h = await Harness.StartAsync();

        var prereqs = await h.GetAsync<PrereqsDto>(IpcMethods.CheckPrereqs);

        Assert.True(prereqs.FirewallServiceRunning); // FakeFirewall reports running
        Assert.NotNull(prereqs.Warnings);
    }

    // ---------- v0.2: report-only, statistics, ban history ----------

    [Fact]
    public async Task Status_reports_report_only_mode()
    {
        await using var h = await Harness.StartAsync();

        Assert.False((await h.GetAsync<ServiceStatusDto>(IpcMethods.GetStatus)).ReportOnly);

        var settings = await h.GetAsync<WinGuardSettings>(IpcMethods.GetSettings);
        settings.ReportOnly = true;
        await h.SendAsync(IpcMethods.UpdateSettings, new UpdateSettingsParams { Settings = settings });

        Assert.True((await h.GetAsync<ServiceStatusDto>(IpcMethods.GetStatus)).ReportOnly);
    }

    [Fact]
    public async Task Statistics_and_ban_history_round_trip()
    {
        await using var h = await Harness.StartAsync();

        // A manual ban (and its manual unban) produce history + stats rows.
        await h.SendAsync(IpcMethods.BlockNow, new BlockNowParams { Ip = "203.0.113.60", Duration = TimeSpan.FromHours(2) });
        await h.SendAsync(IpcMethods.Unblock, new UnblockParams { Ip = "203.0.113.60" });

        // Flush the buffered daily stats through a housekeeping pass.
        await h.Engine.HousekeepOnceAsync();

        var statistics = await h.GetAsync<StatisticsDto>(IpcMethods.GetStatistics, new GetStatisticsParams { Days = 7 });
        Assert.Equal(0, statistics.TotalActiveBans); // the unban removed the active ban
        Assert.True(statistics.HistoryRows >= 2);
        var bannedDay = Assert.Single(statistics.Daily, entry => entry.Bans == 1);
        Assert.Equal(ProtocolSource.Manual, bannedDay.Source);
        Assert.Equal(0, bannedDay.Detections); // no detector ran; only the ban was recorded

        var history = await h.GetAsync<List<BanHistoryDto>>(IpcMethods.ListBanHistory, new ListBanHistoryParams { Limit = 50 });
        Assert.Contains(history, row => row.Action == "Banned" && row.IpAddress == "203.0.113.60" && row.DurationTicks == TimeSpan.FromHours(2).Ticks);
        Assert.Contains(history, row => row.Action == "Unbanned" && row.IpAddress == "203.0.113.60");
        Assert.Contains(statistics.TopOffenders, offender => offender.IpAddress == "203.0.113.60" && offender.BanCount == 1);
    }

    [Fact]
    public async Task Settings_for_new_features_round_trip()
    {
        await using var h = await Harness.StartAsync();

        var settings = await h.GetAsync<WinGuardSettings>(IpcMethods.GetSettings);
        settings.ReportOnly = true;
        settings.EventBacklogReplayMinutes = 90;
        settings.Ipv6AggregatePrefixLength = 64;
        settings.Notifications = new NotificationSettings
        {
            Enabled = true,
            WebhookUrl = "https://example.invalid/hook",
            TelegramBotToken = "123:abc",
            TelegramChatId = "42",
            RateLimitPerMinute = 5,
            WriteToWindowsEventLog = false,
            Smtp = new SmtpSettings { Host = "smtp.example.invalid", Port = 587, From = "wg@example.invalid", To = "ops@example.invalid" },
        };

        var stored = await h.GetAsync<WinGuardSettings>(IpcMethods.UpdateSettings, new UpdateSettingsParams { Settings = settings });

        Assert.True(stored.ReportOnly);
        Assert.Equal(90, stored.EventBacklogReplayMinutes);
        Assert.Equal(64, stored.Ipv6AggregatePrefixLength);
        Assert.Equal("https://example.invalid/hook", stored.Notifications.WebhookUrl);
        Assert.Equal("42", stored.Notifications.TelegramChatId);
        Assert.Equal(5, stored.Notifications.RateLimitPerMinute);
        Assert.False(stored.Notifications.WriteToWindowsEventLog);
        Assert.Equal(587, stored.Notifications.Smtp!.Port);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(5000)]
    public async Task Out_of_range_backlog_and_prefix_values_are_clamped(int _)
    {
        await using var h = await Harness.StartAsync();

        var settings = await h.GetAsync<WinGuardSettings>(IpcMethods.GetSettings);
        settings.EventBacklogReplayMinutes = 5000; // over the 24 h cap
        settings.Ipv6AggregatePrefixLength = 128;  // over the /64 cap

        var stored = await h.GetAsync<WinGuardSettings>(IpcMethods.UpdateSettings, new UpdateSettingsParams { Settings = settings });

        Assert.Equal(1440, stored.EventBacklogReplayMinutes);
        Assert.Equal(64, stored.Ipv6AggregatePrefixLength);
    }

    /// <summary>A store that refuses to remove one ban, as a locked database would.</summary>
    public class RefusingStore : DispatchProxy
    {
        private IStore _inner = null!;
        private string _ip = string.Empty;

        public static IStore Wrap(IStore inner, string ip)
        {
            var proxy = Create<IStore, RefusingStore>();
            var refusing = (RefusingStore)(object)proxy;
            refusing._inner = inner;
            refusing._ip = ip;
            return proxy;
        }

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            if (targetMethod!.Name == nameof(IStore.RemoveBanAsync) && _ip.Equals(args![0]))
            {
                return Task.FromException(new IOException("database is locked"));
            }

            return targetMethod.Invoke(_inner, args);
        }
    }

    /// <summary>The handler wired the way Program.cs wires it, with in-memory store and firewall.</summary>
    private sealed class Harness : IAsyncDisposable
    {
        private long _nextId;

        private Harness()
        {
        }

        public FakeStore Store { get; } = new();

        public FakeFirewall Firewall { get; } = new();

        public FakeTimeProvider Time { get; } = new(T0);

        public BanEngine Engine { get; private set; } = null!;

        public IpcRequestHandler Handler { get; private set; } = null!;

        public static async Task<Harness> StartAsync(string? refuseRemovalOf = null)
        {
            var h = new Harness();
            var holder = new SettingsHolder(h.Store, NullLogger<SettingsHolder>.Instance);
            await holder.LoadAsync();

            // Keep the engine's own timer out of the test.
            var settings = holder.Current.Clone();
            settings.HousekeepingInterval = TimeSpan.FromHours(6);
            await holder.ApplyAsync(settings);

            IStore store = refuseRemovalOf is null ? h.Store : RefusingStore.Wrap(h.Store, refuseRemovalOf);
            h.Engine = new BanEngine(store, h.Firewall, () => holder.Current, NullLogger<BanEngine>.Instance, h.Time);
            await h.Engine.StartAsync(CancellationToken.None);
            h.Handler = new IpcRequestHandler(
                store,
                h.Engine,
                holder,
                h.Firewall,
                new DetectorRuntimeState(),
                h.Time,
                NullLogger<IpcRequestHandler>.Instance);
            return h;
        }

        /// <summary>Sends a request exactly as the console's pipe client serializes it.</summary>
        public async Task<IpcResponse> CallAsync(string method, object? parameters)
        {
            var request = new IpcRequest
            {
                Id = ++_nextId,
                Method = method,
                Params = parameters is null ? null : JsonSerializer.SerializeToElement(parameters, IpcJson.Options),
            };

            var line = await Handler.HandleLineAsync(JsonSerializer.Serialize(request, IpcJson.Options), CancellationToken.None);
            Assert.NotNull(line);
            Assert.DoesNotContain('\n', line);
            var response = JsonSerializer.Deserialize<IpcResponse>(line, IpcJson.Options)!;
            Assert.Equal(request.Id, response.Id);
            return response;
        }

        public async Task SendAsync(string method, object? parameters)
        {
            var response = await CallAsync(method, parameters);
            Assert.True(response.Ok, response.Error);
        }

        public async Task<T> GetAsync<T>(string method, object? parameters = null)
        {
            var response = await CallAsync(method, parameters);
            Assert.True(response.Ok, response.Error);
            Assert.NotNull(response.Result);
            return JsonSerializer.Deserialize<T>(response.Result.Value, IpcJson.Options)!;
        }

        public ValueTask DisposeAsync() => new(Engine.StopAsync(CancellationToken.None));
    }
}
