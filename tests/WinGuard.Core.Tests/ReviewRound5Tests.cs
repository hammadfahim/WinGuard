using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Engine;
using WinGuard.Core.Ipc;
using WinGuard.Core.Model;
using WinGuard.Core.Store;
using WinGuard.Core.Tests.Fakes;
using WinGuard.Service;
using WinGuard.Service.Ipc;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>
/// Regression tests for the second pass over the engine, store, firewall reconcile and settings:
/// ranges stay enforced across a restart, escalation has its own memory and table, history is
/// bounded, manual bans have their own source, report-only never touches the firewall.
/// </summary>
public sealed class ReviewRound5Tests
{
    private static readonly DateTimeOffset T0 = new(2026, 4, 1, 12, 0, 0, TimeSpan.Zero);

    private const ProtocolSource NonRdp = ProtocolSource.MsSql;
    private const string Attacker = "203.0.113.50";
    private const string Range = "198.51.100.0/24";

    // ---------- blacklisted ranges across a restart ----------

    [Fact]
    public async Task The_start_up_sync_includes_blacklisted_ranges()
    {
        await using var h = await EngineHarness.StartAsync(
            T0,
            seed: async store =>
            {
                await store.AddToListAsync(ListKind.Blacklist, Range);
                await store.UpsertBanAsync(ActiveBan(Attacker));
            });

        // No housekeeping pass yet: one sync put everything in place, in a single call.
        var sync = Assert.Single(h.Firewall.SyncRulesCalls);
        Assert.Contains(Range, sync);
        Assert.Contains(Attacker, sync);
        Assert.Contains(Range, h.Firewall.Blocked);
        Assert.Empty(h.Firewall.UnblockCalls);
    }

    [Fact]
    public async Task The_start_up_sync_keeps_whitelisted_addresses_out_of_blacklisted_ranges()
    {
        await using var h = await EngineHarness.StartAsync(
            T0,
            seed: async store =>
            {
                await store.AddToListAsync(ListKind.Blacklist, "198.51.100.0/30");
                await store.AddToListAsync(ListKind.Whitelist, "198.51.100.1");
            });

        Assert.DoesNotContain("198.51.100.0/30", h.Firewall.Blocked);
        Assert.DoesNotContain("198.51.100.1", h.Firewall.Blocked);
        Assert.Contains("198.51.100.0", h.Firewall.Blocked);
        Assert.Contains("198.51.100.2/31", h.Firewall.Blocked);
    }

    [Fact]
    public async Task Clearing_bans_on_start_up_leaves_the_blacklisted_ranges_enforced()
    {
        await using var h = await EngineHarness.StartAsync(
            T0,
            s => s.ClearBansOnStartup = true,
            seed: async store =>
            {
                await store.AddToListAsync(ListKind.Blacklist, Range);
                await store.UpsertBanAsync(ActiveBan(Attacker));
            });

        Assert.Equal([Range], Assert.Single(h.Firewall.SyncRulesCalls));
        Assert.Equal([Range], h.Firewall.Blocked);
        Assert.Empty(await h.Store.GetActiveBansAsync());
    }

    [Fact]
    public async Task Report_only_start_up_touches_no_firewall_rule_at_all()
    {
        await using var h = await EngineHarness.StartAsync(
            T0,
            s => s.ReportOnly = true,
            seed: async store =>
            {
                await store.AddToListAsync(ListKind.Blacklist, Range);
                await store.UpsertBanAsync(ActiveBan(Attacker));
            });

        AssertFirewallUntouched(h);
    }

    [Fact]
    public async Task Clearing_bans_on_start_up_in_report_only_mode_leaves_the_firewall_alone()
    {
        await using var h = await EngineHarness.StartAsync(
            T0,
            s =>
            {
                s.ReportOnly = true;
                s.ClearBansOnStartup = true;
            },
            seed: store => store.UpsertBanAsync(ActiveBan(Attacker)));

        AssertFirewallUntouched(h);
        Assert.Empty(await h.Store.GetActiveBansAsync());
    }

    [Fact]
    public async Task Unreadable_bans_at_start_up_do_not_wipe_the_firewall()
    {
        await using var h = await EngineHarness.StartAsync(
            T0,
            seed: async store =>
            {
                await store.UpsertBanAsync(ActiveBan(Attacker));
                store.FailActiveBansRead = true;
            });

        // A sync with nothing would delete every rule, and leave them deleted until the store recovers.
        Assert.Empty(h.Firewall.SyncRulesCalls);

        h.Store.FailActiveBansRead = false;
        await h.Engine.HousekeepOnceAsync();

        Assert.Contains(Attacker, h.Firewall.Blocked);
    }

    [Fact]
    public async Task Unreadable_lists_do_not_get_blacklisted_ranges_removed_as_orphans()
    {
        await using var h = await EngineHarness.StartAsync(
            T0,
            seed: async store =>
            {
                await store.AddToListAsync(ListKind.Blacklist, Range);
                store.FailListRead = true;
            });
        h.Firewall.Block(Range); // the rule a previous run left in place

        Assert.Empty(h.Firewall.SyncRulesCalls);
        await h.Engine.HousekeepOnceAsync();
        Assert.Contains(Range, h.Firewall.Blocked);

        h.Store.FailListRead = false;
        await h.Engine.HousekeepOnceAsync();
        Assert.Contains(Range, h.Firewall.Blocked);
    }

    // ---------- offense memory ----------

    [Fact]
    public async Task An_attacker_returning_days_after_a_ban_ended_continues_at_the_next_tier()
    {
        await using var h = await EngineHarness.StartAsync(T0);

        await SendThresholdAsync(h);
        await ExpireAsync(h, TimeSpan.FromHours(25));

        // Well past the old ExpireTime x 4 (4 days with the defaults).
        h.Time.Advance(TimeSpan.FromDays(5));
        await h.Engine.HousekeepOnceAsync();
        await SendThresholdAsync(h);

        var ban = await h.Store.GetBanAsync(Attacker);
        Assert.Equal(2, ban!.OffenseCount);
        Assert.Equal(TimeSpan.FromDays(7), ban.ExpiresUtc - ban.BannedAtUtc);
    }

    [Fact]
    public async Task Past_the_offense_memory_an_attacker_starts_over_and_is_forgotten_in_the_store_too()
    {
        await using var h = await EngineHarness.StartAsync(T0, s => s.OffenseMemory = TimeSpan.FromDays(10));

        await SendThresholdAsync(h);
        await ExpireAsync(h, TimeSpan.FromHours(25));
        Assert.Contains(Attacker, h.Store.OffenseCounts.Keys);

        h.Time.Advance(TimeSpan.FromDays(11));
        await h.Engine.HousekeepOnceAsync();
        Assert.DoesNotContain(Attacker, h.Store.OffenseCounts.Keys);

        await SendThresholdAsync(h);
        Assert.Equal(1, (await h.Store.GetBanAsync(Attacker))!.OffenseCount);
    }

    [Fact]
    public async Task The_offense_memory_runs_from_when_the_ban_ended()
    {
        await using var h = await EngineHarness.StartAsync(T0, s => s.OffenseMemory = TimeSpan.FromDays(3));

        await SendThresholdAsync(h);
        await ExpireAsync(h, TimeSpan.FromHours(25));
        await SendThresholdAsync(h); // 7 days, longer than the memory
        await ExpireAsync(h, TimeSpan.FromDays(8));

        h.Time.Advance(TimeSpan.FromDays(2));
        await h.Engine.HousekeepOnceAsync();
        await SendThresholdAsync(h);

        Assert.Equal(3, (await h.Store.GetBanAsync(Attacker))!.OffenseCount);
    }

    [Fact]
    public void Settings_saved_before_offense_memory_existed_get_the_default()
    {
        var settings = JsonSerializer.Deserialize<WinGuardSettings>("""{"failedLoginThreshold":7}""", IpcJson.Options)!;

        settings.Normalize();

        Assert.Equal(7, settings.FailedLoginThreshold);
        Assert.Equal(TimeSpan.FromDays(90), settings.OffenseMemory);
        Assert.Equal(365, settings.BanHistoryRetentionDays);
    }

    [Theory]
    [InlineData(0, 90)]
    [InlineData(-5, 90)]
    [InlineData(7, 7)]
    [InlineData(100000, 3650)]
    public void Offense_memory_is_normalized(int days, int expected)
    {
        var settings = new WinGuardSettings { OffenseMemory = TimeSpan.FromDays(days) };

        settings.Normalize();

        Assert.Equal(TimeSpan.FromDays(expected), settings.OffenseMemory);
    }

    // ---------- offense counts in their own table ----------

    [Fact]
    public async Task A_ban_writes_one_offense_row_however_many_are_remembered()
    {
        await using var h = await EngineHarness.StartAsync(
            T0,
            seed: async store =>
            {
                var remembered = Enumerable.Range(0, 2000)
                    .Select(i => new OffenseCountEntry { IpAddress = $"192.0.{i / 256}.{i % 256}", Count = 1, LastUtc = T0.UtcDateTime })
                    .ToList();
                await store.SaveOffenseCountsAsync(remembered, []);
            });
        var before = h.Store.OffenseRowsWritten;

        await SendThresholdAsync(h);

        Assert.Equal(1, h.Store.OffenseRowsWritten - before);
        Assert.False(h.Store.SettingValues.ContainsKey("offense_counts"));
        Assert.Equal(1, h.Store.OffenseCounts[Attacker].Count);
    }

    [Fact]
    public async Task A_failed_offense_write_does_not_stop_the_ban_and_is_repeated()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        h.Store.FailOffenseWrites = true;

        await SendThresholdAsync(h);

        Assert.Contains(Attacker, h.Firewall.Blocked);
        Assert.NotNull(await h.Store.GetBanAsync(Attacker));
        Assert.Empty(h.Store.OffenseCounts);

        h.Store.FailOffenseWrites = false;
        await h.Engine.HousekeepOnceAsync();

        Assert.Equal(1, h.Store.OffenseCounts[Attacker].Count);
    }

    [Fact]
    public async Task A_failed_offense_removal_is_repeated_too()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        await SendThresholdAsync(h);
        h.Store.FailOffenseWrites = true;

        await h.Engine.UnbanAsync(Attacker);

        Assert.Contains(Attacker, h.Store.OffenseCounts.Keys);

        h.Store.FailOffenseWrites = false;
        await h.Engine.HousekeepOnceAsync();

        Assert.Empty(h.Store.OffenseCounts);
    }

    [Fact]
    public async Task Stopping_saves_what_the_store_refused_while_running()
    {
        var h = await EngineHarness.StartAsync(T0);
        h.Store.FailOffenseWrites = true;
        await SendThresholdAsync(h);

        h.Store.FailOffenseWrites = false;
        await h.DisposeAsync();

        Assert.Equal(1, h.Store.OffenseCounts[Attacker].Count);
    }

    [Fact]
    public async Task Clearing_bans_on_start_up_forgets_the_saved_offense_counts()
    {
        await using var h = await EngineHarness.StartAsync(
            T0,
            s => s.ClearBansOnStartup = true,
            seed: store => store.SaveOffenseCountsAsync(
                [new OffenseCountEntry { IpAddress = Attacker, Count = 3, LastUtc = T0.UtcDateTime }],
                []));

        Assert.Empty(h.Store.OffenseCounts);
    }

    [Fact]
    public async Task The_store_keeps_offense_counts_and_applies_a_batch_as_a_whole()
    {
        await WithSqliteStoreAsync(async (store, _) =>
        {
            var last = new DateTime(2026, 5, 1, 10, 0, 0, DateTimeKind.Utc);
            await store.SaveOffenseCountsAsync(
                [
                    new OffenseCountEntry { IpAddress = "203.0.113.1", Count = 1, LastUtc = last },
                    new OffenseCountEntry { IpAddress = "203.0.113.2", Count = 2, LastUtc = last },
                ],
                []);

            await store.SaveOffenseCountsAsync(
                [new OffenseCountEntry { IpAddress = "203.0.113.1", Count = 5, LastUtc = last.AddDays(1) }],
                ["203.0.113.2", "203.0.113.99"]);

            var row = Assert.Single(await store.GetOffenseCountsAsync());
            Assert.Equal("203.0.113.1", row.IpAddress);
            Assert.Equal(5, row.Count);
            Assert.Equal(last.AddDays(1), row.LastUtc);

            await store.SaveOffenseCountsAsync([], []);
            Assert.Single(await store.GetOffenseCountsAsync());
        });
    }

    // ---------- ban-history retention ----------

    [Fact]
    public async Task Housekeeping_prunes_ban_history_past_its_retention_in_bounded_batches()
    {
        await using var h = await EngineHarness.StartAsync(T0, s => s.BanHistoryRetentionDays = 30);
        for (var i = 0; i < 5010; i++)
        {
            await h.Store.AddBanHistoryAsync(History("203.0.113.1", T0.UtcDateTime.AddDays(-31).AddSeconds(i)));
        }

        await h.Store.AddBanHistoryAsync(History("203.0.113.2", T0.UtcDateTime.AddDays(-29)));

        await h.Engine.HousekeepOnceAsync();
        Assert.Equal(11, await h.Store.CountBanHistoryAsync());

        await h.Engine.HousekeepOnceAsync();
        Assert.Equal("203.0.113.2", Assert.Single(h.Store.BanHistory).IpAddress);
    }

    [Fact]
    public async Task The_store_prunes_the_oldest_history_rows_first_and_counts_them_all()
    {
        await WithSqliteStoreAsync(async (store, _) =>
        {
            var cutoff = new DateTime(2026, 5, 1, 0, 0, 0, DateTimeKind.Utc);
            await store.AddBanHistoryAsync(History("203.0.113.3", cutoff.AddDays(-1)));
            await store.AddBanHistoryAsync(History("203.0.113.1", cutoff.AddDays(-3)));
            await store.AddBanHistoryAsync(History("203.0.113.2", cutoff.AddDays(-2)));
            await store.AddBanHistoryAsync(History("203.0.113.4", cutoff));

            Assert.Equal(2, await store.PruneBanHistoryAsync(cutoff, maxRows: 2));
            Assert.Equal(new[] { "203.0.113.3", "203.0.113.4" }, (await store.GetBanHistoryAsync(10)).Select(r => r.IpAddress).Order());

            Assert.Equal(1, await store.PruneBanHistoryAsync(cutoff, maxRows: 2));
            Assert.Equal(0, await store.PruneBanHistoryAsync(cutoff, maxRows: 2));
            Assert.Equal(1, await store.CountBanHistoryAsync());
        });
    }

    [Fact]
    public async Task Statistics_report_the_real_number_of_history_rows()
    {
        await using var h = await IpcHarness.StartAsync(T0, TimeSpan.Zero);
        for (var i = 0; i < 1500; i++)
        {
            await h.Store.AddBanHistoryAsync(History("203.0.113.1", T0.UtcDateTime));
        }

        var statistics = await h.GetAsync<StatisticsDto>(IpcMethods.GetStatistics, new GetStatisticsParams { Days = 7 });

        Assert.Equal(1500, statistics.HistoryRows);
    }

    [Fact]
    public async Task Top_offenders_are_answered_from_a_covering_index()
    {
        await WithSqliteStoreAsync(async (store, path) =>
        {
            var at = new DateTime(2026, 5, 1, 0, 0, 0, DateTimeKind.Utc);
            await store.AddBanHistoryAsync(History("203.0.113.1", at, offense: 2));
            await store.AddBanHistoryAsync(History("203.0.113.1", at.AddDays(1), offense: 1));
            await store.AddBanHistoryAsync(History("203.0.113.2", at));
            await store.AddBanHistoryAsync(new BanHistoryEntry { TimestampUtc = at, Action = BanHistoryAction.Expired, IpAddress = "203.0.113.3" });

            var top = await store.GetTopOffendersAsync(10);
            Assert.Equal(new[] { "203.0.113.1", "203.0.113.2" }, top.Select(t => t.IpAddress));
            Assert.Equal(2, top[0].BanCount);
            Assert.Equal(2, top[0].MaxOffense);
            Assert.Equal(at.AddDays(1), top[0].LastSeenUtc);

            await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString());
            await connection.OpenAsync();
            await using var cmd = connection.CreateCommand();
            cmd.CommandText =
                "EXPLAIN QUERY PLAN SELECT ip, COUNT(*), MAX(offense_count), MAX(ts_utc) FROM ban_history " +
                "WHERE action = 0 GROUP BY ip ORDER BY COUNT(*) DESC, MAX(ts_utc) DESC LIMIT 10;";
            await using var reader = await cmd.ExecuteReaderAsync();
            var plan = new List<string>();
            while (await reader.ReadAsync())
            {
                plan.Add(reader.GetString(3));
            }

            Assert.Contains(plan, step => step.Contains("COVERING INDEX ix_ban_history_top", StringComparison.Ordinal));
        });
    }

    // ---------- the Manual source ----------

    [Fact]
    public void Enum_values_stored_in_existing_rows_keep_their_meaning()
    {
        Assert.Equal(0, (int)ProtocolSource.Rdp);
        Assert.Equal(1, (int)ProtocolSource.MsSql);
        Assert.Equal(2, (int)ProtocolSource.Ftp);
        Assert.Equal(3, (int)ProtocolSource.Custom);
        Assert.Equal(4, (int)ProtocolSource.Manual);
    }

    [Fact]
    public async Task A_manual_ban_is_recorded_as_manual_everywhere()
    {
        await using var h = await EngineHarness.StartAsync(T0);

        await h.Engine.BanNowAsync(Attacker, TimeSpan.FromHours(2), permanent: false, null);
        await h.Engine.HousekeepOnceAsync();

        Assert.Equal(ProtocolSource.Manual, (await h.Store.GetBanAsync(Attacker))!.Source);
        Assert.Equal(ProtocolSource.Manual, Assert.Single(h.Store.BanHistory).Source);
        Assert.Equal(ProtocolSource.Manual, h.Store.Events.Last(e => e.Message.StartsWith("MANUAL BLOCK", StringComparison.Ordinal)).Source);
        Assert.Equal(1, Assert.Single(h.Store.DailyStats, pair => pair.Key.Source == ProtocolSource.Manual).Value.Bans);
        Assert.Equal(0, h.Engine.GetDetectionsToday(ProtocolSource.Manual));
    }

    [Fact]
    public async Task Promoting_a_detected_ban_keeps_the_engine_that_found_it()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        await SendThresholdAsync(h);

        await h.Engine.BanNowAsync(Attacker, null, permanent: true, null);

        var ban = await h.Store.GetBanAsync(Attacker);
        Assert.True(ban!.IsPermanent);
        Assert.Equal(NonRdp, ban.Source);
    }

    [Fact]
    public async Task A_manual_ban_over_an_expired_row_is_manual()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        await SendThresholdAsync(h);
        h.Time.Advance(TimeSpan.FromDays(2)); // expired, but no housekeeping has removed the row yet

        await h.Engine.BanNowAsync(Attacker, TimeSpan.FromHours(1), permanent: false, null);

        Assert.Equal(ProtocolSource.Manual, (await h.Store.GetBanAsync(Attacker))!.Source);
    }

    [Fact]
    public async Task Status_shows_detection_engines_only_and_still_counts_manual_bans()
    {
        await using var h = await IpcHarness.StartAsync(T0, TimeSpan.Zero);

        await h.SendAsync(IpcMethods.BlockNow, new BlockNowParams { Ip = Attacker, Duration = TimeSpan.FromHours(1) });
        await h.Engine.HousekeepOnceAsync();

        var status = await h.GetAsync<ServiceStatusDto>(IpcMethods.GetStatus);
        Assert.Equal(1, status.ActiveBans);
        Assert.DoesNotContain(status.Engines, engine => engine.Source == ProtocolSource.Manual);
        Assert.All(status.Engines, engine => Assert.Equal(0, engine.ActiveBans));

        var ban = Assert.Single(await h.GetAsync<List<BanDto>>(IpcMethods.ListBans));
        Assert.Equal(ProtocolSource.Manual, ban.Source);
        var statistics = await h.GetAsync<StatisticsDto>(IpcMethods.GetStatistics, new GetStatisticsParams { Days = 7 });
        Assert.Equal(ProtocolSource.Manual, Assert.Single(statistics.Daily).Source);
    }

    [Fact]
    public async Task The_store_keeps_the_manual_source()
    {
        await WithSqliteStoreAsync(async (store, _) =>
        {
            await store.UpsertBanAsync(ActiveBan(Attacker, ProtocolSource.Manual));

            Assert.Equal(ProtocolSource.Manual, (await store.GetBanAsync(Attacker))!.Source);
        });
    }

    // ---------- internal addresses ----------

    [Theory]
    [InlineData("100.64.1.1")]
    [InlineData("198.18.0.1")]
    [InlineData("64:ff9b::a00:1")]
    public async Task Carrier_nat_benchmarking_and_translated_private_peers_are_never_banned(string ip)
    {
        await using var h = await EngineHarness.StartAsync(T0);

        for (var i = 0; i < 5; i++)
        {
            await h.ProcessAsync(h.Fail(ip, NonRdp));
        }

        Assert.Empty(h.Firewall.BlockCalls);
    }

    [Fact]
    public async Task An_attacker_behind_nat64_is_banned()
    {
        await using var h = await EngineHarness.StartAsync(T0);

        for (var i = 0; i < 5; i++)
        {
            await h.ProcessAsync(h.Fail("64:ff9b::808:808", NonRdp));
        }

        Assert.Equal("64:ff9b::808:808", Assert.Single(h.Firewall.BlockCalls));
    }

    // ---------- report-only ----------

    [Fact]
    public async Task Every_ban_message_says_when_nothing_was_enforced()
    {
        await using var h = await EngineHarness.StartAsync(
            T0,
            s => s.ReportOnly = true,
            seed: store => store.AddToListAsync(ListKind.Blacklist, "203.0.113.70"));

        await h.ProcessAsync(h.Fail("203.0.113.70", NonRdp));
        await h.Engine.BanNowAsync("203.0.113.71", null, permanent: true, null);
        await h.Engine.BanNowAsync("203.0.113.72", TimeSpan.FromHours(1), permanent: false, null);
        await SendThresholdAsync(h);

        var messages = h.Store.Events
            .Select(e => e.Message)
            .Where(m => m.StartsWith("BLOCKED", StringComparison.Ordinal) || m.StartsWith("MANUAL BLOCK", StringComparison.Ordinal))
            .ToList();
        Assert.Equal(4, messages.Count);
        Assert.All(messages, message => Assert.EndsWith("(report-only: firewall unchanged)", message));
        AssertFirewallUntouched(h);
    }

    [Fact]
    public async Task Ban_messages_mention_report_only_only_in_report_only_mode()
    {
        await using var h = await EngineHarness.StartAsync(
            T0,
            seed: store => store.AddToListAsync(ListKind.Blacklist, "203.0.113.70"));

        await h.ProcessAsync(h.Fail("203.0.113.70", NonRdp));
        await h.Engine.BanNowAsync("203.0.113.71", null, permanent: true, null);
        await h.Engine.UnbanAsync("203.0.113.71");

        Assert.DoesNotContain(h.Store.Events, e => e.Message.Contains("report-only", StringComparison.Ordinal));
    }

    [Fact]
    public async Task In_report_only_mode_expiry_and_unban_leave_the_firewall_alone_and_say_so()
    {
        await using var h = await EngineHarness.StartAsync(T0, s => s.ReportOnly = true);
        await SendThresholdAsync(h);
        await h.Engine.BanNowAsync("203.0.113.71", null, permanent: true, null);

        await ExpireAsync(h, TimeSpan.FromHours(25));
        await h.Engine.UnbanAsync("203.0.113.71");

        AssertFirewallUntouched(h);
        Assert.Contains(h.Store.Events, e => e.Message == $"UNBANNED {Attacker} (report-only: firewall unchanged)");
        Assert.Contains(h.Store.Events, e => e.Message == "MANUAL UNBLOCK 203.0.113.71 (report-only: firewall unchanged)");
    }

    [Fact]
    public async Task A_rule_from_before_report_only_outlives_its_ban_until_the_mode_is_switched_off()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        await SendThresholdAsync(h);
        Assert.Contains(Attacker, h.Firewall.Blocked);

        h.Settings.ReportOnly = true;
        await ExpireAsync(h, TimeSpan.FromHours(25));
        Assert.Contains(Attacker, h.Firewall.Blocked);

        h.Settings.ReportOnly = false;
        await h.Engine.HousekeepOnceAsync();
        Assert.DoesNotContain(Attacker, h.Firewall.Blocked);
    }

    // ---------- statistics ----------

    [Theory]
    [InlineData(10, "2026-03-01T20:00:00Z", "2026-03-02")] // local day ahead of the UTC day
    [InlineData(-10, "2026-03-02T04:00:00Z", "2026-03-01")] // local day behind the UTC day
    public async Task The_statistics_window_counts_the_same_local_days_the_engine_buckets_by(int offsetHours, string utcNow, string localToday)
    {
        await using var h = await IpcHarness.StartAsync(DateTimeOffset.Parse(utcNow), TimeSpan.FromHours(offsetHours));
        var today = DateTime.Parse(localToday);

        await h.Engine.BanNowAsync(Attacker, TimeSpan.FromHours(1), permanent: false, null);
        await h.Engine.HousekeepOnceAsync();
        await h.Store.AddDailyStatsAsync(today.AddDays(-1), NonRdp, 7, 0);

        var oneDay = await h.GetAsync<StatisticsDto>(IpcMethods.GetStatistics, new GetStatisticsParams { Days = 1 });
        Assert.Equal(today, Assert.Single(oneDay.Daily).DayUtc.Date);

        var twoDays = await h.GetAsync<StatisticsDto>(IpcMethods.GetStatistics, new GetStatisticsParams { Days = 2 });
        Assert.Equal(2, twoDays.Daily.Count);
    }

    [Fact]
    public async Task Daily_statistics_the_store_refuses_survive_for_the_next_flush()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        await h.ProcessAsync(h.Fail(Attacker, NonRdp));
        await h.ProcessAsync(h.Fail(Attacker, ProtocolSource.Ftp));

        h.Store.FailStatsWrites = true;
        await h.Engine.HousekeepOnceAsync();
        Assert.Empty(h.Store.DailyStats);

        await h.ProcessAsync(h.Fail(Attacker, NonRdp)); // arrives while the deltas wait
        h.Store.FailStatsWrites = false;
        await h.Engine.HousekeepOnceAsync();
        await h.Engine.HousekeepOnceAsync();

        Assert.Equal(2, h.Store.DailyStats.Single(pair => pair.Key.Source == NonRdp).Value.Detections);
        Assert.Equal(1, h.Store.DailyStats.Single(pair => pair.Key.Source == ProtocolSource.Ftp).Value.Detections);
    }

    // ---------- offense tracker ----------

    [Fact]
    public void Touching_an_ip_without_a_count_creates_nothing()
    {
        var tracker = new OffenseTracker();
        var old = T0.UtcDateTime;

        tracker.Touch(Attacker, old.AddDays(10));
        Assert.Empty(tracker.GetUnsaved().Changed);

        // Had the touch left a time behind, the IP would now look recently active.
        tracker.Seed(Attacker, 1, old);
        Assert.Equal(1, tracker.PruneStale([], old.AddDays(5)));
    }

    [Fact]
    public void Seeding_never_moves_the_last_offense_backwards()
    {
        var tracker = new OffenseTracker();
        var now = T0.UtcDateTime;

        tracker.Seed(Attacker, 2, now);
        tracker.Seed(Attacker, 1, now.AddDays(-50));

        Assert.Equal(2, tracker.GetCount(Attacker));
        Assert.Equal(0, tracker.PruneStale([], now.AddDays(-1)));
    }

    // ---------- firewall reconcile ----------

    [Fact]
    public async Task An_unreadable_firewall_is_left_alone_instead_of_retrying_every_ban()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        await BanSeveralAsync(h);
        var blocksBefore = h.Firewall.BlockCalls.Count;
        var syncsBefore = h.Firewall.SyncRulesCalls.Count;

        h.Firewall.FailListBlocked = true;
        await h.Engine.HousekeepOnceAsync();

        Assert.Equal(blocksBefore, h.Firewall.BlockCalls.Count);
        Assert.Equal(syncsBefore, h.Firewall.SyncRulesCalls.Count);
        Assert.Empty(h.Firewall.UnblockCalls);
    }

    [Fact]
    public async Task A_firewall_reset_is_healed_by_one_call()
    {
        await using var h = await EngineHarness.StartAsync(T0, seed: store => store.AddToListAsync(ListKind.Blacklist, Range));
        await BanSeveralAsync(h);
        var blocksBefore = h.Firewall.BlockCalls.Count;
        var syncsBefore = h.Firewall.SyncRulesCalls.Count;

        h.Firewall.ClearAll();
        await h.Engine.HousekeepOnceAsync();

        Assert.Equal(syncsBefore + 1, h.Firewall.SyncRulesCalls.Count);
        Assert.Equal(blocksBefore, h.Firewall.BlockCalls.Count);
        Assert.Equal(4, h.Firewall.Blocked.Count);
        Assert.Contains(Range, h.Firewall.Blocked);
    }

    [Fact]
    public async Task A_firewall_that_matches_is_not_written_to()
    {
        await using var h = await EngineHarness.StartAsync(T0, seed: store => store.AddToListAsync(ListKind.Blacklist, Range));
        await BanSeveralAsync(h);
        await h.Engine.HousekeepOnceAsync();
        var syncsBefore = h.Firewall.SyncRulesCalls.Count;

        await h.Engine.HousekeepOnceAsync();

        Assert.Equal(syncsBefore, h.Firewall.SyncRulesCalls.Count);
    }

    [Fact]
    public async Task Reconcile_removes_an_orphan_rule()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        await BanSeveralAsync(h);

        h.Firewall.Block("192.0.2.200");
        await h.Engine.HousekeepOnceAsync();

        Assert.DoesNotContain("192.0.2.200", h.Firewall.Blocked);
        Assert.Equal(3, h.Firewall.Blocked.Count);
    }

    [Fact]
    public async Task Reconcile_does_not_treat_an_unsaved_ban_as_an_orphan()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        h.Store.FailWrites = true;
        await SendThresholdAsync(h);

        await h.Engine.HousekeepOnceAsync();

        Assert.Contains(Attacker, h.Firewall.Blocked);
    }

    // ---------- settings bounds ----------

    [Fact]
    public async Task Extreme_durations_are_clamped_so_housekeeping_and_bans_keep_working()
    {
        await using var h = await EngineHarness.StartAsync(
            T0,
            s =>
            {
                s.ExpireTime = TimeSpan.MaxValue;
                s.CountWindow = TimeSpan.MaxValue;
                s.MsSql.CountWindow = TimeSpan.MaxValue;
                s.OffenseMemory = TimeSpan.MaxValue;
                s.Normalize();
            });

        await SendThresholdAsync(h);
        await h.Engine.HousekeepOnceAsync();

        Assert.Contains(Attacker, h.Firewall.Blocked);
        Assert.Equal(TimeSpan.FromDays(3650), h.Settings.ExpireTime);
        Assert.Equal(TimeSpan.FromDays(3650), h.Settings.CountWindow);
        Assert.Equal(TimeSpan.FromDays(3650), h.Settings.MsSql.CountWindow);
    }

    [Fact]
    public void Expire_time_cannot_cut_a_count_window_short()
    {
        var settings = new WinGuardSettings { ExpireTime = TimeSpan.FromMinutes(1), CountWindow = TimeSpan.FromMinutes(10) };
        settings.Normalize();
        Assert.Equal(TimeSpan.FromMinutes(10), settings.ExpireTime);

        settings.Ftp.CountWindow = TimeSpan.FromHours(3);
        settings.Normalize();
        Assert.Equal(TimeSpan.FromHours(3), settings.ExpireTime);
    }

    [Fact]
    public void An_expire_time_longer_than_every_window_is_left_alone()
    {
        var settings = new WinGuardSettings { ExpireTime = TimeSpan.FromDays(2) };

        settings.Normalize();

        Assert.Equal(TimeSpan.FromDays(2), settings.ExpireTime);
    }

    [Fact]
    public void A_per_protocol_window_that_means_nothing_falls_back_to_the_global_one()
    {
        var settings = new WinGuardSettings();
        settings.Rdp.CountWindow = TimeSpan.Zero;
        settings.MsSql.CountWindow = TimeSpan.FromMinutes(-5);

        settings.Normalize();

        Assert.Equal(settings.CountWindow, settings.CountWindowFor(ProtocolSource.Rdp));
        Assert.Equal(settings.CountWindow, settings.CountWindowFor(ProtocolSource.MsSql));
    }

    [Fact]
    public async Task A_timer_interval_cannot_exceed_what_a_timer_can_wait_for()
    {
        var settings = new WinGuardSettings { HousekeepingInterval = TimeSpan.MaxValue };
        settings.Ftp.PollInterval = TimeSpan.MaxValue;

        settings.Normalize();

        // Task.Delay throws for anything it cannot represent, which would end the polling loop.
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Task.Delay(settings.HousekeepingInterval, cancelled.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Task.Delay(settings.Ftp.PollInterval, cancelled.Token));
    }

    [Fact]
    public void Ban_history_retention_is_normalized()
    {
        var zero = new WinGuardSettings { BanHistoryRetentionDays = 0 };
        zero.Normalize();
        Assert.Equal(365, zero.BanHistoryRetentionDays);

        var huge = new WinGuardSettings { BanHistoryRetentionDays = 100000 };
        huge.Normalize();
        Assert.Equal(3650, huge.BanHistoryRetentionDays);
    }

    [Fact]
    public void Blocked_ports_the_firewall_would_refuse_are_dropped()
    {
        var settings = new WinGuardSettings { BlockedPorts = ["3389", " 21-22 ", "70000", "500-100", "1-2-3", "-5", "5-", "ftp", "0", "65535"] };

        settings.Normalize();

        Assert.Equal(["3389", "21-22", "0", "65535"], settings.BlockedPorts);
    }

    // ---------- smaller fixes ----------

    [Fact]
    public async Task The_server_stays_protected_from_itself_when_the_lists_cannot_be_read()
    {
        await using var h = await EngineHarness.StartAsync(
            T0,
            s => s.ProcessInternalIPs = true,
            seed: store =>
            {
                store.FailListRead = true;
                return Task.CompletedTask;
            });

        for (var i = 0; i < 5; i++)
        {
            await h.ProcessAsync(h.Fail("127.0.0.1", NonRdp));
        }

        Assert.Empty(h.Firewall.BlockCalls);
    }

    [Fact]
    public async Task A_manual_ban_is_enforced_while_the_store_refuses_writes()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        h.Store.FailWrites = true;

        await h.Engine.BanNowAsync(Attacker, null, permanent: true, null);
        Assert.Contains(Attacker, h.Firewall.Blocked);

        h.Store.FailWrites = false;
        await h.Engine.HousekeepOnceAsync();

        Assert.True((await h.Store.GetBanAsync(Attacker))!.IsPermanent);
    }

    [Fact]
    public async Task Stopping_saves_a_ban_the_store_refused()
    {
        var h = await EngineHarness.StartAsync(T0);
        h.Store.FailWrites = true;
        await SendThresholdAsync(h);

        h.Store.FailWrites = false;
        await h.DisposeAsync();

        Assert.NotNull(await h.Store.GetBanAsync(Attacker));
    }

    [Fact]
    public async Task Unbanning_an_ip_with_no_ban_records_nothing()
    {
        await using var h = await EngineHarness.StartAsync(T0);

        await h.Engine.UnbanAsync(Attacker);

        Assert.Empty(h.Store.BanHistory);
        Assert.DoesNotContain(h.Store.Events, e => e.Message.StartsWith("MANUAL UNBLOCK", StringComparison.Ordinal));
    }

    [Fact]
    public async Task An_unban_history_row_describes_the_ban_it_ended()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        await SendThresholdAsync(h);

        await h.Engine.UnbanAsync(Attacker);

        var row = h.Store.BanHistory.Last();
        Assert.Equal(BanHistoryAction.Unbanned, row.Action);
        Assert.Equal(NonRdp, row.Source);
        Assert.Equal(1, row.OffenseCount);
    }

    [Fact]
    public async Task An_expired_ban_the_store_will_not_delete_is_recorded_once()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        await SendThresholdAsync(h);

        h.Store.FailBanRemoval = true;
        await ExpireAsync(h, TimeSpan.FromHours(25), expectRemoved: false);
        await h.Engine.HousekeepOnceAsync();
        Assert.DoesNotContain(h.Store.BanHistory, row => row.Action == BanHistoryAction.Expired);

        h.Store.FailBanRemoval = false;
        await h.Engine.HousekeepOnceAsync();
        await h.Engine.HousekeepOnceAsync();

        Assert.Single(h.Store.BanHistory, row => row.Action == BanHistoryAction.Expired);
    }

    // ---------- helpers ----------

    private static BanEntry ActiveBan(string ip, ProtocolSource source = NonRdp) => new()
    {
        IpAddress = ip,
        Source = source,
        BannedAtUtc = T0.UtcDateTime,
        ExpiresUtc = T0.UtcDateTime.AddDays(1),
    };

    private static BanHistoryEntry History(string ip, DateTime atUtc, int offense = 1) => new()
    {
        TimestampUtc = atUtc,
        Action = BanHistoryAction.Banned,
        IpAddress = ip,
        Source = NonRdp,
        OffenseCount = offense,
    };

    private static void AssertFirewallUntouched(EngineHarness h)
    {
        Assert.Empty(h.Firewall.BlockCalls);
        Assert.Empty(h.Firewall.UnblockCalls);
        Assert.Empty(h.Firewall.SyncRulesCalls);
        Assert.Equal(0, h.Firewall.ClearAllCallCount);
    }

    private static async Task SendThresholdAsync(EngineHarness h, string ip = Attacker)
    {
        for (var i = 0; i < h.Settings.FailedLoginThreshold; i++)
        {
            await h.ProcessAsync(h.Fail(ip, NonRdp));
        }
    }

    private static async Task BanSeveralAsync(EngineHarness h)
    {
        foreach (var ip in new[] { "203.0.113.61", "203.0.113.62", "203.0.113.63" })
        {
            await SendThresholdAsync(h, ip);
        }
    }

    private static async Task ExpireAsync(EngineHarness h, TimeSpan after, bool expectRemoved = true)
    {
        h.Time.Advance(after);
        await h.Engine.HousekeepOnceAsync();
        if (expectRemoved)
        {
            Assert.Null(await h.Store.GetBanAsync(Attacker));
        }
    }

    private static async Task WithSqliteStoreAsync(Func<SqliteStore, string, Task> test)
    {
        var dir = Path.Combine(Path.GetTempPath(), "winguard-r5-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "test.db");
        try
        {
            await using var store = new SqliteStore(path, NullLogger<SqliteStore>.Instance);
            await store.InitializeAsync();
            await test(store, path);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            try
            {
                Directory.Delete(dir, recursive: true);
            }
            catch (IOException)
            {
                // Best effort.
            }
        }
    }

    /// <summary>The request handler over fakes, in a chosen local time zone.</summary>
    private sealed class IpcHarness : IAsyncDisposable
    {
        private long _nextId;

        private IpcHarness(DateTimeOffset now, TimeSpan utcOffset)
        {
            Time = new FakeTimeProvider(now)
            {
                LocalZone = TimeZoneInfo.CreateCustomTimeZone("test", utcOffset, "test", "test"),
            };
        }

        public FakeStore Store { get; } = new();

        public FakeFirewall Firewall { get; } = new();

        public FakeTimeProvider Time { get; }

        public BanEngine Engine { get; private set; } = null!;

        public IpcRequestHandler Handler { get; private set; } = null!;

        public static async Task<IpcHarness> StartAsync(DateTimeOffset now, TimeSpan utcOffset)
        {
            var h = new IpcHarness(now, utcOffset);
            var holder = new SettingsHolder(h.Store, NullLogger<SettingsHolder>.Instance);
            await holder.ApplyAsync(new WinGuardSettings { HousekeepingInterval = TimeSpan.FromHours(6) });

            h.Engine = new BanEngine(h.Store, h.Firewall, () => holder.Current, NullLogger<BanEngine>.Instance, h.Time);
            await h.Engine.StartAsync(CancellationToken.None);
            h.Handler = new IpcRequestHandler(
                h.Store,
                h.Engine,
                holder,
                h.Firewall,
                new DetectorRuntimeState(),
                h.Time,
                NullLogger<IpcRequestHandler>.Instance);
            return h;
        }

        public async Task<T> GetAsync<T>(string method, object? parameters = null)
        {
            var response = await CallAsync(method, parameters);
            Assert.True(response.Ok, response.Error);
            return response.Result!.Value.Deserialize<T>(IpcJson.Options)!;
        }

        public async Task SendAsync(string method, object parameters)
        {
            var response = await CallAsync(method, parameters);
            Assert.True(response.Ok, response.Error);
        }

        public ValueTask DisposeAsync() => new(Engine.StopAsync(CancellationToken.None));

        private async Task<IpcResponse> CallAsync(string method, object? parameters)
        {
            var request = new IpcRequest
            {
                Id = ++_nextId,
                Method = method,
                Params = parameters is null ? null : JsonSerializer.SerializeToElement(parameters, IpcJson.Options),
            };

            var line = await Handler.HandleLineAsync(JsonSerializer.Serialize(request, IpcJson.Options), CancellationToken.None);
            return JsonSerializer.Deserialize<IpcResponse>(line!, IpcJson.Options)!;
        }
    }
}
