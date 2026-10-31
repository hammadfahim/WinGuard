using System.Text.Json;
using WinGuard.Core.Config;
using WinGuard.Core.Ipc;
using WinGuard.Core.Model;
using WinGuard.Core.Tests.Fakes;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>The detection rules on failures: honeypot user names, password spraying and slow brute force.</summary>
public sealed class BanEngineRulesTests
{
    private static readonly DateTimeOffset T0 = new(2026, 3, 1, 0, 0, 0, TimeSpan.Zero);

    private const ProtocolSource NonRdp = ProtocolSource.MsSql;

    private static void Honeypot(WinGuardSettings s) => s.Rules.HoneypotUsernames = ["admin", "test"];

    private static void Spray(WinGuardSettings s) => s.Rules.SprayMaxUsernames = 3;

    private static void Slow(WinGuardSettings s)
    {
        s.Rules.SlowBruteForceThreshold = 6;
        s.Rules.SlowBruteForceWindow = TimeSpan.FromHours(24);
    }

    private static FailedLogin Replayed(FailedLogin failed)
    {
        failed.IsReplayed = true;
        return failed;
    }

    // ---------- honeypot user names ----------

    [Fact]
    public async Task A_honeypot_name_bans_on_the_first_attempt_and_says_why()
    {
        await using var h = await EngineHarness.StartAsync(T0, Honeypot);
        const string ip = "203.0.113.1";

        await h.ProcessAsync(h.Fail(ip, NonRdp, user: "admin"));

        var ban = await h.Store.GetBanAsync(ip);
        Assert.NotNull(ban);
        Assert.Equal("honeypot user 'admin'", ban!.Note);
        Assert.Contains(ip, h.Firewall.Blocked);

        var history = Assert.Single(h.Store.BanHistory, entry => entry.Action == BanHistoryAction.Banned);
        Assert.Equal("honeypot user 'admin'", history.Note);

        var logged = Assert.Single(h.Store.Events, e => e.Message.StartsWith("BLOCKED", StringComparison.Ordinal));
        Assert.Equal($"BLOCKED {ip} for 1.00:00:00 (honeypot user 'admin') (offense #1)", logged.Message);
        Assert.Equal(LogEventLevel.Warning, logged.Level);
    }

    [Theory]
    [InlineData("ADMIN")]
    [InlineData("Admin")]
    [InlineData(@"EXAMPLE\admin")]
    [InlineData(@".\admin")]
    [InlineData("admin@example.com")]
    [InlineData(@"EXAMPLE\Admin@example.com")]
    [InlineData("  admin ")]
    public async Task Honeypot_names_match_case_insensitively_without_the_domain(string user)
    {
        await using var h = await EngineHarness.StartAsync(T0, Honeypot);

        await h.ProcessAsync(h.Fail("203.0.113.2", NonRdp, user: user));

        Assert.Equal("honeypot user 'admin'", (await h.Store.GetBanAsync("203.0.113.2"))?.Note);
    }

    [Theory]
    [InlineData("administrator")]
    [InlineData("admin1")]
    [InlineData("xadmin")]
    [InlineData("adm*")]
    [InlineData("bob")]
    [InlineData(null)]
    public async Task Only_an_exact_name_is_a_honeypot(string? user)
    {
        await using var h = await EngineHarness.StartAsync(T0, s => s.Rules.HoneypotUsernames = ["admin", "adm"]);

        await h.ProcessAsync(h.Fail("203.0.113.3", NonRdp, user: user));

        Assert.Null(await h.Store.GetBanAsync("203.0.113.3"));
    }

    [Fact]
    public async Task A_wildcard_entry_is_a_literal_name_not_a_pattern()
    {
        await using var h = await EngineHarness.StartAsync(T0, s => s.Rules.HoneypotUsernames = ["adm*"]);

        await h.ProcessAsync(h.Fail("203.0.113.3", NonRdp, user: "admin"));

        Assert.Null(await h.Store.GetBanAsync("203.0.113.3"));
    }

    [Fact]
    public async Task Honeypot_bans_escalate_through_the_normal_tiers()
    {
        await using var h = await EngineHarness.StartAsync(T0, Honeypot);
        const string ip = "203.0.113.4";

        await h.ProcessAsync(h.Fail(ip, NonRdp, user: "admin"));
        h.Time.Advance(TimeSpan.FromHours(25));
        await h.Engine.HousekeepOnceAsync();
        await h.ProcessAsync(h.Fail(ip, NonRdp, user: "test"));

        var ban = await h.Store.GetBanAsync(ip);
        Assert.Equal(2, ban!.OffenseCount);
        Assert.Equal(TimeSpan.FromDays(7), ban.ExpiresUtc - ban.BannedAtUtc);
        Assert.Contains(h.Store.Events, e => e.Message == $"BLOCKED {ip} for 7.00:00:00 (honeypot user 'test') (offense #2)");
    }

    [Fact]
    public async Task The_whitelist_beats_a_honeypot_name()
    {
        await using var h = await EngineHarness.StartAsync(T0, Honeypot, seed: s => s.AddToListAsync(ListKind.Whitelist, "203.0.113.5"));

        await h.ProcessAsync(h.Fail("203.0.113.5", NonRdp, user: "admin"));

        Assert.Null(await h.Store.GetBanAsync("203.0.113.5"));
        Assert.Empty(h.Firewall.BlockCalls);
    }

    [Fact]
    public async Task Internal_addresses_stay_ignored_unless_enabled()
    {
        await using var ignoring = await EngineHarness.StartAsync(T0, Honeypot);
        await ignoring.ProcessAsync(ignoring.Fail("10.0.0.5", NonRdp, user: "admin"));
        Assert.Null(await ignoring.Store.GetBanAsync("10.0.0.5"));

        await using var processing = await EngineHarness.StartAsync(T0, s =>
        {
            Honeypot(s);
            s.ProcessInternalIPs = true;
        });
        await processing.ProcessAsync(processing.Fail("10.0.0.5", NonRdp, user: "admin"));
        Assert.NotNull(await processing.Store.GetBanAsync("10.0.0.5"));
    }

    [Fact]
    public async Task Report_only_records_a_honeypot_ban_without_blocking()
    {
        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            Honeypot(s);
            s.ReportOnly = true;
        });
        const string ip = "203.0.113.6";

        await h.ProcessAsync(h.Fail(ip, NonRdp, user: "admin"));

        Assert.NotNull(await h.Store.GetBanAsync(ip));
        Assert.Empty(h.Firewall.BlockCalls);
        var logged = Assert.Single(h.Store.Events, e => e.Message.StartsWith("BLOCKED", StringComparison.Ordinal));
        Assert.Contains("honeypot user 'admin'", logged.Message, StringComparison.Ordinal);
        Assert.Contains("report-only", logged.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_excluded_event_never_fires_a_rule()
    {
        await using var h = await EngineHarness.StartAsync(T0, Honeypot);
        var failed = h.Fail("203.0.113.7", ProtocolSource.Rdp, user: "admin", detector: "4625");
        failed.IsExcluded = true;

        await h.ProcessAsync(failed);

        Assert.Null(await h.Store.GetBanAsync("203.0.113.7"));
        Assert.Empty(h.Store.FailedLogins);
    }

    [Fact]
    public async Task A_4625_merged_into_an_earlier_140_still_fires_the_honeypot()
    {
        await using var h = await EngineHarness.StartAsync(T0, Honeypot);
        const string ip = "203.0.113.8";

        await h.ProcessAsync(h.Fail(ip, ProtocolSource.Rdp, user: null, detector: "140"));
        Assert.Null(await h.Store.GetBanAsync(ip));

        await h.ProcessAsync(h.Fail(ip, ProtocolSource.Rdp, user: "admin", detector: "4625"));

        Assert.Equal("honeypot user 'admin'", (await h.Store.GetBanAsync(ip))?.Note);
        Assert.Equal(1, h.Engine.GetDetectionsToday(ProtocolSource.Rdp));
    }

    [Fact]
    public async Task A_4625_merged_into_an_excluded_140_stays_dropped()
    {
        await using var h = await EngineHarness.StartAsync(T0, Honeypot);
        const string ip = "203.0.113.9";
        var excluded = h.Fail(ip, ProtocolSource.Rdp, user: null, detector: "140");
        excluded.IsExcluded = true;

        await h.ProcessAsync(excluded);
        await h.ProcessAsync(h.Fail(ip, ProtocolSource.Rdp, user: "admin", detector: "4625"));

        Assert.Null(await h.Store.GetBanAsync(ip));
        Assert.Empty(h.Store.FailedLogins);
    }

    [Fact]
    public async Task A_replayed_honeypot_attempt_the_last_run_handled_stays_handled()
    {
        const string ip = "203.0.113.10";
        var store = new FakeStore();
        var attempted = T0.AddMinutes(-1).UtcDateTime;
        await using (await EngineHarness.StartAsync(T0, Honeypot, store: store))
        {
        }

        await using var second = await EngineHarness.StartAsync(T0.AddMinutes(5), Honeypot, store: store);
        await second.ProcessAsync(Replayed(second.Fail(ip, NonRdp, user: "admin", at: attempted)));

        Assert.Null(await store.GetBanAsync(ip));
    }

    [Fact]
    public async Task A_honeypot_attempt_logged_while_the_service_was_down_bans_on_replay()
    {
        const string ip = "203.0.113.11";
        var store = new FakeStore();
        await using (await EngineHarness.StartAsync(T0, Honeypot, store: store))
        {
        }

        await using var second = await EngineHarness.StartAsync(T0.AddMinutes(5), Honeypot, store: store);
        await second.ProcessAsync(Replayed(second.Fail(ip, NonRdp, user: "admin", at: T0.AddMinutes(1).UtcDateTime)));

        Assert.Equal("honeypot user 'admin'", (await store.GetBanAsync(ip))?.Note);
    }

    [Fact]
    public async Task A_honeypot_name_bans_the_aggregated_prefix()
    {
        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            Honeypot(s);
            s.Ipv6AggregatePrefixLength = 64;
        });

        await h.ProcessAsync(h.Fail("2001:db8:1:2::5", NonRdp, user: "admin"));

        Assert.NotNull(await h.Store.GetBanAsync("2001:db8:1:2::/64"));
        Assert.Equal("2001:db8:1:2::/64", Assert.Single(h.Firewall.BlockCalls));
    }

    [Fact]
    public async Task A_rule_switched_on_applies_to_the_next_failure()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        await h.ProcessAsync(h.Fail("203.0.113.12", NonRdp, user: "admin"));
        Assert.Null(await h.Store.GetBanAsync("203.0.113.12"));

        h.Settings.Rules.HoneypotUsernames = ["admin"];
        await h.ProcessAsync(h.Fail("203.0.113.12", NonRdp, user: "admin"));

        Assert.NotNull(await h.Store.GetBanAsync("203.0.113.12"));
    }

    // ---------- password spraying ----------

    [Fact]
    public async Task Reaching_the_distinct_user_limit_bans_across_engines()
    {
        await using var h = await EngineHarness.StartAsync(T0, Spray);
        const string ip = "203.0.113.20";

        await h.ProcessAsync(h.Fail(ip, ProtocolSource.MsSql, user: "alice"));
        await h.ProcessAsync(h.Fail(ip, ProtocolSource.Ftp, user: "bob"));
        Assert.Null(await h.Store.GetBanAsync(ip));

        await h.ProcessAsync(h.Fail(ip, ProtocolSource.Custom, user: "carol"));

        var ban = await h.Store.GetBanAsync(ip);
        Assert.Equal("password spraying: 3 usernames in 01:00:00", ban?.Note);
        Assert.Contains(h.Store.Events, e => e.Message == $"BLOCKED {ip} for 1.00:00:00 (password spraying: 3 usernames in 01:00:00) (offense #1)");
    }

    [Fact]
    public async Task The_same_user_written_differently_is_one_user()
    {
        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            Spray(s);
            s.FailedLoginThreshold = 100;
        });
        const string ip = "203.0.113.21";

        foreach (var user in new[] { "bob", "BOB", @"EXAMPLE\bob", "bob@example.com", @"OTHER\Bob" })
        {
            await h.ProcessAsync(h.Fail(ip, NonRdp, user: user));
        }

        Assert.Null(await h.Store.GetBanAsync(ip));
    }

    [Fact]
    public async Task Failures_without_a_user_name_are_not_a_user()
    {
        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            s.Rules.SprayMaxUsernames = 2;
            s.FailedLoginThreshold = 100;
        });
        const string ip = "203.0.113.22";

        await h.ProcessAsync(h.Fail(ip, NonRdp, user: "bob"));
        for (var i = 0; i < 4; i++)
        {
            h.Time.Advance(TimeSpan.FromSeconds(10));
            await h.ProcessAsync(h.Fail(ip, ProtocolSource.Rdp, user: null, detector: "140"));
        }

        Assert.Null(await h.Store.GetBanAsync(ip));
    }

    [Fact]
    public async Task A_nameless_failure_costs_the_spray_rule_no_query()
    {
        await using var h = await EngineHarness.StartAsync(T0, s => s.Rules.SprayMaxUsernames = 2);

        await h.ProcessAsync(h.Fail("203.0.113.23", ProtocolSource.Rdp, user: null, detector: "140"));

        Assert.Equal(0, h.Store.FailureReads);
    }

    [Fact]
    public async Task Users_outside_the_window_do_not_count()
    {
        await using var h = await EngineHarness.StartAsync(T0, Spray);
        const string ip = "203.0.113.24";

        await h.ProcessAsync(h.Fail(ip, NonRdp, user: "alice"));
        await h.ProcessAsync(h.Fail(ip, NonRdp, user: "bob"));
        h.Time.Advance(TimeSpan.FromMinutes(61));
        await h.ProcessAsync(h.Fail(ip, NonRdp, user: "carol"));

        Assert.Null(await h.Store.GetBanAsync(ip));
    }

    [Fact]
    public async Task The_user_of_a_4625_merged_into_a_140_still_counts()
    {
        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            s.Rules.SprayMaxUsernames = 2;
            s.FailedLoginThreshold = 100;
        });
        const string ip = "203.0.113.25";

        await h.ProcessAsync(h.Fail(ip, ProtocolSource.Rdp, user: null, detector: "140"));
        await h.ProcessAsync(h.Fail(ip, ProtocolSource.Rdp, user: "alice", detector: "4625"));

        var row = Assert.Single(h.Store.FailedLogins);
        Assert.Equal("alice", row.UserName);

        h.Time.Advance(TimeSpan.FromSeconds(10));
        await h.ProcessAsync(h.Fail(ip, ProtocolSource.Rdp, user: null, detector: "140"));
        await h.ProcessAsync(h.Fail(ip, ProtocolSource.Rdp, user: "bob", detector: "4625"));

        Assert.NotNull(await h.Store.GetBanAsync(ip));
    }

    [Fact]
    public async Task Overlapping_140_and_4625_pairs_keep_every_user_name()
    {
        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            s.Rules.SprayMaxUsernames = 3;
            s.FailedLoginThreshold = 100;
        });
        const string ip = "203.0.113.26";

        await h.ProcessAsync(h.Fail(ip, ProtocolSource.Rdp, user: null, detector: "140"));
        await h.ProcessAsync(h.Fail(ip, ProtocolSource.Rdp, user: null, detector: "140"));
        await h.ProcessAsync(h.Fail(ip, ProtocolSource.Rdp, user: "alice", detector: "4625"));
        await h.ProcessAsync(h.Fail(ip, ProtocolSource.Rdp, user: "bob", detector: "4625"));

        Assert.Equal(new[] { "alice", "bob" }, h.Store.FailedLogins.Select(f => f.UserName).OrderBy(u => u));
    }

    [Fact]
    public async Task Spraying_inside_an_aggregated_prefix_counts_as_one_attacker()
    {
        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            Spray(s);
            s.Ipv6AggregatePrefixLength = 64;
        });

        await h.ProcessAsync(h.Fail("2001:db8:1:2::1", NonRdp, user: "alice"));
        await h.ProcessAsync(h.Fail("2001:db8:1:2::2", NonRdp, user: "bob"));
        await h.ProcessAsync(h.Fail("2001:db8:1:2::3", NonRdp, user: "carol"));

        Assert.NotNull(await h.Store.GetBanAsync("2001:db8:1:2::/64"));
    }

    [Fact]
    public async Task Replayed_failures_the_last_run_handled_add_no_users()
    {
        const string ip = "203.0.113.27";
        var store = new FakeStore();
        await using (var first = await EngineHarness.StartAsync(T0.AddMinutes(-5), Spray, store: store))
        {
            await first.ProcessAsync(first.Fail(ip, NonRdp, user: "alice"));
            await first.ProcessAsync(first.Fail(ip, NonRdp, user: "bob"));
            first.Time.Advance(TimeSpan.FromMinutes(5));
        }

        await using var second = await EngineHarness.StartAsync(T0.AddMinutes(1), Spray, store: store);
        await second.ProcessAsync(Replayed(second.Fail(ip, NonRdp, user: "carol", at: T0.AddMinutes(-1).UtcDateTime)));

        Assert.Null(await store.GetBanAsync(ip));
        Assert.Equal(2, store.FailedLogins.Count);
    }

    [Fact]
    public async Task The_whitelist_and_report_only_apply_to_spraying()
    {
        await using var h = await EngineHarness.StartAsync(
            T0,
            s =>
            {
                Spray(s);
                s.ReportOnly = true;
            },
            seed: s => s.AddToListAsync(ListKind.Whitelist, "203.0.113.28"));

        foreach (var user in new[] { "alice", "bob", "carol" })
        {
            await h.ProcessAsync(h.Fail("203.0.113.28", NonRdp, user: user));
            await h.ProcessAsync(h.Fail("203.0.113.29", NonRdp, user: user));
        }

        Assert.Null(await h.Store.GetBanAsync("203.0.113.28"));
        Assert.NotNull(await h.Store.GetBanAsync("203.0.113.29"));
        Assert.Empty(h.Firewall.BlockCalls);
    }

    [Fact]
    public async Task An_unreadable_store_costs_the_rule_not_the_failure()
    {
        await using var h = await EngineHarness.StartAsync(T0, Spray);
        h.Store.FailFailureReads = true;

        await h.ProcessAsync(h.Fail("203.0.113.30", NonRdp, user: "alice"));

        Assert.Single(h.Store.FailedLogins);
        Assert.DoesNotContain(h.Store.Events, e => e.Level == LogEventLevel.Error);
    }

    // ---------- slow brute force ----------

    [Fact]
    public async Task An_attacker_pacing_below_the_normal_rule_is_caught()
    {
        await using var h = await EngineHarness.StartAsync(T0, Slow);
        const string ip = "203.0.113.40";

        for (var i = 0; i < 5; i++)
        {
            await h.ProcessAsync(h.Fail(ip, NonRdp));
            h.Time.Advance(TimeSpan.FromMinutes(30));
            Assert.Null(await h.Store.GetBanAsync(ip));
        }

        await h.ProcessAsync(h.Fail(ip, NonRdp));

        Assert.Equal("slow brute force: 6 failures in 1.00:00:00", (await h.Store.GetBanAsync(ip))?.Note);
        Assert.Contains(h.Store.Events, e => e.Message == $"BLOCKED {ip} for 1.00:00:00 (slow brute force: 6 failures in 1.00:00:00) (offense #1)");
    }

    [Fact]
    public async Task Failures_add_up_across_engines()
    {
        await using var h = await EngineHarness.StartAsync(T0, Slow);
        const string ip = "203.0.113.41";

        foreach (var source in new[] { ProtocolSource.MsSql, ProtocolSource.Ftp, ProtocolSource.Custom })
        {
            await h.ProcessAsync(h.Fail(ip, source));
            await h.ProcessAsync(h.Fail(ip, source));
        }

        Assert.NotNull(await h.Store.GetBanAsync(ip));
    }

    [Fact]
    public async Task The_normal_rule_is_unchanged_and_keeps_its_plain_text()
    {
        const string ip = "203.0.113.42";
        await using var plain = await EngineHarness.StartAsync(T0);
        for (var i = 0; i < 5; i++)
        {
            await plain.ProcessAsync(plain.Fail(ip, NonRdp));
        }

        Assert.Null((await plain.Store.GetBanAsync(ip))?.Note);
        Assert.Contains(plain.Store.Events, e => e.Message == $"BLOCKED {ip} for 1.00:00:00 (offense #1)");
    }

    [Fact]
    public async Task Failures_past_the_window_do_not_count()
    {
        await using var h = await EngineHarness.StartAsync(T0, Slow);
        const string ip = "203.0.113.43";

        for (var i = 0; i < 5; i++)
        {
            await h.ProcessAsync(h.Fail(ip, NonRdp));
            h.Time.Advance(TimeSpan.FromHours(5));
        }

        await h.ProcessAsync(h.Fail(ip, NonRdp));

        Assert.Null(await h.Store.GetBanAsync(ip));
    }

    [Fact]
    public async Task Excluded_duplicate_and_whitelisted_failures_do_not_count()
    {
        await using var h = await EngineHarness.StartAsync(
            T0,
            s => s.Rules.SlowBruteForceThreshold = 2,
            seed: s => s.AddToListAsync(ListKind.Whitelist, "203.0.113.45"));
        const string ip = "203.0.113.44";

        var excluded = h.Fail(ip, ProtocolSource.Rdp, detector: "4625");
        excluded.IsExcluded = true;
        await h.ProcessAsync(excluded);
        await h.ProcessAsync(h.Fail(ip, ProtocolSource.Rdp, user: null, detector: "140"));

        await h.ProcessAsync(h.Fail("203.0.113.45", NonRdp));
        await h.ProcessAsync(h.Fail("203.0.113.45", NonRdp));

        Assert.Empty(await h.Store.GetActiveBansAsync());
    }

    [Fact]
    public async Task A_replayed_failure_the_last_run_counted_is_not_counted_twice()
    {
        const string ip = "203.0.113.46";
        var store = new FakeStore();
        var attempts = new List<DateTime>();
        await using (var first = await EngineHarness.StartAsync(T0.AddMinutes(-10), s => s.Rules.SlowBruteForceThreshold = 4, store: store))
        {
            for (var i = 0; i < 3; i++)
            {
                var attempt = first.Fail(ip, NonRdp);
                attempts.Add(attempt.TimestampUtc);
                await first.ProcessAsync(attempt);
                first.Time.Advance(TimeSpan.FromMinutes(3));
            }
        }

        await using var second = await EngineHarness.StartAsync(T0, s => s.Rules.SlowBruteForceThreshold = 4, store: store);
        foreach (var at in attempts)
        {
            await second.ProcessAsync(Replayed(second.Fail(ip, NonRdp, at: at)));
        }

        Assert.Null(await store.GetBanAsync(ip));
        Assert.Equal(3, store.FailedLogins.Count);
    }

    [Fact]
    public async Task Failures_counted_during_a_store_outage_still_add_up()
    {
        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            s.Rules.SlowBruteForceThreshold = 3;
            s.FailedLoginThreshold = 100;
        });
        const string ip = "203.0.113.47";
        h.Store.FailWrites = true;

        await h.ProcessAsync(h.Fail(ip, ProtocolSource.Ftp));
        await h.ProcessAsync(h.Fail(ip, ProtocolSource.MsSql));
        await h.ProcessAsync(h.Fail(ip, ProtocolSource.Custom));

        Assert.Contains(ip, h.Firewall.Blocked);
    }

    [Fact]
    public async Task Housekeeping_keeps_rows_for_a_window_longer_than_the_default_expiry()
    {
        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            s.Rules.SlowBruteForceThreshold = 4;
            s.Rules.SlowBruteForceWindow = TimeSpan.FromDays(3);
            s.Normalize();
        });
        const string ip = "203.0.113.48";

        for (var i = 0; i < 3; i++)
        {
            await h.ProcessAsync(h.Fail(ip, NonRdp));
            h.Time.Advance(TimeSpan.FromHours(20));
            await h.Engine.HousekeepOnceAsync();
        }

        await h.ProcessAsync(h.Fail(ip, NonRdp));

        Assert.NotNull(await h.Store.GetBanAsync(ip));
    }

    // ---------- hot path ----------

    [Fact]
    public async Task With_every_rule_off_a_failure_adds_no_query()
    {
        await using var h = await EngineHarness.StartAsync(T0);

        for (var i = 0; i < 4; i++)
        {
            await h.ProcessAsync(h.Fail("203.0.113.50", NonRdp));
        }

        Assert.Equal(0, h.Store.FailureReads);
    }

    [Fact]
    public async Task A_honeypot_list_alone_adds_no_query()
    {
        await using var h = await EngineHarness.StartAsync(T0, Honeypot);

        await h.ProcessAsync(h.Fail("203.0.113.51", NonRdp, user: "bob"));

        Assert.Equal(0, h.Store.FailureReads);
    }

    [Fact]
    public async Task A_duplicate_with_every_rule_off_stays_dropped_and_costs_nothing()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        const string ip = "203.0.113.52";

        await h.ProcessAsync(h.Fail(ip, ProtocolSource.Rdp, user: null, detector: "140"));
        await h.ProcessAsync(h.Fail(ip, ProtocolSource.Rdp, user: "bob", detector: "4625"));

        Assert.Null(Assert.Single(h.Store.FailedLogins).UserName);
        Assert.Equal(0, h.Store.FailureReads);
    }

    // ---------- settings ----------

    [Fact]
    public void Every_rule_is_off_by_default_and_expiry_stays_as_it_was()
    {
        var settings = new WinGuardSettings();
        settings.Normalize();

        Assert.Empty(settings.Rules.HoneypotUsernames);
        Assert.Equal(0, settings.Rules.SprayMaxUsernames);
        Assert.Equal(0, settings.Rules.SlowBruteForceThreshold);
        Assert.False(settings.Rules.CompromiseAlerts);
        Assert.Equal(0, settings.Rules.TrustAdminIpHours);
        Assert.False(settings.Rules.ObservesLogons());
        Assert.Equal(Defaults.ExpireTime, settings.ExpireTime);
    }

    [Fact]
    public void A_disabled_rule_does_not_raise_the_expiry()
    {
        var settings = new WinGuardSettings();
        settings.Rules.SlowBruteForceWindow = TimeSpan.FromDays(5);
        settings.Rules.SprayWindow = TimeSpan.FromDays(6);
        settings.Rules.CompromiseWindow = TimeSpan.FromDays(7);

        settings.Normalize();

        Assert.Equal(Defaults.ExpireTime, settings.ExpireTime);
    }

    [Theory]
    [InlineData(5, 0, false, 5)]
    [InlineData(0, 6, false, 6)]
    [InlineData(0, 0, true, 7)]
    public void Each_enabled_rule_raises_the_expiry_to_its_window(int slow, int spray, bool alerts, int expectedDays)
    {
        var settings = new WinGuardSettings();
        settings.Rules.SlowBruteForceThreshold = slow == 0 ? 0 : 20;
        settings.Rules.SlowBruteForceWindow = TimeSpan.FromDays(5);
        settings.Rules.SprayMaxUsernames = spray == 0 ? 0 : 5;
        settings.Rules.SprayWindow = TimeSpan.FromDays(6);
        settings.Rules.CompromiseAlerts = alerts;
        settings.Rules.CompromiseWindow = TimeSpan.FromDays(7);

        settings.Normalize();

        Assert.Equal(TimeSpan.FromDays(expectedDays), settings.ExpireTime);
    }

    [Fact]
    public void Normalize_clamps_the_rules()
    {
        var settings = new WinGuardSettings();
        settings.Rules.HoneypotUsernames = [" Admin ", @"EXAMPLE\admin", "guest@example.com", "", "  ", @"EXAMPLE\", null!];
        settings.Rules.SprayMaxUsernames = 1;
        settings.Rules.SprayWindow = TimeSpan.FromMinutes(-5);
        settings.Rules.SlowBruteForceThreshold = -3;
        settings.Rules.SlowBruteForceWindow = TimeSpan.FromDays(400);
        settings.Rules.CompromiseMinFailures = 0;
        settings.Rules.CompromiseWindow = TimeSpan.Zero;
        settings.Rules.TrustAdminIpHours = 100;

        settings.Normalize();

        Assert.Equal(new[] { "Admin", "guest" }, settings.Rules.HoneypotUsernames);
        Assert.Equal(2, settings.Rules.SprayMaxUsernames);
        Assert.Equal(TimeSpan.FromHours(1), settings.Rules.SprayWindow);
        Assert.Equal(0, settings.Rules.SlowBruteForceThreshold);
        Assert.Equal(TimeSpan.FromDays(30), settings.Rules.SlowBruteForceWindow);
        Assert.Equal(1, settings.Rules.CompromiseMinFailures);
        Assert.Equal(TimeSpan.FromHours(24), settings.Rules.CompromiseWindow);
        Assert.Equal(24, settings.Rules.TrustAdminIpHours);
    }

    [Fact]
    public void Settings_saved_before_the_rules_existed_load_with_them_off()
    {
        var old = JsonSerializer.Deserialize<WinGuardSettings>("""{"failedLoginThreshold":7}""", IpcJson.Options)!;
        var explicitNull = JsonSerializer.Deserialize<WinGuardSettings>("""{"rules":null}""", IpcJson.Options)!;

        old.Normalize();
        explicitNull.Normalize();

        Assert.Equal(7, old.FailedLoginThreshold);
        Assert.False(old.Rules.ObservesLogons());
        Assert.Empty(explicitNull.Rules.HoneypotUsernames);
    }

    [Fact]
    public void The_rules_survive_the_copy_the_console_edits_and_the_saved_form()
    {
        var settings = new WinGuardSettings();
        settings.Rules.HoneypotUsernames = ["admin"];
        settings.Rules.SlowBruteForceThreshold = 20;
        settings.Rules.TrustAdminIpHours = 2;

        var copy = settings.Clone();
        var saved = JsonSerializer.Deserialize<WinGuardSettings>(JsonSerializer.Serialize(settings, IpcJson.Options), IpcJson.Options)!;

        Assert.Equal(new[] { "admin" }, copy.Rules.HoneypotUsernames);
        Assert.Equal(20, saved.Rules.SlowBruteForceThreshold);
        Assert.Equal(2, saved.Rules.TrustAdminIpHours);
    }

    [Fact]
    public void A_wildcard_in_the_honeypot_list_is_refused()
    {
        var settings = new WinGuardSettings();
        settings.Rules.HoneypotUsernames = ["admin", "adm*", "te?t"];

        var problems = SettingsValidator.Validate(settings);

        Assert.Equal(2, problems.Count);
        Assert.All(problems, problem => Assert.Contains("wildcards", problem, StringComparison.Ordinal));
    }
}
