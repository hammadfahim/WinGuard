using WinGuard.Core.Config;
using WinGuard.Core.Model;
using WinGuard.Core.Notifications;
using WinGuard.Core.Tests.Fakes;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>Successful logons: the POSSIBLE COMPROMISE alert and the temporary trust of an admin's IP.</summary>
public sealed class BanEngineLogonTests
{
    private static readonly DateTimeOffset T0 = new(2026, 3, 1, 0, 0, 0, TimeSpan.Zero);

    private const ProtocolSource NonRdp = ProtocolSource.MsSql;

    private static void Alerts(WinGuardSettings s) => s.Rules.CompromiseAlerts = true;

    private static void Trust(WinGuardSettings s) => s.Rules.TrustAdminIpHours = 2;

    private static FailedLogin Logon(EngineHarness h, string ip, string user = "bob", int logonType = 3, DateTime? at = null, bool replayed = false) => new()
    {
        IpAddress = ip,
        UserName = user,
        Source = ProtocolSource.Rdp,
        Detector = "4624",
        TimestampUtc = at ?? h.Time.UtcNow.UtcDateTime,
        IsSuccess = true,
        LogonType = logonType,
        IsReplayed = replayed,
    };

    private static async Task FailAsync(EngineHarness h, string ip, int times = 3)
    {
        for (var i = 0; i < times; i++)
        {
            await h.ProcessAsync(h.Fail(ip, NonRdp));
        }
    }

    private static List<LogEvent> Alerts(FakeStore store) =>
        store.Events.Where(e => e.Message.StartsWith("POSSIBLE COMPROMISE", StringComparison.Ordinal)).ToList();

    private static List<LogEvent> Trusts(FakeStore store) =>
        store.Events.Where(e => e.Message.StartsWith("TEMPORARILY TRUSTED", StringComparison.Ordinal)).ToList();

    // ---------- the alert ----------

    [Fact]
    public async Task A_logon_after_failures_raises_a_warning_that_reaches_notifications()
    {
        await using var h = await EngineHarness.StartAsync(T0, Alerts);
        const string ip = "203.0.113.1";
        await FailAsync(h, ip);

        await h.ProcessAsync(Logon(h, ip, "alice"));

        var alert = Assert.Single(Alerts(h.Store));
        Assert.Equal($"POSSIBLE COMPROMISE: alice logged on from {ip} after 3 failed attempt(s)", alert.Message);
        Assert.Equal(LogEventLevel.Warning, alert.Level);
        Assert.Equal(ip, alert.IpAddress);
        Assert.True(WinGuardEventIds.IsNotifiable(alert));
        Assert.Equal(WinGuardEventIds.PossibleCompromise, WinGuardEventIds.For(alert));
    }

    [Fact]
    public async Task The_alert_is_kept_in_the_ban_history_without_counting_as_a_ban()
    {
        await using var h = await EngineHarness.StartAsync(T0, Alerts);
        const string ip = "203.0.113.2";
        await FailAsync(h, ip);

        await h.ProcessAsync(Logon(h, ip, "alice"));

        var row = Assert.Single(h.Store.BanHistory);
        Assert.Equal(BanHistoryAction.SuspiciousLogon, row.Action);
        Assert.Equal(ip, row.IpAddress);
        Assert.Contains("alice", row.Note, StringComparison.Ordinal);
        Assert.Empty(await h.Store.GetTopOffendersAsync(10));
        Assert.Null(await h.Store.GetBanAsync(ip));
    }

    [Fact]
    public async Task A_logon_is_not_a_failure_and_clears_none()
    {
        await using var h = await EngineHarness.StartAsync(T0, Alerts);
        const string ip = "203.0.113.3";
        await FailAsync(h, ip, 2);
        var detections = h.Engine.GetDetectionsToday(NonRdp);

        for (var i = 0; i < 10; i++)
        {
            await h.ProcessAsync(Logon(h, ip));
        }

        Assert.Equal(2, h.Store.FailedLogins.Count);
        Assert.Equal(detections, h.Engine.GetDetectionsToday(NonRdp));
        Assert.Equal(0, h.Engine.GetDetectionsToday(ProtocolSource.Rdp));
        Assert.Null(await h.Store.GetBanAsync(ip));
        Assert.Empty(h.Firewall.BlockCalls);
    }

    [Fact]
    public async Task Fewer_failures_than_the_limit_raise_nothing()
    {
        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            Alerts(s);
            s.Rules.CompromiseMinFailures = 3;
        });
        await FailAsync(h, "203.0.113.4", 2);

        await h.ProcessAsync(Logon(h, "203.0.113.4"));

        Assert.Empty(Alerts(h.Store));
    }

    [Fact]
    public async Task Failures_past_the_window_raise_nothing()
    {
        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            Alerts(s);
            s.Rules.CompromiseWindow = TimeSpan.FromHours(1);
        });
        await FailAsync(h, "203.0.113.5");
        h.Time.Advance(TimeSpan.FromMinutes(61));

        await h.ProcessAsync(Logon(h, "203.0.113.5"));

        Assert.Empty(Alerts(h.Store));
    }

    [Fact]
    public async Task Failures_from_every_engine_count()
    {
        await using var h = await EngineHarness.StartAsync(T0, Alerts);
        const string ip = "203.0.113.6";
        await h.ProcessAsync(h.Fail(ip, ProtocolSource.MsSql));
        await h.ProcessAsync(h.Fail(ip, ProtocolSource.Ftp));
        await h.ProcessAsync(h.Fail(ip, ProtocolSource.Custom));

        await h.ProcessAsync(Logon(h, ip));

        Assert.Single(Alerts(h.Store));
    }

    [Fact]
    public async Task A_logon_from_a_banned_ip_alerts_and_reports_the_failures_that_led_to_the_ban()
    {
        await using var h = await EngineHarness.StartAsync(T0, Alerts);
        const string ip = "203.0.113.7";
        await FailAsync(h, ip, 5);
        Assert.NotNull(await h.Store.GetBanAsync(ip));
        Assert.Empty(h.Store.FailedLogins);

        await h.ProcessAsync(Logon(h, ip, "alice"));

        Assert.Equal($"POSSIBLE COMPROMISE: alice logged on from {ip} after 5 failed attempt(s)", Assert.Single(Alerts(h.Store)).Message);
    }

    [Fact]
    public async Task A_logon_from_a_manually_banned_ip_alerts()
    {
        await using var h = await EngineHarness.StartAsync(T0, Alerts);
        await h.Engine.BanNowAsync("203.0.113.8", TimeSpan.FromHours(1), permanent: false, null);

        await h.ProcessAsync(Logon(h, "203.0.113.8"));

        Assert.Single(Alerts(h.Store));
    }

    [Fact]
    public async Task An_expired_ban_is_no_reason_to_alert()
    {
        await using var h = await EngineHarness.StartAsync(T0, Alerts);
        const string ip = "203.0.113.9";
        await FailAsync(h, ip, 5);
        h.Time.Advance(TimeSpan.FromHours(25));
        await h.Engine.HousekeepOnceAsync();

        await h.ProcessAsync(Logon(h, ip));

        Assert.Empty(Alerts(h.Store));
    }

    [Fact]
    public async Task Alerts_are_limited_per_ip()
    {
        await using var h = await EngineHarness.StartAsync(T0, Alerts);
        await FailAsync(h, "203.0.113.10");
        await FailAsync(h, "203.0.113.11");

        await h.ProcessAsync(Logon(h, "203.0.113.10", logonType: 3));
        await h.ProcessAsync(Logon(h, "203.0.113.10", logonType: 10));
        h.Time.Advance(TimeSpan.FromMinutes(30));
        await h.ProcessAsync(Logon(h, "203.0.113.10"));
        await h.ProcessAsync(Logon(h, "203.0.113.11"));

        Assert.Equal(new[] { "203.0.113.10", "203.0.113.11" }, Alerts(h.Store).Select(e => e.IpAddress));

        h.Time.Advance(TimeSpan.FromMinutes(31));
        await h.ProcessAsync(Logon(h, "203.0.113.10"));

        Assert.Equal(3, Alerts(h.Store).Count);
    }

    [Fact]
    public async Task A_user_name_from_a_log_cannot_forge_lines_in_the_event()
    {
        await using var h = await EngineHarness.StartAsync(T0, Alerts);
        await FailAsync(h, "203.0.113.12");

        await h.ProcessAsync(Logon(h, "203.0.113.12", "bob\r\nBLOCKED 1.1.1.1 " + new string('x', 200)));

        var message = Assert.Single(Alerts(h.Store)).Message;
        Assert.DoesNotContain('\n', message);
        Assert.DoesNotContain('\r', message);
        Assert.True(message.Length < 200);
    }

    [Fact]
    public async Task The_whitelist_silences_the_alert()
    {
        await using var h = await EngineHarness.StartAsync(T0, Alerts, seed: s => s.AddToListAsync(ListKind.Whitelist, "203.0.113.13"));
        await FailAsync(h, "203.0.113.13");

        await h.ProcessAsync(Logon(h, "203.0.113.13"));

        Assert.Empty(Alerts(h.Store));
    }

    [Fact]
    public async Task Internal_addresses_stay_ignored_unless_enabled()
    {
        await using var ignoring = await EngineHarness.StartAsync(T0, Alerts);
        await ignoring.Store.AddFailedLoginAsync(ignoring.Fail("10.0.0.9", NonRdp));
        await ignoring.Store.AddFailedLoginAsync(ignoring.Fail("10.0.0.9", NonRdp));
        await ignoring.Store.AddFailedLoginAsync(ignoring.Fail("10.0.0.9", NonRdp));
        await ignoring.ProcessAsync(Logon(ignoring, "10.0.0.9"));
        Assert.Empty(Alerts(ignoring.Store));

        await using var processing = await EngineHarness.StartAsync(T0, s =>
        {
            Alerts(s);
            s.ProcessInternalIPs = true;
        });
        await FailAsync(processing, "10.0.0.9");
        await processing.ProcessAsync(Logon(processing, "10.0.0.9"));
        Assert.Single(Alerts(processing.Store));
    }

    [Fact]
    public async Task Report_only_still_records_the_alert_and_blocks_nothing()
    {
        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            Alerts(s);
            s.ReportOnly = true;
        });
        const string ip = "203.0.113.14";
        await FailAsync(h, ip, 5);

        await h.ProcessAsync(Logon(h, ip));

        Assert.Single(Alerts(h.Store));
        Assert.Empty(h.Firewall.BlockCalls);
    }

    [Fact]
    public async Task IPv6_logons_are_judged_by_the_aggregated_identity()
    {
        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            Alerts(s);
            s.Ipv6AggregatePrefixLength = 64;
        });
        await h.ProcessAsync(h.Fail("2001:db8:1:2::1", NonRdp));
        await h.ProcessAsync(h.Fail("2001:db8:1:2::2", NonRdp));
        await h.ProcessAsync(h.Fail("2001:db8:1:2::3", NonRdp));

        await h.ProcessAsync(Logon(h, "2001:db8:1:2::9", "alice"));

        var alert = Assert.Single(Alerts(h.Store));
        Assert.Equal("POSSIBLE COMPROMISE: alice logged on from 2001:db8:1:2::9 after 3 failed attempt(s)", alert.Message);
        Assert.Equal("2001:db8:1:2::/64", alert.IpAddress);
        Assert.Equal("2001:db8:1:2::/64", Assert.Single(h.Store.BanHistory).IpAddress);
    }

    [Fact]
    public async Task A_logon_inside_an_aggregate_ban_alerts()
    {
        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            Alerts(s);
            s.Ipv6AggregatePrefixLength = 64;
        });
        for (var i = 1; i <= 5; i++)
        {
            await h.ProcessAsync(h.Fail($"2001:db8:1:2::{i:x}", NonRdp));
        }

        await h.ProcessAsync(Logon(h, "2001:db8:1:2::9"));

        Assert.Single(Alerts(h.Store));
    }

    [Fact]
    public async Task The_feature_can_be_switched_on_and_off_live()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        const string ip = "203.0.113.15";
        await FailAsync(h, ip);

        await h.ProcessAsync(Logon(h, ip));
        Assert.Empty(Alerts(h.Store));

        h.Settings.Rules.CompromiseAlerts = true;
        await h.ProcessAsync(Logon(h, ip));
        Assert.Single(Alerts(h.Store));
    }

    // ---------- cost ----------

    [Fact]
    public async Task With_the_feature_off_a_logon_costs_nothing()
    {
        await using var h = await EngineHarness.StartAsync(T0);

        await h.ProcessAsync(Logon(h, "203.0.113.20"));

        Assert.Equal(0, h.Store.FailureReads);
        Assert.Equal(0, h.Store.BanReads);
    }

    [Fact]
    public async Task A_clean_ip_is_read_from_the_store_once()
    {
        await using var h = await EngineHarness.StartAsync(T0, Alerts);

        for (var i = 0; i < 20; i++)
        {
            await h.ProcessAsync(Logon(h, "203.0.113.21"));
        }

        Assert.Equal(1, h.Store.FailureReads);
        Assert.Equal(1, h.Store.BanReads);
    }

    [Fact]
    public async Task An_internal_or_whitelisted_logon_never_reaches_the_store()
    {
        await using var h = await EngineHarness.StartAsync(T0, Alerts, seed: s => s.AddToListAsync(ListKind.Whitelist, "203.0.113.22"));

        await h.ProcessAsync(Logon(h, "10.0.0.9"));
        await h.ProcessAsync(Logon(h, "203.0.113.22"));

        Assert.Equal(0, h.Store.FailureReads);
    }

    [Fact]
    public async Task A_failure_ends_the_clean_memory_of_an_ip_at_once()
    {
        await using var h = await EngineHarness.StartAsync(T0, Alerts);
        const string ip = "203.0.113.23";
        await h.ProcessAsync(Logon(h, ip));

        await FailAsync(h, ip);
        await h.ProcessAsync(Logon(h, ip));

        Assert.Single(Alerts(h.Store));
    }

    [Fact]
    public async Task A_manual_ban_ends_the_clean_memory_of_an_ip_at_once()
    {
        await using var h = await EngineHarness.StartAsync(T0, Alerts);
        const string ip = "203.0.113.24";
        await h.ProcessAsync(Logon(h, ip));

        await h.Engine.BanNowAsync(ip, TimeSpan.FromHours(1), permanent: false, null);
        await h.ProcessAsync(Logon(h, ip));

        Assert.Single(Alerts(h.Store));
    }

    [Fact]
    public async Task An_unreadable_store_is_not_remembered_as_clean()
    {
        await using var h = await EngineHarness.StartAsync(T0, Alerts);
        const string ip = "203.0.113.25";
        await FailAsync(h, ip);

        h.Store.FailFailureReads = true;
        await h.ProcessAsync(Logon(h, ip));
        h.Store.FailFailureReads = false;
        await h.ProcessAsync(Logon(h, ip));

        Assert.Single(Alerts(h.Store));
    }

    // ---------- replay ----------

    [Fact]
    public async Task A_replayed_logon_the_last_run_handled_is_ignored()
    {
        const string ip = "203.0.113.30";
        var store = new FakeStore();
        var loggedOn = T0.AddMinutes(-1).UtcDateTime;
        await using (var first = await EngineHarness.StartAsync(T0.AddMinutes(-5), Alerts, store: store))
        {
            await FailAsync(first, ip);
            first.Time.Advance(TimeSpan.FromMinutes(5));
        }

        await using var second = await EngineHarness.StartAsync(T0.AddMinutes(5), Alerts, store: store);
        await second.ProcessAsync(Logon(second, ip, at: loggedOn, replayed: true));
        second.Time.Advance(TimeSpan.FromMinutes(2));
        await second.Engine.HousekeepOnceAsync();

        Assert.Empty(Alerts(store));
    }

    [Fact]
    public async Task A_replayed_logon_can_arrive_before_the_failures_that_led_to_it()
    {
        const string ip = "203.0.113.31";
        var store = new FakeStore();
        await using (await EngineHarness.StartAsync(T0, Alerts, store: store))
        {
        }

        await using var second = await EngineHarness.StartAsync(T0.AddMinutes(10), Alerts, store: store);
        await second.ProcessAsync(Logon(second, ip, "alice", at: T0.AddMinutes(5).UtcDateTime, replayed: true));
        for (var i = 1; i <= 3; i++)
        {
            var failed = second.Fail(ip, NonRdp, at: T0.AddMinutes(i).UtcDateTime);
            failed.IsReplayed = true;
            await second.ProcessAsync(failed);
        }

        Assert.Empty(Alerts(store));

        second.Time.Advance(TimeSpan.FromMinutes(2));
        await second.Engine.HousekeepOnceAsync();

        Assert.Equal($"POSSIBLE COMPROMISE: alice logged on from {ip} after 3 failed attempt(s)", Assert.Single(Alerts(store)).Message);
    }

    [Fact]
    public async Task Failures_after_a_replayed_logon_did_not_lead_to_it()
    {
        const string ip = "203.0.113.32";
        var store = new FakeStore();
        await using (await EngineHarness.StartAsync(T0, Alerts, store: store))
        {
        }

        await using var second = await EngineHarness.StartAsync(T0.AddMinutes(10), Alerts, store: store);
        await second.ProcessAsync(Logon(second, ip, at: T0.AddMinutes(1).UtcDateTime, replayed: true));
        for (var i = 2; i <= 4; i++)
        {
            var failed = second.Fail(ip, NonRdp, at: T0.AddMinutes(i).UtcDateTime);
            failed.IsReplayed = true;
            await second.ProcessAsync(failed);
        }

        second.Time.Advance(TimeSpan.FromMinutes(2));
        await second.Engine.HousekeepOnceAsync();

        Assert.Empty(Alerts(store));
    }

    [Fact]
    public async Task A_replayed_logon_is_not_lost_when_the_service_stops_early()
    {
        const string ip = "203.0.113.33";
        var store = new FakeStore();
        await using (var first = await EngineHarness.StartAsync(T0, Alerts, store: store))
        {
            await FailAsync(first, ip);
        }

        await using (var second = await EngineHarness.StartAsync(T0.AddMinutes(5), Alerts, store: store))
        {
            await second.ProcessAsync(Logon(second, ip, at: T0.AddMinutes(1).UtcDateTime, replayed: true));
        }

        Assert.Single(Alerts(store));
    }

    [Fact]
    public async Task A_live_logon_right_after_a_restart_waits_for_the_replayed_failures()
    {
        const string ip = "203.0.113.34";
        var store = new FakeStore();
        await using (await EngineHarness.StartAsync(T0, s =>
        {
            Alerts(s);
            Trust(s);
        }, store: store))
        {
        }

        await using var second = await EngineHarness.StartAsync(T0.AddMinutes(10), s =>
        {
            Alerts(s);
            Trust(s);
        }, store: store);
        await second.ProcessAsync(Logon(second, ip, logonType: 10));
        for (var i = 1; i <= 3; i++)
        {
            var failed = second.Fail(ip, NonRdp, at: T0.AddMinutes(i).UtcDateTime);
            failed.IsReplayed = true;
            await second.ProcessAsync(failed);
        }

        second.Time.Advance(TimeSpan.FromMinutes(2));
        await second.Engine.HousekeepOnceAsync();

        Assert.Empty(Trusts(store));
        Assert.Single(Alerts(store));
        Assert.Equal(3, store.FailedLogins.Count);
    }

    [Fact]
    public async Task Once_the_replay_is_over_a_logon_is_judged_at_once()
    {
        var store = new FakeStore();
        await using (await EngineHarness.StartAsync(T0, Trust, store: store))
        {
        }

        await using var second = await EngineHarness.StartAsync(T0.AddMinutes(10), Trust, store: store);
        second.Time.Advance(TimeSpan.FromMinutes(1));

        await second.ProcessAsync(Logon(second, "203.0.113.35", logonType: 10));

        Assert.Single(Trusts(store));
    }

    [Fact]
    public async Task A_honeypot_ban_merged_from_a_4625_reports_at_least_that_attempt()
    {
        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            Alerts(s);
            s.Rules.HoneypotUsernames = ["admin"];
        });
        const string ip = "203.0.113.36";
        await h.ProcessAsync(h.Fail(ip, ProtocolSource.Rdp, user: null, detector: "140"));
        await h.ProcessAsync(h.Fail(ip, ProtocolSource.Rdp, user: "admin", detector: "4625"));

        await h.ProcessAsync(Logon(h, ip, "alice"));

        Assert.EndsWith("after 1 failed attempt(s)", Assert.Single(Alerts(h.Store)).Message, StringComparison.Ordinal);
    }

    // ---------- temporary trust ----------

    [Fact]
    public async Task An_rdp_logon_with_a_clean_record_trusts_the_ip_for_the_set_time()
    {
        await using var h = await EngineHarness.StartAsync(T0, Trust);
        const string ip = "203.0.113.40";

        await h.ProcessAsync(Logon(h, ip, "alice", logonType: 10));

        var trusted = Assert.Single(Trusts(h.Store));
        Assert.Equal($"TEMPORARILY TRUSTED {ip} for 02:00:00 after RDP logon by alice", trusted.Message);

        await FailAsync(h, ip, 10);
        Assert.Null(await h.Store.GetBanAsync(ip));
        Assert.Empty(h.Store.FailedLogins);

        h.Time.Advance(TimeSpan.FromHours(2).Add(TimeSpan.FromSeconds(1)));
        await FailAsync(h, ip, 5);
        Assert.NotNull(await h.Store.GetBanAsync(ip));
    }

    [Fact]
    public async Task Another_logon_does_not_extend_the_trust()
    {
        await using var h = await EngineHarness.StartAsync(T0, Trust);
        const string ip = "203.0.113.41";

        await h.ProcessAsync(Logon(h, ip, logonType: 10));
        h.Time.Advance(TimeSpan.FromHours(1));
        await h.ProcessAsync(Logon(h, ip, logonType: 10));
        h.Time.Advance(TimeSpan.FromHours(1).Add(TimeSpan.FromSeconds(1)));
        await FailAsync(h, ip, 5);

        Assert.Single(Trusts(h.Store));
        Assert.NotNull(await h.Store.GetBanAsync(ip));
    }

    [Fact]
    public async Task A_network_logon_trusts_nothing()
    {
        await using var h = await EngineHarness.StartAsync(T0, Trust);

        await h.ProcessAsync(Logon(h, "203.0.113.42", logonType: 3));

        Assert.Empty(Trusts(h.Store));
    }

    [Fact]
    public async Task A_single_failure_rules_out_trust_even_below_the_alert_limit()
    {
        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            Trust(s);
            Alerts(s);
        });
        await FailAsync(h, "203.0.113.43", 1);

        await h.ProcessAsync(Logon(h, "203.0.113.43", logonType: 10));

        Assert.Empty(Trusts(h.Store));
        Assert.Empty(Alerts(h.Store));
    }

    [Fact]
    public async Task Failures_older_than_the_alert_window_still_rule_out_trust()
    {
        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            Trust(s);
            s.Rules.CompromiseWindow = TimeSpan.FromMinutes(10);
        });
        await FailAsync(h, "203.0.113.44", 1);
        h.Time.Advance(TimeSpan.FromHours(1));

        await h.ProcessAsync(Logon(h, "203.0.113.44", logonType: 10));

        Assert.Empty(Trusts(h.Store));
    }

    [Fact]
    public async Task An_active_ban_rules_out_trust()
    {
        await using var h = await EngineHarness.StartAsync(T0, Trust);
        const string ip = "203.0.113.45";
        await FailAsync(h, ip, 5);

        await h.ProcessAsync(Logon(h, ip, logonType: 10));

        Assert.Empty(Trusts(h.Store));
    }

    [Fact]
    public async Task A_past_ban_rules_out_trust_although_its_failures_are_gone()
    {
        await using var h = await EngineHarness.StartAsync(T0, Trust);
        const string ip = "203.0.113.46";
        await FailAsync(h, ip, 5);
        h.Time.Advance(TimeSpan.FromHours(25));
        await h.Engine.HousekeepOnceAsync();
        Assert.Empty(h.Store.FailedLogins);

        await h.ProcessAsync(Logon(h, ip, logonType: 10));

        Assert.Empty(Trusts(h.Store));
    }

    [Theory]
    [InlineData("admin")]
    [InlineData("ADMIN")]
    [InlineData(@"EXAMPLE\admin")]
    [InlineData("admin@example.com")]
    public async Task A_honeypot_name_is_never_trusted(string user)
    {
        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            Trust(s);
            s.Rules.HoneypotUsernames = ["admin"];
        });

        await h.ProcessAsync(Logon(h, "203.0.113.47", user, logonType: 10));

        Assert.Empty(Trusts(h.Store));
    }

    [Fact]
    public async Task A_blacklisted_address_is_never_trusted()
    {
        await using var h = await EngineHarness.StartAsync(T0, Trust, seed: s => s.AddToListAsync(ListKind.Blacklist, "203.0.113.48"));

        await h.ProcessAsync(Logon(h, "203.0.113.48", logonType: 10));

        Assert.Empty(Trusts(h.Store));
    }

    [Fact]
    public async Task An_unreadable_store_rules_out_trust()
    {
        await using var h = await EngineHarness.StartAsync(T0, Trust);
        h.Store.FailFailureReads = true;

        await h.ProcessAsync(Logon(h, "203.0.113.49", logonType: 10));

        Assert.Empty(Trusts(h.Store));
    }

    [Fact]
    public async Task Trust_ends_with_the_service_and_a_replay_cannot_bring_it_back()
    {
        const string ip = "203.0.113.50";
        var store = new FakeStore();
        await using (var first = await EngineHarness.StartAsync(T0, Trust, store: store))
        {
            await first.ProcessAsync(Logon(first, ip, logonType: 10));
            Assert.Single(Trusts(store));
        }

        await using var second = await EngineHarness.StartAsync(T0.AddMinutes(5), Trust, store: store);
        await second.ProcessAsync(Logon(second, ip, logonType: 10, at: T0.AddMinutes(1).UtcDateTime, replayed: true));
        await FailAsync(second, ip, 5);

        Assert.Single(Trusts(store));
        Assert.NotNull(await store.GetBanAsync(ip));
        Assert.DoesNotContain(store.SettingValues.Values, value => value.Contains(ip, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Switching_the_setting_off_ends_the_trust_at_once()
    {
        await using var h = await EngineHarness.StartAsync(T0, Trust);
        const string ip = "203.0.113.51";
        await h.ProcessAsync(Logon(h, ip, logonType: 10));

        h.Settings.Rules.TrustAdminIpHours = 0;
        await FailAsync(h, ip, 5);

        Assert.NotNull(await h.Store.GetBanAsync(ip));
    }

    [Fact]
    public async Task A_manual_block_outranks_the_trust()
    {
        await using var h = await EngineHarness.StartAsync(T0, Trust);
        const string ip = "203.0.113.52";
        await h.ProcessAsync(Logon(h, ip, logonType: 10));

        await h.Engine.BanNowAsync(ip, TimeSpan.FromHours(1), permanent: false, null);
        await h.Engine.UnbanAsync(ip);
        await FailAsync(h, ip, 5);

        Assert.NotNull(await h.Store.GetBanAsync(ip));
    }

    [Fact]
    public async Task A_later_blacklist_entry_outranks_the_trust()
    {
        await using var h = await EngineHarness.StartAsync(T0, Trust);
        const string ip = "203.0.113.53";
        await h.ProcessAsync(Logon(h, ip, logonType: 10));

        await h.Store.AddToListAsync(ListKind.Blacklist, ip);
        await h.Engine.ReloadListsAsync();
        await FailAsync(h, ip, 1);

        Assert.True((await h.Store.GetBanAsync(ip))?.IsPermanent);
    }

    [Fact]
    public async Task An_aggregate_ban_never_covers_a_trusted_address()
    {
        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            Trust(s);
            s.Ipv6AggregatePrefixLength = 64;
        });
        await h.ProcessAsync(Logon(h, "2001:db8:1:2::1", logonType: 10));

        for (var i = 0; i < 5; i++)
        {
            await h.ProcessAsync(h.Fail("2001:db8:1:2::9", NonRdp));
        }

        Assert.Null(await h.Store.GetBanAsync("2001:db8:1:2::/64"));
        Assert.NotNull(await h.Store.GetBanAsync("2001:db8:1:2::9"));
    }

    [Fact]
    public async Task Failures_in_an_aggregated_prefix_rule_out_trust_for_all_of_it()
    {
        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            Trust(s);
            s.Ipv6AggregatePrefixLength = 64;
        });
        await h.ProcessAsync(h.Fail("2001:db8:1:2::9", NonRdp));

        await h.ProcessAsync(Logon(h, "2001:db8:1:2::1", logonType: 10));

        Assert.Empty(Trusts(h.Store));
    }

    [Fact]
    public async Task Trust_alone_needs_no_store_read_for_a_network_logon()
    {
        await using var h = await EngineHarness.StartAsync(T0, Trust);

        await h.ProcessAsync(Logon(h, "203.0.113.54", logonType: 3));

        Assert.Equal(0, h.Store.FailureReads);
    }
}
