using System.Globalization;
using System.Reflection;
using Microsoft.Extensions.Logging;
using WinGuard.Core.Config;
using WinGuard.Core.Engine;
using WinGuard.Core.Model;
using WinGuard.Core.Tests.Fakes;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>
/// The engine keeps its promises when things go wrong: a database that cannot be read or written,
/// lists that are unreadable at start-up, a backlog older than the count window, a shutdown in the
/// middle of a ban, and the addresses that only look like one client.
/// </summary>
public sealed class BanEngineResilienceTests
{
    private static readonly DateTimeOffset T0 = new(2026, 5, 1, 12, 0, 0, TimeSpan.Zero);
    private const string Attacker = "203.0.113.50";
    private const string Nat64Client = "64:ff9b::cb00:7101"; // 203.0.113.1
    private const string Aggregate = "2001:db8:1:2::/64";

    private static readonly PortSet Rdp = PortSet.Parse(["3389"]);
    private static readonly PortSet Sql = PortSet.Parse(["1433"]);

    private static void Profiles(WinGuardSettings s)
    {
        s.Rdp.BlockedPorts = ["3389"];
        s.MsSql.BlockedPorts = ["1433"];
    }

    private static async Task Threshold(EngineHarness h, string ip, ProtocolSource source, string? detector = null)
    {
        for (var i = 0; i < 5; i++)
        {
            await h.ProcessAsync(h.Fail(ip, source, detector: detector));
        }
    }

    /// <summary>Everything the engine needs from the database fails, as with a locked file.</summary>
    private static void Locked(EngineHarness h, bool on)
    {
        h.Store.FailWrites = on;
        h.Store.FailBanRead = on;
        h.Store.FailActiveBansRead = on;
        h.Store.FailFailureReads = on;
        h.Store.FailBanRemoval = on;
        h.Store.FailListRead = on;
    }

    /// <summary>A pass of the timer loop: unlike HousekeepOnceAsync it reconciles at most once a minute.</summary>
    private static Task PassLikeTheTimer(EngineHarness h)
    {
        var core = typeof(BanEngine).GetMethod("HousekeepCoreAsync", BindingFlags.Instance | BindingFlags.NonPublic)!;
        return (Task)core.Invoke(h.Engine, [false, CancellationToken.None])!;
    }

    // ---------- a failed ban read is not "no ban" ----------

    [Fact]
    public async Task A_locked_database_does_not_open_the_rdp_port_of_a_scoped_ban()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        await Threshold(h, Attacker, ProtocolSource.Rdp, "4625");
        Assert.Equal(Rdp, h.Firewall.PortsOf(Attacker));

        Locked(h, true);
        await Threshold(h, Attacker, ProtocolSource.MsSql);

        // RDP was banned first and must stay covered.
        Assert.True(h.Firewall.PortsOf(Attacker)!.Covers(Rdp), $"firewall now holds {h.Firewall.PortsOf(Attacker)}");
    }

    [Fact]
    public async Task After_the_outage_the_stored_ban_covers_both_engines()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        await Threshold(h, Attacker, ProtocolSource.Rdp, "4625");
        var bannedAt = (await h.Store.GetBanAsync(Attacker))!.BannedAtUtc;

        h.Time.Advance(TimeSpan.FromMinutes(1));
        Locked(h, true);
        await Threshold(h, Attacker, ProtocolSource.MsSql);
        Locked(h, false);
        await h.Engine.HousekeepOnceAsync();

        var row = (await h.Store.GetBanAsync(Attacker))!;
        Assert.Equal(Rdp.Union(Sql), PortProfiles.Resolve(row.PortScope, h.Settings));
        Assert.Equal(Rdp.Union(Sql), h.Firewall.PortsOf(Attacker));
        Assert.Equal(ProtocolSource.Rdp, row.Source);
        Assert.Equal(bannedAt, row.BannedAtUtc);
        Assert.Equal(2, row.OffenseCount);
    }

    [Fact]
    public async Task A_permanent_ban_survives_an_outage_in_report_only()
    {
        await using var h = await EngineHarness.StartAsync(T0, s => s.ReportOnly = true);
        await h.Engine.BanNowAsync(Attacker, null, permanent: true, "keep out");

        Locked(h, true);
        await Threshold(h, Attacker, ProtocolSource.MsSql);
        Locked(h, false);
        await h.Engine.HousekeepOnceAsync();

        var row = (await h.Store.GetBanAsync(Attacker))!;
        Assert.True(row.IsPermanent, $"row now expires {row.ExpiresUtc:u}, note '{row.Note}'");
        Assert.Equal("keep out", row.Note);
    }

    [Fact]
    public async Task A_new_attacker_during_an_outage_goes_on_all_ports_then_back_to_its_engine()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);

        Locked(h, true);
        await Threshold(h, Attacker, ProtocolSource.MsSql);
        Assert.Equal(PortSet.All, h.Firewall.PortsOf(Attacker));

        Locked(h, false);
        await h.Engine.HousekeepOnceAsync();

        Assert.Equal("MsSql", (await h.Store.GetBanAsync(Attacker))!.PortScope);
        Assert.Equal(Sql, h.Firewall.PortsOf(Attacker));
    }

    [Fact]
    public async Task A_row_that_cannot_be_read_is_not_written_over_even_if_writes_work()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        await Threshold(h, Attacker, ProtocolSource.Rdp, "4625");

        h.Store.FailBanRead = true;
        await Threshold(h, Attacker, ProtocolSource.MsSql);
        h.Store.FailBanRead = false;

        Assert.Equal("Rdp", (await h.Store.GetBanAsync(Attacker))!.PortScope);

        await h.Engine.HousekeepOnceAsync();

        Assert.Equal(Rdp.Union(Sql), PortProfiles.Resolve((await h.Store.GetBanAsync(Attacker))!.PortScope, h.Settings));
    }

    [Fact]
    public async Task A_blind_ban_that_runs_out_stays_until_the_store_says_what_it_holds()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        await h.Engine.BanNowAsync(Attacker, null, permanent: true, null);

        Locked(h, true);
        await Threshold(h, Attacker, ProtocolSource.MsSql);
        h.Time.Advance(TimeSpan.FromDays(40));
        await h.Engine.HousekeepOnceAsync();
        Assert.Contains(Attacker, h.Firewall.Blocked);

        Locked(h, false);
        await h.Engine.HousekeepOnceAsync();

        Assert.Contains(Attacker, h.Firewall.Blocked);
        Assert.True((await h.Store.GetBanAsync(Attacker))!.IsPermanent);
    }

    [Fact]
    public async Task An_attacker_on_a_second_engine_during_an_outage_stays_on_all_ports()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        await Threshold(h, Attacker, ProtocolSource.Ftp);

        Locked(h, true);
        await Threshold(h, Attacker, ProtocolSource.MsSql);
        await Threshold(h, Attacker, ProtocolSource.Rdp, "4625");
        Assert.Equal(PortSet.All, h.Firewall.PortsOf(Attacker));

        Locked(h, false);
        await h.Engine.HousekeepOnceAsync();

        var row = (await h.Store.GetBanAsync(Attacker))!;
        Assert.Equal("Ftp\nMsSql\nRdp", row.PortScope);
    }

    [Fact]
    public async Task A_blind_ban_can_be_lifted_by_hand()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        Locked(h, true);
        await Threshold(h, Attacker, ProtocolSource.MsSql);

        await h.Engine.UnbanAsync(Attacker);
        Locked(h, false);
        await h.Engine.HousekeepOnceAsync();

        Assert.Empty(h.Firewall.Blocked);
        Assert.Null(await h.Store.GetBanAsync(Attacker));
    }

    [Fact]
    public async Task A_manual_ban_without_duration_does_not_demote_a_row_it_cannot_read()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        await h.Engine.BanNowAsync(Attacker, null, permanent: true, "keep out");

        Locked(h, true);
        await h.Engine.BanNowAsync(Attacker, null, permanent: false, null);
        Locked(h, false);
        await h.Engine.HousekeepOnceAsync();

        Assert.True((await h.Store.GetBanAsync(Attacker))!.IsPermanent);
    }

    [Fact]
    public async Task An_explicit_manual_ban_stands_whatever_the_unread_row_says()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        await h.Engine.BanNowAsync(Attacker, null, permanent: true, null);

        h.Store.FailBanRead = true;
        await h.Engine.BanNowAsync(Attacker, TimeSpan.FromHours(1), permanent: false, null);
        h.Store.FailBanRead = false;

        var row = (await h.Store.GetBanAsync(Attacker))!;
        Assert.False(row.IsPermanent);
        Assert.Equal(T0.UtcDateTime.AddHours(1), row.ExpiresUtc);
    }

    [Fact]
    public async Task A_logon_earns_no_trust_while_the_ban_cannot_be_read()
    {
        await using var h = await EngineHarness.StartAsync(T0, s => s.Rules.TrustAdminIpHours = 2);
        await h.Store.UpsertBanAsync(new BanEntry
        {
            IpAddress = Attacker,
            Source = ProtocolSource.MsSql,
            BannedAtUtc = T0.UtcDateTime,
            ExpiresUtc = T0.UtcDateTime.AddDays(1),
            OffenseCount = 1,
        });

        h.Store.FailBanRead = true;
        await h.ProcessAsync(new FailedLogin
        {
            IpAddress = Attacker,
            UserName = "alice",
            Source = ProtocolSource.Rdp,
            Detector = "4624",
            TimestampUtc = T0.UtcDateTime,
            IsSuccess = true,
            LogonType = 10,
        });

        Assert.DoesNotContain(h.Store.Events, e => e.Message.StartsWith("TEMPORARILY TRUSTED", StringComparison.Ordinal));
    }

    // ---------- expiry goes by the newest ban ----------

    /// <summary>The row of a first ban that ran out and cannot be deleted, and a second ban the store refused.</summary>
    private static async Task ReBanOverAnExpiredRowAsync(EngineHarness h)
    {
        h.Store.ActiveClock = () => h.Time.UtcNow.UtcDateTime;
        await Threshold(h, Attacker, ProtocolSource.MsSql);

        h.Store.FailWrites = true;
        h.Store.FailBanRemoval = true;
        h.Time.Advance(TimeSpan.FromHours(24) + TimeSpan.FromSeconds(1));
        await h.Engine.HousekeepOnceAsync();
        Assert.DoesNotContain(Attacker, h.Firewall.Blocked);

        // The attacker returns; the ban is enforced and held in memory.
        await Threshold(h, Attacker, ProtocolSource.MsSql);
        Assert.Contains(Attacker, h.Firewall.Blocked);
    }

    [Fact]
    public async Task An_unsaved_reban_stays_blocked_across_timer_passes_while_the_expired_row_cannot_be_deleted()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        await ReBanOverAnExpiredRowAsync(h);

        // HousekeepOnceAsync just reconciled, so the next timer passes do not.
        var open = 0;
        for (var pass = 0; pass < 3; pass++)
        {
            h.Time.Advance(TimeSpan.FromSeconds(15));
            await PassLikeTheTimer(h);
            open += h.Firewall.Blocked.Contains(Attacker) ? 0 : 1;
        }

        Assert.True(open == 0, $"attacker unblocked after {open} of 3 timer passes");
    }

    [Fact]
    public async Task A_widened_unsaved_ban_outlives_the_old_row()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        await Threshold(h, Attacker, ProtocolSource.Rdp, "4625");

        h.Store.FailWrites = true;
        h.Store.FailBanRemoval = true;
        h.Time.Advance(TimeSpan.FromHours(23) + TimeSpan.FromMinutes(59) + TimeSpan.FromSeconds(30));
        await Threshold(h, Attacker, ProtocolSource.MsSql); // widened for 7 days, unsaved
        await h.Engine.HousekeepOnceAsync();

        h.Time.Advance(TimeSpan.FromSeconds(40)); // past the old row's expiry, inside the 60 s reconcile interval
        h.Firewall.UnblockCalls.Clear();
        await PassLikeTheTimer(h);

        Assert.DoesNotContain(Attacker, h.Firewall.UnblockCalls);
        Assert.Contains(Attacker, h.Firewall.Blocked);
    }

    [Fact]
    public async Task The_unsaved_ban_replaces_the_expired_row_when_the_store_recovers()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        await ReBanOverAnExpiredRowAsync(h);

        h.Store.FailWrites = false;
        h.Store.FailBanRemoval = false;
        await h.Engine.HousekeepOnceAsync();

        var row = (await h.Store.GetBanAsync(Attacker))!;
        Assert.Equal(2, row.OffenseCount);
        Assert.True(row.ExpiresUtc > h.Time.UtcNow.UtcDateTime);
        Assert.Contains(Attacker, h.Firewall.Blocked);
    }

    [Fact]
    public async Task The_expired_row_expires_once_when_the_unsaved_ban_runs_out_first()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        await ReBanOverAnExpiredRowAsync(h);

        h.Time.Advance(TimeSpan.FromDays(8));
        await h.Engine.HousekeepOnceAsync();
        Assert.DoesNotContain(Attacker, h.Firewall.Blocked);

        h.Store.FailWrites = false;
        h.Store.FailBanRemoval = false;
        await h.Engine.HousekeepOnceAsync();
        await h.Engine.HousekeepOnceAsync();

        Assert.Null(await h.Store.GetBanAsync(Attacker));
        Assert.Single(h.Store.BanHistory, row => row.Action == BanHistoryAction.Expired);
    }

    // ---------- whitelist unknown at start-up ----------

    private static Task UnreadableLists(FakeStore store)
    {
        store.FailListRead = true;
        return Task.CompletedTask;
    }

    [Fact]
    public async Task A_whitelisted_ip_is_not_banned_while_the_lists_cannot_be_read()
    {
        await using var h = await EngineHarness.StartAsync(T0, seed: async store =>
        {
            await store.AddToListAsync(ListKind.Whitelist, Attacker);
            store.FailListRead = true;
        });

        await Threshold(h, Attacker, ProtocolSource.MsSql);
        Assert.Empty(h.Firewall.BlockCalls);
        Assert.Contains(h.Store.Events, e => e.Message.StartsWith($"SKIPPED {Attacker} (whitelist unreadable", StringComparison.Ordinal));

        h.Store.FailListRead = false;
        await Threshold(h, Attacker, ProtocolSource.MsSql);

        Assert.Empty(h.Firewall.BlockCalls);
        Assert.Null(await h.Store.GetBanAsync(Attacker));
    }

    [Fact]
    public async Task An_attacker_counted_while_the_lists_cannot_be_read_is_banned_once_they_load()
    {
        await using var h = await EngineHarness.StartAsync(T0, seed: UnreadableLists);

        await Threshold(h, Attacker, ProtocolSource.MsSql);
        Assert.Empty(h.Firewall.BlockCalls);
        Assert.Equal(5, h.Store.FailedLogins.Count);

        h.Store.FailListRead = false;
        await h.ProcessAsync(h.Fail(Attacker, ProtocolSource.MsSql));

        Assert.Contains(Attacker, h.Firewall.Blocked);
    }

    [Fact]
    public async Task Failures_held_in_memory_while_nothing_can_be_read_still_ban_once_the_lists_load()
    {
        await using var h = await EngineHarness.StartAsync(T0, seed: store =>
        {
            store.FailWrites = true;
            return UnreadableLists(store);
        });

        await Threshold(h, Attacker, ProtocolSource.MsSql);
        Assert.Empty(h.Firewall.BlockCalls);

        h.Store.FailListRead = false;
        await h.ProcessAsync(h.Fail(Attacker, ProtocolSource.MsSql));

        Assert.Contains(Attacker, h.Firewall.Blocked);
    }

    [Fact]
    public async Task A_whitelisted_ip_banned_while_the_lists_were_unreadable_is_released_once_they_load()
    {
        await using var h = await EngineHarness.StartAsync(T0, seed: async store =>
        {
            await store.AddToListAsync(ListKind.Whitelist, Attacker);
            store.FailListRead = true;
        });

        // An administrator can still ban by hand with nothing to check it against.
        await h.Engine.BanNowAsync(Attacker, null, permanent: false, null);
        Assert.Contains(Attacker, h.Firewall.Blocked);

        h.Store.FailListRead = false;
        await h.Engine.HousekeepOnceAsync();

        Assert.DoesNotContain(Attacker, h.Firewall.Blocked);
        Assert.Null(await h.Store.GetBanAsync(Attacker));
    }

    // ---------- replay is older than the count window ----------

    private static Task<EngineHarness> AfterDowntimeAsync(TimeSpan downtime, Func<FakeStore, Task>? seed = null) =>
        EngineHarness.StartAsync(T0, seed: async store =>
        {
            await store.SetSettingAsync("engine_last_alive_utc", (T0 - downtime).UtcDateTime.ToString("o", CultureInfo.InvariantCulture));
            if (seed is not null)
            {
                await seed(store);
            }
        });

    private static FailedLogin Replayed(EngineHarness h, DateTimeOffset at)
    {
        var failed = h.Fail(Attacker, ProtocolSource.MsSql, at: at.UtcDateTime);
        failed.IsReplayed = true;
        return failed;
    }

    [Theory]
    [InlineData(5, false)]
    [InlineData(15, false)]
    [InlineData(5, true)]
    [InlineData(15, true)]
    public async Task A_burst_during_downtime_bans_after_replay(int minutesAgo, bool newestFirst)
    {
        await using var h = await AfterDowntimeAsync(TimeSpan.FromMinutes(20));
        var attempts = Enumerable.Range(0, 20).Select(i => T0.AddMinutes(-minutesAgo).AddSeconds(i));

        foreach (var at in newestFirst ? attempts.Reverse() : attempts)
        {
            await h.ProcessAsync(Replayed(h, at));
        }

        Assert.Contains(Attacker, h.Firewall.Blocked);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Replayed_failures_too_far_apart_for_one_window_ban_nobody(bool newestFirst)
    {
        await using var h = await AfterDowntimeAsync(TimeSpan.FromMinutes(30));
        var attempts = Enumerable.Range(0, 7).Select(i => T0.AddMinutes(-25 + (i * 3)));

        foreach (var at in newestFirst ? attempts.Reverse() : attempts)
        {
            await h.ProcessAsync(Replayed(h, at));
        }

        Assert.Empty(h.Firewall.Blocked);
        Assert.Equal(7, h.Store.FailedLogins.Count);
    }

    [Fact]
    public async Task A_burst_older_than_the_replay_window_bans_nobody()
    {
        await using var h = await AfterDowntimeAsync(TimeSpan.FromHours(3));

        for (var i = 0; i < 20; i++)
        {
            await h.ProcessAsync(Replayed(h, T0.AddHours(-2).AddSeconds(i)));
        }

        Assert.Empty(h.Firewall.Blocked);
    }

    [Fact]
    public async Task Replay_counts_together_with_what_the_last_run_stored_before_it_stopped()
    {
        await using var h = await AfterDowntimeAsync(TimeSpan.FromMinutes(15), async store =>
        {
            for (var i = 0; i < 3; i++)
            {
                await store.AddFailedLoginAsync(new FailedLogin
                {
                    IpAddress = Attacker,
                    Source = ProtocolSource.MsSql,
                    TimestampUtc = T0.AddMinutes(-16).AddSeconds(i).UtcDateTime,
                });
            }
        });

        await h.ProcessAsync(Replayed(h, T0.AddMinutes(-14)));
        Assert.Empty(h.Firewall.Blocked);

        await h.ProcessAsync(Replayed(h, T0.AddMinutes(-13)));

        Assert.Contains(Attacker, h.Firewall.Blocked);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task A_replayed_burst_bans_while_the_store_refuses_it(bool newestFirst)
    {
        await using var h = await AfterDowntimeAsync(TimeSpan.FromMinutes(20));
        h.Store.FailWrites = true;
        h.Store.FailFailureReads = true;
        var attempts = Enumerable.Range(0, 5).Select(i => T0.AddMinutes(-15).AddSeconds(i));

        foreach (var at in newestFirst ? attempts.Reverse() : attempts)
        {
            await h.ProcessAsync(Replayed(h, at));
        }

        Assert.Contains(Attacker, h.Firewall.Blocked);
    }

    // ---------- NAT64 ----------

    [Fact]
    public async Task One_nat64_attacker_does_not_ban_every_ipv4_client_of_the_translator()
    {
        await using var h = await EngineHarness.StartAsync(T0, s => s.Ipv6AggregatePrefixLength = 64);
        await Threshold(h, Nat64Client, ProtocolSource.MsSql);

        Assert.Equal(Nat64Client, Assert.Single(h.Firewall.Blocked));
    }

    [Fact]
    public async Task A_whitelisted_ipv4_client_seen_through_nat64_is_not_banned()
    {
        await using var h = await EngineHarness.StartAsync(T0, seed: store => store.AddToListAsync(ListKind.Whitelist, "203.0.113.1"));
        await Threshold(h, Nat64Client, ProtocolSource.MsSql);

        Assert.Empty(h.Firewall.Blocked);
    }

    [Fact]
    public async Task Whitelisting_an_ipv4_client_lifts_its_nat64_ban()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        await Threshold(h, Nat64Client, ProtocolSource.MsSql);
        Assert.Contains(Nat64Client, h.Firewall.Blocked);

        await h.Store.AddToListAsync(ListKind.Whitelist, "203.0.113.0/24");
        await h.Engine.HousekeepOnceAsync();

        Assert.Empty(h.Firewall.Blocked);
    }

    [Fact]
    public async Task A_blacklisted_ipv4_client_seen_through_nat64_is_banned_for_good()
    {
        await using var h = await EngineHarness.StartAsync(T0, seed: store => store.AddToListAsync(ListKind.Blacklist, "203.0.113.1"));
        await h.ProcessAsync(h.Fail(Nat64Client, ProtocolSource.MsSql));

        Assert.True((await h.Store.GetBanAsync(Nat64Client))!.IsPermanent);
    }

    // ---------- shutdown between the block and the save ----------

    [Fact]
    public async Task A_ban_cancelled_between_block_and_save_is_saved_on_stop()
    {
        using var cts = new CancellationTokenSource();
        await using var h = await EngineHarness.StartAsync(T0);
        h.Store.BeforeUpsert = ct =>
        {
            if (cts.Token == ct && !cts.IsCancellationRequested)
            {
                cts.Cancel();
            }

            ct.ThrowIfCancellationRequested();
        };

        for (var i = 0; i < 4; i++)
        {
            await h.Engine.ProcessAsync(h.Fail(Attacker, ProtocolSource.MsSql), cts.Token);
        }

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => h.Engine.ProcessAsync(h.Fail(Attacker, ProtocolSource.MsSql), cts.Token));
        Assert.Contains(Attacker, h.Firewall.Blocked);

        h.Store.BeforeUpsert = null;
        await h.Engine.StopAsync();
        Assert.NotNull(await h.Store.GetBanAsync(Attacker));
    }

    // ---------- a re-ban without a duration ----------

    [Fact]
    public async Task A_manual_ban_without_duration_does_not_shorten_a_permanent_ban()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        await h.Engine.BanNowAsync(Attacker, null, permanent: true, "keep out");

        await h.Engine.BanNowAsync(Attacker, null, permanent: false, null);

        var row = (await h.Store.GetBanAsync(Attacker))!;
        Assert.True(row.IsPermanent);
        Assert.Equal(DateTime.MaxValue, row.ExpiresUtc);
        Assert.Equal("keep out", row.Note);
    }

    [Fact]
    public async Task A_manual_ban_without_duration_keeps_a_longer_running_ban()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        await h.Engine.BanNowAsync(Attacker, TimeSpan.FromDays(3), permanent: false, null);

        await h.Engine.BanNowAsync(Attacker, null, permanent: false, null);

        var row = (await h.Store.GetBanAsync(Attacker))!;
        Assert.Equal(T0.UtcDateTime.AddDays(3), row.ExpiresUtc);
        Assert.Equal(TimeSpan.FromDays(3), h.Store.BanHistory.Last().Duration);
    }

    [Fact]
    public async Task A_manual_ban_without_duration_still_extends_a_shorter_ban()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        await h.Engine.BanNowAsync(Attacker, TimeSpan.FromHours(1), permanent: false, null);

        await h.Engine.BanNowAsync(Attacker, null, permanent: false, null);

        Assert.Equal(T0.UtcDateTime.AddHours(24), (await h.Store.GetBanAsync(Attacker))!.ExpiresUtc);
    }

    [Fact]
    public async Task An_explicit_duration_still_shortens_a_permanent_ban()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        await h.Engine.BanNowAsync(Attacker, null, permanent: true, null);

        await h.Engine.BanNowAsync(Attacker, TimeSpan.FromHours(1), permanent: false, null);

        var row = (await h.Store.GetBanAsync(Attacker))!;
        Assert.False(row.IsPermanent);
        Assert.Equal(T0.UtcDateTime.AddHours(1), row.ExpiresUtc);
    }

    // ---------- clearing on start with unreadable lists ----------

    [Fact]
    public async Task Clearing_on_start_with_unreadable_lists_does_not_sync_the_blacklisted_ranges_away()
    {
        await using var h = await EngineHarness.StartAsync(T0, s => s.ClearBansOnStartup = true, seed: async store =>
        {
            await store.AddToListAsync(ListKind.Blacklist, "198.51.100.0/24");
            store.FailListRead = true;
        });

        Assert.Empty(h.Firewall.SyncRulesCalls);
    }

    [Fact]
    public async Task Clearing_on_start_with_unreadable_lists_lifts_the_ban_rules_once_they_load()
    {
        const string range = "198.51.100.0/24";
        await using var h = await EngineHarness.StartAsync(T0, s => s.ClearBansOnStartup = true, seed: async store =>
        {
            await store.AddToListAsync(ListKind.Blacklist, range);
            await store.UpsertBanAsync(new BanEntry
            {
                IpAddress = Attacker,
                Source = ProtocolSource.MsSql,
                BannedAtUtc = T0.UtcDateTime,
                ExpiresUtc = T0.UtcDateTime.AddDays(1),
            });
            store.FailListRead = true;
        });
        h.Firewall.Block(Attacker); // the rules a previous run left in place
        h.Firewall.Block(range);

        Assert.Null(await h.Store.GetBanAsync(Attacker));

        h.Store.FailListRead = false;
        await h.Engine.HousekeepOnceAsync();

        Assert.Equal([range], h.Firewall.Blocked);
    }

    // ---------- exclusion take-back during an outage ----------

    [Fact]
    public async Task Excluded_attempts_are_not_counted_while_the_store_refuses_writes()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        h.Store.FailWrites = true;

        for (var i = 0; i < 6; i++)
        {
            await h.ProcessAsync(h.Fail(Attacker, ProtocolSource.Rdp, user: null, detector: "140"));
            var excluded = h.Fail(Attacker, ProtocolSource.Rdp, user: "backup-svc", detector: "4625");
            excluded.IsExcluded = true;
            await h.ProcessAsync(excluded);
            h.Time.Advance(TimeSpan.FromSeconds(10));
        }

        Assert.Empty(h.Firewall.Blocked);
    }

    [Fact]
    public void Taking_back_a_held_failure_goes_by_source_and_time()
    {
        var counter = new FallbackFailureCounter();
        var at = T0.UtcDateTime;
        counter.Record(Attacker, ProtocolSource.Rdp, at);
        var tolerance = TimeSpan.FromSeconds(2);

        Assert.False(counter.TryRemoveNear("203.0.113.51", ProtocolSource.Rdp, at, tolerance));
        Assert.False(counter.TryRemoveNear(Attacker, ProtocolSource.MsSql, at, tolerance));
        Assert.False(counter.TryRemoveNear(Attacker, ProtocolSource.Rdp, at.AddSeconds(3), tolerance));
        Assert.True(counter.TryRemoveNear(Attacker, ProtocolSource.Rdp, at.AddSeconds(1), tolerance));
        Assert.Equal(0, counter.Count(Attacker, DateTime.MinValue));
    }

    // ---------- unbanning a member of an aggregate ban ----------

    private static async Task BanAggregateAsync(EngineHarness h)
    {
        await Threshold(h, "2001:db8:1:2::5", ProtocolSource.MsSql);
        Assert.Contains(Aggregate, h.Firewall.Blocked);
    }

    [Fact]
    public async Task Unbanning_an_address_inside_an_aggregate_ban_lifts_the_range_and_says_so()
    {
        await using var h = await EngineHarness.StartAsync(T0, s => s.Ipv6AggregatePrefixLength = 64);
        await BanAggregateAsync(h);

        await h.Engine.UnbanAsync("2001:db8:1:2::5");

        Assert.DoesNotContain(Aggregate, h.Firewall.Blocked);
        Assert.Null(await h.Store.GetBanAsync(Aggregate));
        Assert.Contains(h.Store.Events, e => e.Message == $"MANUAL UNBLOCK {Aggregate} (it held 2001:db8:1:2::5)");
        Assert.Contains(h.Store.BanHistory, row => row.Action == BanHistoryAction.Unbanned && row.IpAddress == Aggregate);
    }

    [Fact]
    public async Task Unbanning_an_address_inside_an_unsaved_aggregate_ban_lifts_it_too()
    {
        await using var h = await EngineHarness.StartAsync(T0, s => s.Ipv6AggregatePrefixLength = 64);
        h.Store.FailWrites = true;
        await BanAggregateAsync(h);

        await h.Engine.UnbanAsync("2001:db8:1:2::5");
        await h.Engine.HousekeepOnceAsync();

        Assert.Empty(h.Firewall.Blocked);
    }

    [Fact]
    public async Task Unbanning_an_address_leaves_ranges_that_do_not_hold_it()
    {
        await using var h = await EngineHarness.StartAsync(T0, s => s.Ipv6AggregatePrefixLength = 64);
        await BanAggregateAsync(h);

        await h.Engine.UnbanAsync("2001:db8:1:3::5");

        Assert.Contains(Aggregate, h.Firewall.Blocked);
    }

    // ---------- the unsaved bans and the RDP de-dup stay bounded ----------

    [Fact]
    public async Task At_its_limit_the_unsaved_ban_closest_to_its_end_goes_and_that_is_logged()
    {
        var store = new FakeStore();
        var firewall = new FakeFirewall();
        var logger = new RecordingLogger();
        var settings = new WinGuardSettings { HousekeepingInterval = TimeSpan.FromHours(6) };
        var engine = new BanEngine(store, firewall, () => settings, logger, new FakeTimeProvider(T0)) { MaxUnsavedBans = 2 };
        await engine.StartAsync(CancellationToken.None);

        store.FailWrites = true;
        await engine.BanNowAsync("203.0.113.1", null, permanent: true, null);
        await engine.BanNowAsync("203.0.113.2", TimeSpan.FromHours(1), permanent: false, null);
        await engine.BanNowAsync("203.0.113.3", TimeSpan.FromHours(2), permanent: false, null);

        Assert.Contains(logger.Lines, line => line.Level == LogLevel.Error && line.Text.Contains("dropped the one of 203.0.113.2", StringComparison.Ordinal));

        store.FailWrites = false;
        await engine.HousekeepOnceAsync();
        await engine.StopAsync();

        Assert.Equal(["203.0.113.1", "203.0.113.3"], (await store.GetActiveBansAsync()).Select(ban => ban.IpAddress).Order(StringComparer.Ordinal));
        Assert.DoesNotContain("203.0.113.2", firewall.Blocked);
    }

    [Fact]
    public void The_dedup_empties_itself_at_its_limit_and_reports_it_once()
    {
        var dedup = new RdpDeduplicator(maxTrackedIps: 2);
        var at = T0.UtcDateTime;

        dedup.IsDuplicateAndRecord("203.0.113.1", "4625", at);
        dedup.IsDuplicateAndRecord("203.0.113.2", "4625", at);
        Assert.Equal(0, dedup.TakeResets());

        dedup.IsDuplicateAndRecord("203.0.113.3", "4625", at);

        Assert.Equal(1, dedup.TrackedIps);
        Assert.Equal(1, dedup.TakeResets());
        Assert.Equal(0, dedup.TakeResets());
    }

    [Fact]
    public void At_its_limit_the_dedup_drops_what_is_stale_first()
    {
        var dedup = new RdpDeduplicator(maxTrackedIps: 2);
        var at = T0.UtcDateTime;

        dedup.IsDuplicateAndRecord("203.0.113.1", "4625", at);
        dedup.IsDuplicateAndRecord("203.0.113.2", "4625", at.AddSeconds(30));
        dedup.IsDuplicateAndRecord("203.0.113.3", "4625", at.AddSeconds(31));

        Assert.Equal(2, dedup.TrackedIps);
        Assert.Equal(0, dedup.TakeResets());
    }

    [Fact]
    public void The_replay_dedup_is_bounded_too()
    {
        var dedup = new RdpDeduplicator(trimByEventTime: false, maxTrackedIps: 2);
        var at = T0.UtcDateTime;

        foreach (var ip in new[] { "203.0.113.1", "203.0.113.2", "203.0.113.3" })
        {
            dedup.RecordExcluded(ip, "4625", at);
        }

        Assert.Equal(1, dedup.TrackedIps);
        Assert.Equal(1, dedup.TakeResets());
    }

    private static readonly FieldInfo RdpDedupField =
        typeof(BanEngine).GetField("_rdpDedup", BindingFlags.Instance | BindingFlags.NonPublic)!;

    [Fact]
    public async Task An_outage_does_not_stop_housekeeping_from_trimming_the_dedup()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        Locked(h, true);
        for (var i = 1; i <= 3; i++)
        {
            await h.ProcessAsync(h.Fail($"203.0.113.{i}", ProtocolSource.Rdp, detector: "140"));
        }

        var dedup = (RdpDeduplicator)RdpDedupField.GetValue(h.Engine)!;
        Assert.Equal(3, dedup.TrackedIps);

        h.Time.Advance(TimeSpan.FromSeconds(15));
        await h.Engine.HousekeepOnceAsync();

        Assert.Equal(0, dedup.TrackedIps);
    }

    [Fact]
    public async Task Housekeeping_logs_that_the_dedup_reached_its_limit()
    {
        var store = new FakeStore();
        var logger = new RecordingLogger();
        var settings = new WinGuardSettings { HousekeepingInterval = TimeSpan.FromHours(6) };
        var time = new FakeTimeProvider(T0);
        var engine = new BanEngine(store, new FakeFirewall(), () => settings, logger, time);
        await engine.StartAsync(CancellationToken.None);
        RdpDedupField.SetValue(engine, new RdpDeduplicator(maxTrackedIps: 1));

        foreach (var ip in new[] { "203.0.113.1", "203.0.113.2" })
        {
            await engine.ProcessAsync(new FailedLogin { IpAddress = ip, Source = ProtocolSource.Rdp, Detector = "140", TimestampUtc = T0.UtcDateTime });
        }

        await engine.HousekeepOnceAsync();
        await engine.StopAsync();

        Assert.Contains(logger.Lines, line => line.Level == LogLevel.Warning && line.Text.Contains("de-dup reached its limit", StringComparison.Ordinal));
    }

    private sealed class RecordingLogger : ILogger<BanEngine>
    {
        private readonly object _gate = new();
        private readonly List<(LogLevel Level, string Text)> _lines = [];

        public IReadOnlyList<(LogLevel Level, string Text)> Lines
        {
            get { lock (_gate) { return _lines.ToList(); } }
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            lock (_gate)
            {
                _lines.Add((logLevel, formatter(state, exception)));
            }
        }
    }
}
