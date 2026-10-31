using Microsoft.Extensions.Logging.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Engine;
using WinGuard.Core.Firewall;
using WinGuard.Core.Model;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>
/// Port-scoped bans in the engine: one row per address, however many engines it attacks, and every
/// path that touches the firewall keeping to the row's ports.
/// </summary>
public sealed class BanEnginePortScopeTests
{
    private static readonly DateTimeOffset T0 = new(2026, 5, 1, 12, 0, 0, TimeSpan.Zero);

    private const string Attacker = "203.0.113.50";
    private const string Rdp4625 = "4625";

    private static readonly PortSet RdpPort = PortSet.Parse(["3389"]);
    private static readonly PortSet SqlPort = PortSet.Parse(["1433"]);
    private static readonly PortSet RdpAndSql = PortSet.Parse(["1433", "3389"]);

    private static void Profiles(WinGuardSettings settings)
    {
        settings.Rdp.BlockedPorts = ["3389"];
        settings.MsSql.BlockedPorts = ["1433"];
    }

    // ---------- nothing configured ----------

    [Fact]
    public async Task Without_any_port_setting_a_ban_blocks_all_ports_and_reads_as_it_always_did()
    {
        await using var h = await EngineHarness.StartAsync(T0);

        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);

        Assert.Equal(PortSet.All, h.Firewall.PortsOf(Attacker));
        Assert.Contains(h.Store.Events, e => e.Message.StartsWith($"BLOCKED {Attacker} for 1.00:00:00", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Without_any_port_setting_a_second_engine_changes_nothing()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);
        var ban = await h.Store.GetBanAsync(Attacker);

        await SendThresholdAsync(h, ProtocolSource.MsSql);

        var after = await h.Store.GetBanAsync(Attacker);
        Assert.Equal(ban!.ExpiresUtc, after!.ExpiresUtc);
        Assert.Equal(ban.OffenseCount, after.OffenseCount);
        Assert.Single(h.Firewall.BlockCalls);
        Assert.Contains(h.Store.Events, e => e.Message == $"SKIPPED {Attacker} (already banned)");
        Assert.DoesNotContain(h.Store.FailedLogins, f => f.Source == ProtocolSource.MsSql);
    }

    // ---------- scoped bans ----------

    [Fact]
    public async Task A_ban_blocks_the_ports_of_the_engine_that_issued_it()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);

        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);

        Assert.Equal(RdpPort, h.Firewall.PortsOf(Attacker));
        Assert.Contains(h.Store.Events, e => e.Message.StartsWith($"BLOCKED {Attacker} on ports 3389 for ", StringComparison.Ordinal));
    }

    [Fact]
    public async Task An_engine_without_a_profile_uses_the_global_list()
    {
        await using var h = await EngineHarness.StartAsync(T0, s => s.BlockedPorts = ["22"]);

        await SendThresholdAsync(h, ProtocolSource.Ftp);

        Assert.Equal(PortSet.Parse(["22"]), h.Firewall.PortsOf(Attacker));
    }

    [Fact]
    public async Task A_custom_source_bans_on_its_own_profile()
    {
        await using var h = await EngineHarness.StartAsync(T0, s => s.CustomSources =
        [
            new CustomLogSource { Name = "mail", BlockedPorts = ["25"] },
            new CustomLogSource { Name = "web", BlockedPorts = ["443"] },
        ]);

        await SendThresholdAsync(h, ProtocolSource.Custom, "web");

        Assert.Equal(PortSet.Parse(["443"]), h.Firewall.PortsOf(Attacker));
    }

    // ---------- widening ----------

    [Fact]
    public async Task A_banned_address_attacking_another_engine_gets_that_engines_ports_too()
    {
        // The hole this design exists to close: "already banned, ignore" would leave SQL open for good.
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);

        await SendThresholdAsync(h, ProtocolSource.MsSql);

        Assert.Equal(RdpAndSql, h.Firewall.PortsOf(Attacker));
        Assert.Equal("1433,3389", PortProfiles.Resolve((await h.Store.GetBanAsync(Attacker))!.PortScope, h.Settings).Text);
    }

    [Fact]
    public async Task One_failed_login_from_a_colleague_behind_the_same_address_does_not_widen_the_ban()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);

        await h.ProcessAsync(h.Fail(Attacker, ProtocolSource.MsSql));

        Assert.Equal(RdpPort, h.Firewall.PortsOf(Attacker));
    }

    [Fact]
    public async Task Failures_towards_widening_count_against_the_second_engines_own_threshold_and_window()
    {
        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            Profiles(s);
            s.MsSql.Threshold = 2;
            s.MsSql.CountWindow = TimeSpan.FromMinutes(1);
        });
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);

        await h.ProcessAsync(h.Fail(Attacker, ProtocolSource.MsSql));
        h.Time.Advance(TimeSpan.FromMinutes(2));
        await h.ProcessAsync(h.Fail(Attacker, ProtocolSource.MsSql));
        Assert.Equal(RdpPort, h.Firewall.PortsOf(Attacker));

        await h.ProcessAsync(h.Fail(Attacker, ProtocolSource.MsSql));
        Assert.Equal(RdpAndSql, h.Firewall.PortsOf(Attacker));
    }

    [Fact]
    public async Task A_widened_ban_is_a_new_offense_with_a_full_tier_and_keeps_its_origin()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);
        var original = (await h.Store.GetBanAsync(Attacker))!;
        h.Time.Advance(TimeSpan.FromHours(23));

        await SendThresholdAsync(h, ProtocolSource.MsSql);

        var widened = (await h.Store.GetBanAsync(Attacker))!;
        Assert.Equal(2, widened.OffenseCount);
        Assert.Equal(h.Time.GetUtcNow().UtcDateTime + TimeSpan.FromDays(7), widened.ExpiresUtc);
        Assert.Equal(ProtocolSource.Rdp, widened.Source);
        Assert.Equal(original.BannedAtUtc, widened.BannedAtUtc);
    }

    [Fact]
    public async Task Widening_never_shortens_a_ban()
    {
        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            Profiles(s);
            s.BanTiers = [TimeSpan.FromDays(30), TimeSpan.FromHours(1)];
        });
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);
        var expires = (await h.Store.GetBanAsync(Attacker))!.ExpiresUtc;

        await SendThresholdAsync(h, ProtocolSource.MsSql);

        Assert.Equal(expires, (await h.Store.GetBanAsync(Attacker))!.ExpiresUtc);
    }

    [Fact]
    public async Task Widening_is_recorded_as_an_update_and_reported_as_a_block()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);

        await SendThresholdAsync(h, ProtocolSource.MsSql);

        Assert.Single(h.Store.BanHistory, row => row.Action == BanHistoryAction.Banned);
        var update = Assert.Single(h.Store.BanHistory, row => row.Action == BanHistoryAction.Updated);
        Assert.Equal(ProtocolSource.MsSql, update.Source);
        Assert.Contains("1433,3389", update.Note);
        var message = h.Store.Events.Last(e => e.Level == LogEventLevel.Warning).Message;
        Assert.StartsWith($"BLOCKED {Attacker} on ports 1433,3389", message);
    }

    [Fact]
    public async Task Once_widened_further_failures_are_ignored_like_on_any_ban()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);
        await SendThresholdAsync(h, ProtocolSource.MsSql);
        var writes = h.Firewall.BlockCalls.Count;

        await SendThresholdAsync(h, ProtocolSource.MsSql);
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);

        Assert.Equal(writes, h.Firewall.BlockCalls.Count);
        Assert.Equal(2, (await h.Store.GetBanAsync(Attacker))!.OffenseCount);
    }

    [Fact]
    public async Task A_third_engine_widens_the_ban_again()
    {
        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            Profiles(s);
            s.Ftp.BlockedPorts = ["21"];
        });
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);
        await SendThresholdAsync(h, ProtocolSource.MsSql);

        await SendThresholdAsync(h, ProtocolSource.Ftp);

        Assert.Equal(PortSet.Parse(["21", "1433", "3389"]), h.Firewall.PortsOf(Attacker));
    }

    [Fact]
    public async Task An_engine_blocking_all_ports_widens_a_ban_to_all_ports()
    {
        await using var h = await EngineHarness.StartAsync(T0, s => s.Rdp.BlockedPorts = ["3389"]);
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);

        await SendThresholdAsync(h, ProtocolSource.MsSql);

        Assert.Equal(PortSet.All, h.Firewall.PortsOf(Attacker));
    }

    [Fact]
    public async Task An_engine_whose_ports_the_ban_covers_widens_nothing()
    {
        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            s.Rdp.BlockedPorts = ["3389", "1433"];
            s.MsSql.BlockedPorts = ["1433"];
        });
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);

        await SendThresholdAsync(h, ProtocolSource.MsSql);

        Assert.Single(h.Firewall.BlockCalls);
        Assert.Equal(1, (await h.Store.GetBanAsync(Attacker))!.OffenseCount);
    }

    [Fact]
    public async Task A_custom_source_widens_a_ban_by_its_own_ports()
    {
        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            s.Rdp.BlockedPorts = ["3389"];
            s.CustomSources = [new CustomLogSource { Name = "mail", BlockedPorts = ["25"] }];
        });
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);

        await SendThresholdAsync(h, ProtocolSource.Custom, "mail");

        Assert.Equal(PortSet.Parse(["25", "3389"]), h.Firewall.PortsOf(Attacker));
    }

    [Fact]
    public async Task A_widened_ban_expires_and_leaves_the_firewall_clean()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);
        await SendThresholdAsync(h, ProtocolSource.MsSql);

        h.Time.Advance(TimeSpan.FromDays(8));
        await h.Engine.HousekeepOnceAsync();

        Assert.Null(await h.Store.GetBanAsync(Attacker));
        Assert.DoesNotContain(Attacker, h.Firewall.Blocked);
        Assert.Contains(h.Store.BanHistory, row => row.Action == BanHistoryAction.Expired);
    }

    [Fact]
    public async Task After_a_widened_ban_ends_the_next_one_starts_from_the_new_engine_alone()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);
        await SendThresholdAsync(h, ProtocolSource.MsSql);
        h.Time.Advance(TimeSpan.FromDays(8));
        await h.Engine.HousekeepOnceAsync();

        await SendThresholdAsync(h, ProtocolSource.MsSql);

        Assert.Equal(SqlPort, h.Firewall.PortsOf(Attacker));
    }

    [Fact]
    public async Task An_expired_ban_not_yet_lifted_is_replaced_rather_than_widened()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);
        h.Time.Advance(TimeSpan.FromHours(25));

        await SendThresholdAsync(h, ProtocolSource.MsSql);

        Assert.Equal(SqlPort, h.Firewall.PortsOf(Attacker));
        Assert.Equal("MsSql", (await h.Store.GetBanAsync(Attacker))!.PortScope);
    }

    [Fact]
    public async Task A_widened_scope_survives_a_restart()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);
        await SendThresholdAsync(h, ProtocolSource.MsSql);

        await using var restarted = await EngineHarness.StartAsync(T0, Profiles, store: h.Store);

        Assert.Equal(RdpAndSql, restarted.Firewall.PortsOf(Attacker));
    }

    // ---------- all-ports bans ----------

    [Fact]
    public async Task A_manual_ban_blocks_all_ports_whatever_the_settings_say()
    {
        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            Profiles(s);
            s.BlockedPorts = ["22"];
        });

        await h.Engine.BanNowAsync(Attacker, TimeSpan.FromHours(1), permanent: false, note: null);

        Assert.Equal(PortSet.All, h.Firewall.PortsOf(Attacker));
        Assert.Equal(PortProfiles.AllPorts, (await h.Store.GetBanAsync(Attacker))!.PortScope);
    }

    [Fact]
    public async Task A_manual_ban_widens_a_narrower_one_to_all_ports()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);

        await h.Engine.BanNowAsync(Attacker, null, permanent: true, note: null);

        Assert.Equal(PortSet.All, h.Firewall.PortsOf(Attacker));
    }

    [Fact]
    public async Task An_all_ports_ban_stays_all_ports_when_an_engine_with_a_profile_attacks()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        await h.Engine.BanNowAsync(Attacker, TimeSpan.FromHours(1), permanent: false, note: null);
        var offense = (await h.Store.GetBanAsync(Attacker))!.OffenseCount;

        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);

        Assert.Equal(PortSet.All, h.Firewall.PortsOf(Attacker));
        var ban = (await h.Store.GetBanAsync(Attacker))!;
        Assert.Equal(PortProfiles.AllPorts, ban.PortScope);
        Assert.Equal(offense, ban.OffenseCount);
    }

    [Fact]
    public async Task A_blacklisted_address_is_banned_on_all_ports()
    {
        await using var h = await EngineHarness.StartAsync(
            T0,
            Profiles,
            seed: store => store.AddToListAsync(ListKind.Blacklist, Attacker));

        await h.ProcessAsync(h.Fail(Attacker, ProtocolSource.Rdp, detector: Rdp4625));

        Assert.Equal(PortSet.All, h.Firewall.PortsOf(Attacker));
        var ban = (await h.Store.GetBanAsync(Attacker))!;
        Assert.True(ban.IsPermanent);
        Assert.Equal(PortProfiles.AllPorts, ban.PortScope);
    }

    [Fact]
    public async Task Blacklisting_an_address_with_a_narrow_ban_takes_it_to_all_ports()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);

        await h.Store.AddToListAsync(ListKind.Blacklist, Attacker);
        await h.Engine.ReloadListsAsync();
        await h.ProcessAsync(h.Fail(Attacker, ProtocolSource.MsSql));

        Assert.Equal(PortSet.All, h.Firewall.PortsOf(Attacker));
        Assert.True((await h.Store.GetBanAsync(Attacker))!.IsPermanent);
    }

    [Fact]
    public async Task A_narrow_permanent_ban_goes_to_all_ports_when_the_address_is_blacklisted()
    {
        // A ban from an older version, permanent and following the global list.
        await using var h = await EngineHarness.StartAsync(
            T0,
            s => s.BlockedPorts = ["22"],
            seed: async store =>
            {
                await store.AddToListAsync(ListKind.Blacklist, Attacker);
                await store.UpsertBanAsync(Permanent(Attacker));
            });
        Assert.Equal(PortSet.Parse(["22"]), h.Firewall.PortsOf(Attacker));

        await h.ProcessAsync(h.Fail(Attacker, ProtocolSource.MsSql));

        Assert.Equal(PortSet.All, h.Firewall.PortsOf(Attacker));
        Assert.Equal(PortProfiles.AllPorts, (await h.Store.GetBanAsync(Attacker))!.PortScope);
    }

    [Fact]
    public async Task A_blacklisted_range_is_all_ports_even_with_a_global_list()
    {
        await using var h = await EngineHarness.StartAsync(
            T0,
            s => s.BlockedPorts = ["22"],
            seed: store => store.AddToListAsync(ListKind.Blacklist, "198.51.100.0/24"));

        Assert.Equal(PortSet.All, h.Firewall.PortsOf("198.51.100.0/24"));
    }

    [Fact]
    public async Task A_ban_on_a_blacklisted_range_itself_does_not_narrow_the_range()
    {
        await using var h = await EngineHarness.StartAsync(
            T0,
            Profiles,
            seed: async store =>
            {
                await store.AddToListAsync(ListKind.Blacklist, "2001:db8:1:2::/64");
                await store.UpsertBanAsync(new BanEntry
                {
                    IpAddress = "2001:db8:1:2::/64",
                    Source = ProtocolSource.Rdp,
                    BannedAtUtc = T0.UtcDateTime,
                    ExpiresUtc = T0.UtcDateTime.AddDays(1),
                    PortScope = "Rdp",
                });
            });

        Assert.Equal(PortSet.All, h.Firewall.PortsOf("2001:db8:1:2::/64"));
    }

    [Fact]
    public async Task A_ban_ending_on_a_blacklisted_range_itself_leaves_the_range_blocked()
    {
        const string Prefix = "2001:db8:1:2::/64";
        await using var h = await EngineHarness.StartAsync(
            T0,
            seed: async store =>
            {
                await store.AddToListAsync(ListKind.Blacklist, Prefix);
                await store.UpsertBanAsync(new BanEntry
                {
                    IpAddress = Prefix,
                    Source = ProtocolSource.Rdp,
                    BannedAtUtc = T0.UtcDateTime,
                    ExpiresUtc = T0.UtcDateTime.AddHours(1),
                });
            });

        h.Time.Advance(TimeSpan.FromHours(2));
        await h.Engine.HousekeepOnceAsync();

        Assert.Empty(h.Firewall.UnblockCalls);
        Assert.Contains(Prefix, h.Firewall.Blocked);
    }

    // ---------- bans from older versions ----------

    [Fact]
    public async Task A_row_from_an_older_version_stays_on_all_ports_without_a_global_list()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles, seed: store => store.UpsertBanAsync(OldRow(Attacker)));

        Assert.Equal(PortSet.All, h.Firewall.PortsOf(Attacker));

        await h.ProcessAsync(h.Fail(Attacker, ProtocolSource.Rdp, detector: Rdp4625));
        await h.Engine.HousekeepOnceAsync();

        Assert.Equal(PortSet.All, h.Firewall.PortsOf(Attacker));
        Assert.Null((await h.Store.GetBanAsync(Attacker))!.PortScope);
    }

    [Fact]
    public async Task A_row_from_an_older_version_follows_the_global_list_as_it_did()
    {
        await using var h = await EngineHarness.StartAsync(T0, s => s.BlockedPorts = ["22"], seed: store => store.UpsertBanAsync(OldRow(Attacker)));

        Assert.Equal(PortSet.Parse(["22"]), h.Firewall.PortsOf(Attacker));
    }

    [Fact]
    public async Task A_row_from_an_older_version_is_not_touched_by_an_engine_profile()
    {
        await using var h = await EngineHarness.StartAsync(T0, seed: store => store.UpsertBanAsync(OldRow(Attacker, ProtocolSource.Rdp)));

        h.Settings.Rdp.BlockedPorts = ["3389"];
        await h.Engine.HousekeepOnceAsync();

        Assert.Equal(PortSet.All, h.Firewall.PortsOf(Attacker));
    }

    [Fact]
    public async Task A_row_from_an_older_version_on_the_global_list_widens_too()
    {
        await using var h = await EngineHarness.StartAsync(
            T0,
            s =>
            {
                s.BlockedPorts = ["22"];
                s.MsSql.BlockedPorts = ["1433"];
            },
            seed: store => store.UpsertBanAsync(OldRow(Attacker, ProtocolSource.Rdp)));

        await SendThresholdAsync(h, ProtocolSource.MsSql);

        Assert.Equal(PortSet.Parse(["22", "1433"]), h.Firewall.PortsOf(Attacker));
    }

    [Fact]
    public async Task An_upgrade_moves_older_rule_pairs_into_their_family_with_no_address_left_unblocked()
    {
        // The real firewall logic over an in-memory rule store: rules and row exactly as 0.2 left them.
        var rules = new WindowsFirewallBatchingTests.FakeRuleStore();
        rules.Rules["WinGuard_Block_0001_TCP"] = (WindowsFirewall.ProtocolTcp, "22", $"{Attacker}/255.255.255.255");
        rules.Rules["WinGuard_Block_0001_UDP"] = (WindowsFirewall.ProtocolUdp, "22", $"{Attacker}/255.255.255.255");
        var store = new Fakes.FakeStore();
        await store.UpsertBanAsync(OldRow(Attacker));
        var settings = new WinGuardSettings { BlockedPorts = ["22"], HousekeepingInterval = TimeSpan.FromHours(6) };
        var firewall = new WindowsFirewall(NullLogger<WindowsFirewall>.Instance, rules);
        var engine = new BanEngine(store, firewall, () => settings, NullLogger<BanEngine>.Instance, new Fakes.FakeTimeProvider(T0));

        await engine.StartAsync(CancellationToken.None);
        await engine.StopAsync(CancellationToken.None);

        var family = PortSet.Parse(["22"]).RuleFamily;
        Assert.Equal(new[] { $"WinGuard_Block_{family}_0001_TCP", $"WinGuard_Block_{family}_0001_UDP" }, rules.Rules.Keys.Order());
        Assert.All(rules.Rules.Values, rule => Assert.Equal("22", rule.LocalPorts));
        Assert.All(rules.StateAfterEachWrite, state => Assert.Contains(Attacker, state));
    }

    [Fact]
    public async Task An_upgrade_without_port_settings_leaves_the_rules_alone()
    {
        var rules = new WindowsFirewallBatchingTests.FakeRuleStore();
        rules.Rules["WinGuard_Block_0001"] = (WindowsFirewall.ProtocolAny, null, $"{Attacker}/255.255.255.255");
        var store = new Fakes.FakeStore();
        await store.UpsertBanAsync(OldRow(Attacker));
        var settings = new WinGuardSettings { HousekeepingInterval = TimeSpan.FromHours(6) };
        var firewall = new WindowsFirewall(NullLogger<WindowsFirewall>.Instance, rules);
        var engine = new BanEngine(store, firewall, () => settings, NullLogger<BanEngine>.Instance, new Fakes.FakeTimeProvider(T0));

        await engine.StartAsync(CancellationToken.None);
        await engine.HousekeepOnceAsync();
        await engine.StopAsync(CancellationToken.None);

        Assert.Equal(new[] { "WinGuard_Block_0001" }, rules.Rules.Keys);
        Assert.Empty(rules.RemovedNames);
    }

    // ---------- reconcile ----------

    [Fact]
    public async Task The_start_up_sync_puts_every_ban_on_its_own_ports()
    {
        await using var h = await EngineHarness.StartAsync(
            T0,
            Profiles,
            seed: async store =>
            {
                await store.UpsertBanAsync(Scoped("203.0.113.1", "Rdp"));
                await store.UpsertBanAsync(Scoped("203.0.113.2", "MsSql"));
                await store.UpsertBanAsync(Scoped("203.0.113.3", PortProfiles.AllPorts));
            });

        Assert.Equal(RdpPort, h.Firewall.PortsOf("203.0.113.1"));
        Assert.Equal(SqlPort, h.Firewall.PortsOf("203.0.113.2"));
        Assert.Equal(PortSet.All, h.Firewall.PortsOf("203.0.113.3"));
    }

    [Fact]
    public async Task Reconcile_restores_a_missing_rule_on_the_bans_ports()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);

        h.Firewall.Unblock(Attacker);
        await h.Engine.HousekeepOnceAsync();

        Assert.Equal(RdpPort, h.Firewall.PortsOf(Attacker));
    }

    [Fact]
    public async Task Reconcile_moves_a_target_blocked_on_the_wrong_ports()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);

        h.Firewall.Block(Attacker, SqlPort);
        await h.Engine.HousekeepOnceAsync();

        Assert.Equal(RdpPort, h.Firewall.PortsOf(Attacker));
    }

    [Fact]
    public async Task Reconcile_leaves_correct_rules_alone()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);
        await SendThresholdAsync(h, "203.0.113.51", ProtocolSource.MsSql, null);
        var syncs = h.Firewall.SyncRulesCalls.Count;

        await h.Engine.HousekeepOnceAsync();
        await h.Engine.HousekeepOnceAsync();

        Assert.Equal(syncs, h.Firewall.SyncRulesCalls.Count);
    }

    [Fact]
    public async Task Changing_a_profile_rewrites_the_active_bans_of_that_engine()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);
        await SendThresholdAsync(h, "203.0.113.51", ProtocolSource.MsSql, null);

        h.Settings.Rdp.BlockedPorts = ["13389"];
        await h.Engine.HousekeepOnceAsync();

        Assert.Equal(PortSet.Parse(["13389"]), h.Firewall.PortsOf(Attacker));
        Assert.Equal(SqlPort, h.Firewall.PortsOf("203.0.113.51"));
    }

    [Fact]
    public async Task Setting_a_profile_narrows_bans_the_engine_issued_with_none()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);
        Assert.Equal(PortSet.All, h.Firewall.PortsOf(Attacker));

        h.Settings.Rdp.BlockedPorts = ["3389"];
        await h.Engine.HousekeepOnceAsync();

        Assert.Equal(RdpPort, h.Firewall.PortsOf(Attacker));
    }

    [Fact]
    public async Task Clearing_a_profile_widens_its_bans_to_the_global_setting()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);

        h.Settings.Rdp.BlockedPorts = [];
        await h.Engine.HousekeepOnceAsync();

        Assert.Equal(PortSet.All, h.Firewall.PortsOf(Attacker));
    }

    [Fact]
    public async Task Changing_the_global_list_rewrites_the_bans_that_follow_it()
    {
        await using var h = await EngineHarness.StartAsync(T0, s => s.Rdp.BlockedPorts = ["3389"], seed: store => store.UpsertBanAsync(OldRow("203.0.113.9")));
        await SendThresholdAsync(h, ProtocolSource.MsSql);
        await SendThresholdAsync(h, "203.0.113.51", ProtocolSource.Rdp, Rdp4625);

        h.Settings.BlockedPorts = ["22"];
        await h.Engine.HousekeepOnceAsync();

        Assert.Equal(PortSet.Parse(["22"]), h.Firewall.PortsOf("203.0.113.9"));
        Assert.Equal(PortSet.Parse(["22"]), h.Firewall.PortsOf(Attacker));
        Assert.Equal(RdpPort, h.Firewall.PortsOf("203.0.113.51"));
    }

    [Fact]
    public async Task Deleting_a_custom_source_falls_its_bans_back_to_the_global_setting()
    {
        await using var h = await EngineHarness.StartAsync(T0, s => s.CustomSources = [new CustomLogSource { Name = "mail", BlockedPorts = ["25"] }]);
        await SendThresholdAsync(h, ProtocolSource.Custom, "mail");

        h.Settings.CustomSources = [];
        await h.Engine.HousekeepOnceAsync();

        Assert.Equal(PortSet.All, h.Firewall.PortsOf(Attacker));
    }

    [Fact]
    public async Task A_profile_change_leaves_all_ports_bans_alone()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        await h.Engine.BanNowAsync(Attacker, null, permanent: true, note: null);

        h.Settings.Rdp.BlockedPorts = ["13389"];
        await h.Engine.HousekeepOnceAsync();

        Assert.Equal(PortSet.All, h.Firewall.PortsOf(Attacker));
    }

    [Fact]
    public async Task An_unreadable_firewall_is_not_rewritten_because_of_a_profile_change()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);
        var syncs = h.Firewall.SyncRulesCalls.Count;

        h.Settings.Rdp.BlockedPorts = ["13389"];
        h.Firewall.FailListBlocked = true;
        await h.Engine.HousekeepOnceAsync();

        Assert.Equal(syncs, h.Firewall.SyncRulesCalls.Count);
    }

    [Fact]
    public async Task Clearing_bans_on_start_up_leaves_blacklisted_ranges_on_all_ports()
    {
        await using var h = await EngineHarness.StartAsync(
            T0,
            s =>
            {
                s.ClearBansOnStartup = true;
                s.BlockedPorts = ["22"];
            },
            seed: async store =>
            {
                await store.AddToListAsync(ListKind.Blacklist, "198.51.100.0/24");
                await store.UpsertBanAsync(Scoped(Attacker, "Rdp"));
            });

        Assert.Equal(["198.51.100.0/24"], h.Firewall.Blocked);
        Assert.Equal(PortSet.All, h.Firewall.PortsOf("198.51.100.0/24"));
    }

    // ---------- unban, expiry ----------

    [Fact]
    public async Task Unbanning_lifts_a_scoped_ban_from_the_firewall()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);

        await h.Engine.UnbanAsync(Attacker);

        Assert.DoesNotContain(Attacker, h.Firewall.Blocked);
        Assert.Null(await h.Store.GetBanAsync(Attacker));
    }

    [Fact]
    public async Task A_scoped_ban_expires()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);

        h.Time.Advance(TimeSpan.FromHours(25));
        await h.Engine.HousekeepOnceAsync();

        Assert.DoesNotContain(Attacker, h.Firewall.Blocked);
    }

    // ---------- IPv6 aggregate bans ----------

    [Fact]
    public async Task An_aggregate_ban_is_scoped_and_widens_as_one_target()
    {
        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            Profiles(s);
            s.Ipv6AggregatePrefixLength = 64;
        });
        const string Prefix = "2001:db8:1:2::/64";

        await SendThresholdAsync(h, "2001:db8:1:2::1", ProtocolSource.Rdp, Rdp4625);
        Assert.Equal(RdpPort, h.Firewall.PortsOf(Prefix));

        await SendThresholdAsync(h, "2001:db8:1:2::2", ProtocolSource.MsSql, null);

        Assert.Equal(RdpAndSql, h.Firewall.PortsOf(Prefix));
        Assert.Single(await h.Store.GetActiveBansAsync());
    }

    [Fact]
    public async Task An_aggregate_ban_that_comes_to_overlap_the_whitelist_is_lifted_from_its_family()
    {
        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            Profiles(s);
            s.Ipv6AggregatePrefixLength = 64;
        });
        await SendThresholdAsync(h, "2001:db8:1:2::1", ProtocolSource.Rdp, Rdp4625);

        await h.Store.AddToListAsync(ListKind.Whitelist, "2001:db8:1:2::9");
        await h.Engine.HousekeepOnceAsync();

        Assert.Empty(h.Firewall.Blocked);
    }

    // ---------- report-only ----------

    [Fact]
    public async Task Report_only_widens_the_record_and_leaves_the_firewall_alone()
    {
        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            Profiles(s);
            s.ReportOnly = true;
        });

        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);
        await SendThresholdAsync(h, ProtocolSource.MsSql);

        Assert.Empty(h.Firewall.BlockCalls);
        Assert.Empty(h.Firewall.SyncRulesCalls);
        Assert.Equal("1433,3389", PortProfiles.Resolve((await h.Store.GetBanAsync(Attacker))!.PortScope, h.Settings).Text);
        Assert.Contains(h.Store.Events, e => e.Message.Contains("ban widened", StringComparison.Ordinal) && e.Message.Contains("report-only", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Switching_report_only_off_enforces_recorded_bans_on_their_ports()
    {
        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            Profiles(s);
            s.ReportOnly = true;
        });
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);

        h.Settings.ReportOnly = false;
        await h.Engine.HousekeepOnceAsync();

        Assert.Equal(RdpPort, h.Firewall.PortsOf(Attacker));
    }

    [Fact]
    public async Task A_profile_change_in_report_only_mode_touches_no_rule()
    {
        await using var h = await EngineHarness.StartAsync(
            T0,
            s =>
            {
                Profiles(s);
                s.ReportOnly = true;
            },
            seed: store => store.UpsertBanAsync(Scoped(Attacker, "Rdp")));

        h.Settings.Rdp.BlockedPorts = ["13389"];
        await h.Engine.HousekeepOnceAsync();

        Assert.Empty(h.Firewall.SyncRulesCalls);
    }

    // ---------- database failures ----------

    [Fact]
    public async Task A_ban_the_store_refused_is_enforced_on_its_ports_and_stays_there()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);
        h.Store.FailWrites = true;
        await SendThresholdAsync(h, "203.0.113.51", ProtocolSource.MsSql, null);

        await h.Engine.HousekeepOnceAsync();

        Assert.Equal(SqlPort, h.Firewall.PortsOf("203.0.113.51"));
    }

    [Fact]
    public async Task A_ban_the_store_refused_is_saved_with_its_scope_when_it_recovers()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        h.Store.FailWrites = true;
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);
        Assert.Null(await h.Store.GetBanAsync(Attacker));

        h.Store.FailWrites = false;
        await h.Engine.HousekeepOnceAsync();

        Assert.Equal("Rdp", (await h.Store.GetBanAsync(Attacker))!.PortScope);
        Assert.Equal(RdpPort, h.Firewall.PortsOf(Attacker));
    }

    [Fact]
    public async Task A_ban_the_store_refused_can_widen_and_is_saved_widened()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        h.Store.FailWrites = true;
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);

        await SendThresholdAsync(h, ProtocolSource.MsSql);
        Assert.Equal(RdpAndSql, h.Firewall.PortsOf(Attacker));

        await h.Engine.HousekeepOnceAsync();
        Assert.Equal(RdpAndSql, h.Firewall.PortsOf(Attacker));

        h.Store.FailWrites = false;
        await h.Engine.HousekeepOnceAsync();

        Assert.Equal("1433,3389", PortProfiles.Resolve((await h.Store.GetBanAsync(Attacker))!.PortScope, h.Settings).Text);
        Assert.Equal(RdpAndSql, h.Firewall.PortsOf(Attacker));
    }

    [Fact]
    public async Task A_stored_ban_widened_while_the_store_is_down_keeps_the_newer_scope()
    {
        // The row says RDP, the unsaved copy says both: reconcile must go by the newer one.
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);

        h.Store.FailWrites = true;
        await SendThresholdAsync(h, ProtocolSource.MsSql);
        await h.Engine.HousekeepOnceAsync();

        Assert.Equal(RdpAndSql, h.Firewall.PortsOf(Attacker));
    }

    [Fact]
    public async Task An_unsaved_ban_superseded_by_a_saved_one_does_not_overwrite_it_later()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        h.Store.FailWrites = true;
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);

        h.Store.FailWrites = false;
        await h.Engine.BanNowAsync(Attacker, null, permanent: true, note: null);
        await h.Engine.HousekeepOnceAsync();

        var ban = (await h.Store.GetBanAsync(Attacker))!;
        Assert.True(ban.IsPermanent);
        Assert.Equal(PortProfiles.AllPorts, ban.PortScope);
    }

    [Fact]
    public async Task An_unsaved_ban_that_runs_out_is_lifted_from_its_family()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        h.Store.FailWrites = true;
        await SendThresholdAsync(h, ProtocolSource.Rdp, Rdp4625);

        h.Time.Advance(TimeSpan.FromHours(25));
        await h.Engine.HousekeepOnceAsync();

        Assert.DoesNotContain(Attacker, h.Firewall.Blocked);
    }

    // ---------- helpers ----------

    private static BanEntry OldRow(string ip, ProtocolSource source = ProtocolSource.MsSql) => new()
    {
        IpAddress = ip,
        Source = source,
        BannedAtUtc = T0.UtcDateTime,
        ExpiresUtc = T0.UtcDateTime.AddDays(1),
    };

    private static BanEntry Permanent(string ip) => new()
    {
        IpAddress = ip,
        Source = ProtocolSource.MsSql,
        BannedAtUtc = T0.UtcDateTime,
        ExpiresUtc = DateTime.MaxValue,
        IsPermanent = true,
    };

    private static BanEntry Scoped(string ip, string scope) => new()
    {
        IpAddress = ip,
        Source = ProtocolSource.Rdp,
        BannedAtUtc = T0.UtcDateTime,
        ExpiresUtc = T0.UtcDateTime.AddDays(1),
        PortScope = scope,
    };

    private static Task SendThresholdAsync(EngineHarness h, ProtocolSource source, string? detector = null) =>
        SendThresholdAsync(h, Attacker, source, detector);

    private static async Task SendThresholdAsync(EngineHarness h, string ip, ProtocolSource source, string? detector)
    {
        for (var i = 0; i < h.Settings.ThresholdFor(source); i++)
        {
            await h.ProcessAsync(h.Fail(ip, source, detector: detector));
        }
    }
}
