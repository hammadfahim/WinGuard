using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging.Abstractions;
using WinGuard.Core.Abstractions;
using WinGuard.Core.Firewall;
using WinGuard.Core.Model;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>
/// Batching logic of <see cref="WindowsFirewall"/> against an in-memory rule store that returns
/// remote addresses the way Windows does (<c>1.2.3.4/255.255.255.255</c>, <c>a::1-a::1</c>), so the
/// read-back path is covered without administrator rights.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsFirewallBatchingTests
{
    [Theory]
    [InlineData("203.0.113.250/255.255.255.255", "203.0.113.250")]
    [InlineData("203.0.113.250/32", "203.0.113.250")]
    [InlineData("203.0.113.250", "203.0.113.250")]
    [InlineData("2001:db8::1-2001:db8::1", "2001:db8::1")]
    [InlineData("2001:db8::1/128", "2001:db8::1")]
    public void Rule_addresses_are_parsed_in_the_form_Windows_reports(string token, string expected)
    {
        Assert.True(WindowsFirewall.TryParseRuleAddress(token, out var normalized));
        Assert.Equal(expected, normalized);
    }

    [Theory]
    [InlineData("10.0.0.1-10.0.0.9")]
    [InlineData("LocalSubnet")]
    [InlineData("*")]
    [InlineData("")]
    public void Multi_address_ranges_and_keywords_are_rejected(string token)
    {
        Assert.False(WindowsFirewall.TryParseRuleAddress(token, out _));
    }

    [Theory]
    [InlineData("10.0.0.0/255.0.0.0", "10.0.0.0/8")]
    [InlineData("10.0.0.0/8", "10.0.0.0/8")]
    [InlineData("203.0.113.0/255.255.255.0", "203.0.113.0/24")]
    [InlineData("2001:db8:1:2::/64", "2001:db8:1:2::/64")]
    [InlineData("2001:db8::/32", "2001:db8::/32")]
    public void Real_subnets_are_canonicalized_to_prefix_form(string token, string expected)
    {
        // WinGuard writes subnets itself (IPv6 aggregate bans, blacklisted ranges); Windows
        // reports them back with either a prefix or a dotted netmask.
        Assert.True(WindowsFirewall.TryParseRuleAddress(token, out var normalized));
        Assert.Equal(expected, normalized);
    }

    [Fact]
    public void Blocked_addresses_survive_a_fresh_read_of_the_firewall()
    {
        var store = new FakeRuleStore();
        var firewall = Create(store);

        firewall.Block("203.0.113.1");
        firewall.Block("203.0.113.2");
        firewall.Block("2001:db8::7");

        // A second instance has no cache: everything it knows comes from reading the rules back.
        var fresh = Create(store);
        Assert.Equal(new[] { "2001:db8::7", "203.0.113.1", "203.0.113.2" }, fresh.ListBlocked()!.Order());

        // Blocking through the fresh instance must add to the rule, not replace its content.
        fresh.Block("203.0.113.3");
        Assert.Equal(4, Create(store).ListBlocked()!.Count);
        Assert.Single(store.Rules);
    }

    [Fact]
    public void Listing_does_not_rewrite_rules_that_are_already_correct()
    {
        var store = new FakeRuleStore();
        var firewall = Create(store);
        firewall.Block("203.0.113.1");
        firewall.Block("203.0.113.2");
        var writes = store.UpsertCount;

        for (var i = 0; i < 5; i++)
        {
            Assert.Equal(2, firewall.ListBlocked()!.Count);
            firewall.Block("203.0.113.1");
        }

        Assert.Equal(writes, store.UpsertCount);
    }

    [Fact]
    public void Unblock_removes_one_address_and_deletes_the_rule_when_it_empties()
    {
        var store = new FakeRuleStore();
        var firewall = Create(store);
        firewall.Block("203.0.113.1");
        firewall.Block("203.0.113.2");

        firewall.Unblock("203.0.113.1");
        Assert.Equal(new[] { "203.0.113.2" }, firewall.ListBlocked()!);

        firewall.Unblock("203.0.113.2");
        Assert.Empty(firewall.ListBlocked()!);
        Assert.Empty(store.Rules);

        // The emptied batch is gone; a later block creates a fresh rule.
        firewall.Block("203.0.113.9");
        Assert.Equal(new[] { "203.0.113.9" }, Create(store).ListBlocked()!);
    }

    [Fact]
    public void A_full_rule_spills_into_the_next_one()
    {
        var store = new FakeRuleStore();
        var firewall = Create(store, maxPerRule: 2);

        foreach (var ip in new[] { "203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4", "203.0.113.5" })
        {
            firewall.Block(ip);
        }

        Assert.Equal(new[] { "WinGuard_Block_0001", "WinGuard_Block_0002", "WinGuard_Block_0003" }, store.Rules.Keys.Order());
        Assert.Equal(5, Create(store, maxPerRule: 2).ListBlocked()!.Count);
    }

    [Fact]
    public void Sync_writes_the_wanted_rules_and_removes_leftovers_without_clearing_first()
    {
        var store = new FakeRuleStore();
        var firewall = Create(store, maxPerRule: 2);
        foreach (var ip in new[] { "203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4", "203.0.113.5" })
        {
            firewall.Block(ip);
        }

        store.RemovedNames.Clear();
        Create(store, maxPerRule: 2).SyncRules(["203.0.113.1", "198.51.100.7"]);

        Assert.Equal(new[] { "198.51.100.7", "203.0.113.1" }, Create(store).ListBlocked()!.Order());
        Assert.Equal(new[] { "WinGuard_Block_0001" }, store.Rules.Keys);

        // The rule that stays in use is updated in place, never deleted and recreated.
        Assert.DoesNotContain("WinGuard_Block_0001", store.RemovedNames);
    }

    [Fact]
    public void Sync_holds_bans_and_ranges_and_refuses_anything_else()
    {
        var store = new FakeRuleStore();

        Create(store).SyncRules(["203.0.113.1", "198.51.100.0/24", "LocalSubnet", "203.0.113.1", "not an address"]);

        Assert.Equal(new[] { "198.51.100.0/24", "203.0.113.1" }, Create(store).ListBlocked()!.Order());
    }

    [Fact]
    public void Sync_keeps_every_address_in_the_rule_that_holds_it()
    {
        // Moving an address from a rule written early to one written late would leave it
        // unenforced in between, here: the range in rule 1 while the bans change around it.
        var store = new FakeRuleStore();
        var firewall = Create(store, maxPerRule: 2);
        firewall.Block("198.51.100.0/24");
        firewall.Block("203.0.113.1");
        firewall.Block("203.0.113.2");
        firewall.Block("203.0.113.3");
        var rangeRule = store.Rules.Single(rule => rule.Value.Remote.Contains("198.51.100.0")).Key;

        store.StateAfterEachWrite.Clear();
        Create(store, maxPerRule: 2).SyncRules(["203.0.113.2", "203.0.113.4", "203.0.113.5", "203.0.113.6", "198.51.100.0/24"]);

        Assert.Contains("198.51.100.0", store.Rules[rangeRule].Remote);
        Assert.NotEmpty(store.StateAfterEachWrite);
        Assert.All(store.StateAfterEachWrite, state =>
        {
            Assert.Contains("198.51.100.0", state);
            Assert.Contains("203.0.113.2", state);
        });
        Assert.Equal(
            new[] { "198.51.100.0/24", "203.0.113.2", "203.0.113.4", "203.0.113.5", "203.0.113.6" },
            Create(store).ListBlocked()!.Order());
    }

    [Fact]
    public void Sync_with_a_lowered_rule_size_never_drops_an_address_on_the_way()
    {
        var store = new FakeRuleStore();
        var firewall = Create(store, maxPerRule: 4);
        foreach (var ip in new[] { "203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4" })
        {
            firewall.Block(ip);
        }

        store.StateAfterEachWrite.Clear();
        Create(store, maxPerRule: 2).SyncRules(["203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"]);

        Assert.Equal(2, store.Rules.Count);
        Assert.All(store.StateAfterEachWrite, state => Assert.Contains("203.0.113.4", state));
    }

    [Fact]
    public void A_failed_read_is_reported_as_unknown_not_as_no_rules()
    {
        var store = new FakeRuleStore();
        var firewall = Create(store);
        firewall.Block("203.0.113.1");

        store.FailReads = true;
        Assert.Null(firewall.ListBlocked());

        store.FailReads = false;
        Assert.Equal(new[] { "203.0.113.1" }, firewall.ListBlocked());
    }

    [Fact]
    public void Clearing_still_reports_a_firewall_it_could_not_read()
    {
        var store = new FakeRuleStore { FailReads = true };

        Assert.False(Create(store).TryClearAll(out var error));
        Assert.NotNull(error);
    }

    [Fact]
    public void A_rule_with_no_readable_address_is_never_rewritten_as_applying_to_everyone()
    {
        // An empty RemoteAddresses means "any": rewriting such a rule would block the whole internet.
        var store = new FakeRuleStore();
        store.Rules["WinGuard_Block_0001"] = (WindowsFirewall.ProtocolAny, null, "*");
        var firewall = Create(store);
        firewall.SyncRules(["203.0.113.1"]);
        store.Rules["WinGuard_Block_0002"] = (WindowsFirewall.ProtocolAny, null, "*");

        firewall.SyncRules([new FirewallTarget("203.0.113.1", PortSet.Parse(["3389"]))]);
        Assert.Single(firewall.ListBlocked()!);

        Assert.DoesNotContain(store.Rules.Values, rule => rule.Remote.Length == 0);
        Assert.DoesNotContain(store.Rules.Keys, name => name.StartsWith("WinGuard_Block_0002", StringComparison.Ordinal));
    }

    [Fact]
    public void Changing_the_ports_of_a_target_rewrites_existing_rules()
    {
        var store = new FakeRuleStore();
        var firewall = Create(store);

        firewall.SyncRules(["203.0.113.1"]);
        Assert.Equal(new[] { "WinGuard_Block_0001" }, store.Rules.Keys);

        var two = PortSet.Parse(["3389", "1433"]);
        firewall.SyncRules([new FirewallTarget("203.0.113.1", two)]);
        Assert.Single(firewall.ListBlocked()!);
        Assert.Equal(new[] { FamilyRule(two, "TCP"), FamilyRule(two, "UDP") }, store.Rules.Keys.Order());
        Assert.All(store.Rules.Values, rule => Assert.Equal("1433,3389", rule.LocalPorts));

        var one = PortSet.Parse(["3389"]);
        firewall.SyncRules([new FirewallTarget("203.0.113.1", one), new FirewallTarget("203.0.113.2", one)]);
        Assert.All(store.Rules.Values, rule => Assert.Equal("3389", rule.LocalPorts));

        firewall.SyncRules(["203.0.113.1", "203.0.113.2"]);
        Assert.Equal(2, firewall.ListBlocked()!.Count);
        Assert.Equal(new[] { "WinGuard_Block_0001" }, store.Rules.Keys);
    }

    // ---------- rule families ----------

    [Fact]
    public void All_ports_keep_the_rule_name_and_shape_of_every_earlier_version()
    {
        var store = new FakeRuleStore();

        Create(store).Block("203.0.113.1", PortSet.All);

        var rule = Assert.Single(store.Rules);
        Assert.Equal("WinGuard_Block_0001", rule.Key);
        Assert.Equal(WindowsFirewall.ProtocolAny, rule.Value.Protocol);
        Assert.Null(rule.Value.LocalPorts);
    }

    [Fact]
    public void Ports_get_a_tcp_and_udp_rule_pair_named_after_the_set()
    {
        var store = new FakeRuleStore();
        var rdp = PortSet.Parse(["3389"]);

        Create(store).Block("203.0.113.1", rdp);

        Assert.Equal(new[] { FamilyRule(rdp, "TCP"), FamilyRule(rdp, "UDP") }, store.Rules.Keys.Order());
        Assert.StartsWith("WinGuard_Block_", FamilyRule(rdp, "TCP"), StringComparison.Ordinal);
        Assert.Equal(WindowsFirewall.ProtocolTcp, store.Rules[FamilyRule(rdp, "TCP")].Protocol);
        Assert.Equal(WindowsFirewall.ProtocolUdp, store.Rules[FamilyRule(rdp, "UDP")].Protocol);
        Assert.All(store.Rules.Values, rule => Assert.Equal("3389", rule.LocalPorts));
    }

    [Fact]
    public void Targets_with_the_same_ports_share_a_rule_however_the_ports_were_written()
    {
        var store = new FakeRuleStore();
        var firewall = Create(store);

        firewall.Block("203.0.113.1", PortSet.Parse(["3389", "1433"]));
        firewall.Block("203.0.113.2", PortSet.Parse(["1433", "3389", "1433"]));

        Assert.Equal(2, store.Rules.Count);
        Assert.All(store.Rules.Values, rule => Assert.Contains("203.0.113.2", rule.Remote));
    }

    [Fact]
    public void The_rule_count_follows_the_port_sets_not_the_targets()
    {
        var store = new FakeRuleStore();
        var rdp = PortSet.Parse(["3389"]);
        var sql = PortSet.Parse(["1433"]);
        var targets = Enumerable.Range(1, 200)
            .Select(i => new FirewallTarget($"203.0.113.{i}", i % 2 == 0 ? rdp : sql))
            .Concat(Enumerable.Range(1, 200).Select(i => new FirewallTarget($"198.51.100.{i}", PortSet.All)))
            .ToList();

        Create(store).SyncRules(targets);

        Assert.Equal(5, store.Rules.Count); // one all-ports rule, two pairs
        Assert.Equal(400, Create(store).ListBlocked()!.Count);
    }

    [Fact]
    public void A_full_family_spills_into_its_next_rule_without_touching_other_families()
    {
        var store = new FakeRuleStore();
        var rdp = PortSet.Parse(["3389"]);
        var firewall = Create(store, maxPerRule: 1);

        firewall.Block("203.0.113.1", rdp);
        firewall.Block("203.0.113.2", rdp);
        firewall.Block("203.0.113.3", PortSet.All);

        Assert.Equal(5, store.Rules.Count);
        Assert.Contains(FamilyRule(rdp, "TCP", index: 2), store.Rules.Keys);
        Assert.Contains("WinGuard_Block_0001", store.Rules.Keys);
    }

    [Fact]
    public void A_fresh_process_knows_which_family_holds_what()
    {
        var store = new FakeRuleStore();
        var rdp = PortSet.Parse(["3389"]);
        var firewall = Create(store);
        firewall.Block("203.0.113.1", rdp);
        firewall.Block("203.0.113.2");

        var targets = Create(store).ListBlockedTargets()!;

        Assert.Contains(new BlockedTarget("203.0.113.1", rdp.RuleFamily), targets);
        Assert.Contains(new BlockedTarget("203.0.113.2", string.Empty), targets);
        Assert.Equal(2, targets.Count);
    }

    [Fact]
    public void Blocking_for_other_ports_moves_a_target_without_a_gap()
    {
        var store = new FakeRuleStore();
        var firewall = Create(store);
        var rdp = PortSet.Parse(["3389"]);
        var both = PortSet.Parse(["3389", "1433"]);
        firewall.Block("203.0.113.1", rdp);
        firewall.Block("203.0.113.2", rdp);

        store.StateAfterEachWrite.Clear();
        firewall.Block("203.0.113.1", both);

        Assert.NotEmpty(store.StateAfterEachWrite);
        Assert.All(store.StateAfterEachWrite, state => Assert.Contains("203.0.113.1", state));
        Assert.Contains(new BlockedTarget("203.0.113.1", both.RuleFamily), firewall.ListBlockedTargets()!);
        Assert.DoesNotContain(new BlockedTarget("203.0.113.1", rdp.RuleFamily), firewall.ListBlockedTargets()!);
        Assert.Contains("203.0.113.2", store.Rules[FamilyRule(rdp, "TCP")].Remote);
    }

    [Fact]
    public void A_move_keeps_the_ports_of_the_rule_it_leaves()
    {
        // A fresh process knows a family by name only, so the rule it shrinks must keep its LocalPorts.
        var store = new FakeRuleStore();
        var rdp = PortSet.Parse(["3389"]);
        var firewall = Create(store);
        firewall.Block("203.0.113.1", rdp);
        firewall.Block("203.0.113.2", rdp);

        Create(store).Block("203.0.113.1");

        Assert.Equal("3389", store.Rules[FamilyRule(rdp, "TCP")].LocalPorts);
        Assert.Equal("3389", store.Rules[FamilyRule(rdp, "UDP")].LocalPorts);
        Assert.DoesNotContain("203.0.113.1", store.Rules[FamilyRule(rdp, "UDP")].Remote);
    }

    [Fact]
    public void Blocking_again_for_the_same_ports_writes_nothing()
    {
        var store = new FakeRuleStore();
        var firewall = Create(store);
        var rdp = PortSet.Parse(["3389"]);
        firewall.Block("203.0.113.1", rdp);
        var writes = store.UpsertCount;

        firewall.Block("203.0.113.1", rdp);

        Assert.Equal(writes, store.UpsertCount);
    }

    [Fact]
    public void Unblock_finds_a_target_in_any_family()
    {
        var store = new FakeRuleStore();
        var firewall = Create(store);
        firewall.Block("203.0.113.1", PortSet.Parse(["3389"]));

        Create(store).Unblock("203.0.113.1");

        Assert.Empty(store.Rules);
    }

    [Fact]
    public void Unblock_clears_a_target_left_in_two_families_by_an_interrupted_move()
    {
        var store = new FakeRuleStore();
        var firewall = Create(store);
        var rdp = PortSet.Parse(["3389"]);
        firewall.Block("203.0.113.1", rdp);
        firewall.Block("203.0.113.2", rdp);
        store.Rules["WinGuard_Block_0001"] = (WindowsFirewall.ProtocolAny, null, "203.0.113.1/255.255.255.255");

        Create(store).Unblock("203.0.113.1");

        Assert.Equal(new[] { "203.0.113.2" }, Create(store).ListBlocked()!);
    }

    [Fact]
    public void Sync_moves_targets_between_families_gaining_rules_first()
    {
        var store = new FakeRuleStore();
        var firewall = Create(store);
        var rdp = PortSet.Parse(["3389"]);
        firewall.Block("203.0.113.1");
        firewall.Block("203.0.113.2");

        store.StateAfterEachWrite.Clear();
        store.RemovedNames.Clear();
        Create(store).SyncRules([new FirewallTarget("203.0.113.1", rdp), new FirewallTarget("203.0.113.2", PortSet.All)]);

        Assert.All(store.StateAfterEachWrite, state => Assert.Contains("203.0.113.1", state));
        Assert.Contains(new BlockedTarget("203.0.113.1", rdp.RuleFamily), firewall.ListBlockedTargets()!);
        Assert.Contains(new BlockedTarget("203.0.113.2", string.Empty), firewall.ListBlockedTargets()!);
    }

    [Fact]
    public void Sync_gives_a_target_named_twice_the_wider_block()
    {
        var store = new FakeRuleStore();
        var rdp = PortSet.Parse(["3389"]);

        Create(store).SyncRules([new FirewallTarget("203.0.113.1", rdp), new FirewallTarget("203.0.113.1", PortSet.All)]);

        Assert.Equal(new[] { "WinGuard_Block_0001" }, store.Rules.Keys);
    }

    [Fact]
    public void Sync_removes_a_family_nothing_uses_any_more()
    {
        var store = new FakeRuleStore();
        var firewall = Create(store);
        firewall.Block("203.0.113.1", PortSet.Parse(["3389"]));
        firewall.Block("203.0.113.2");

        firewall.SyncRules(["203.0.113.2"]);

        Assert.Equal(new[] { "WinGuard_Block_0001" }, store.Rules.Keys);
    }

    [Fact]
    public void After_the_first_sync_only_rules_that_changed_are_written()
    {
        // A blocklist can fill fifty rules: one new ban must not rewrite them all under the engine's gate.
        var store = new FakeRuleStore();
        var firewall = Create(store, maxPerRule: 2);
        var targets = Enumerable.Range(1, 6).Select(i => $"203.0.113.{i}").ToList();
        firewall.SyncRules(targets);
        var writes = store.UpsertCount;

        firewall.SyncRules([.. targets, "203.0.113.7"]);

        Assert.Equal(writes + 1, store.UpsertCount);
        Assert.Equal(4, store.Rules.Count);
    }

    [Fact]
    public void The_first_sync_of_a_process_writes_every_rule_so_a_disabled_one_comes_back()
    {
        var store = new FakeRuleStore();
        Create(store).SyncRules(["203.0.113.1"]);
        var writes = store.UpsertCount;

        Create(store).SyncRules(["203.0.113.1"]);

        Assert.Equal(writes + 1, store.UpsertCount);
    }

    [Fact]
    public void A_rule_pair_from_an_older_version_is_reported_as_such_and_moved_by_a_sync()
    {
        var store = new FakeRuleStore();
        store.Rules["WinGuard_Block_0001_TCP"] = (WindowsFirewall.ProtocolTcp, "3389", "203.0.113.1/255.255.255.255");
        store.Rules["WinGuard_Block_0001_UDP"] = (WindowsFirewall.ProtocolUdp, "3389", "203.0.113.1/255.255.255.255");
        var firewall = Create(store);
        var rdp = PortSet.Parse(["3389"]);

        Assert.Equal(new BlockedTarget("203.0.113.1", BlockedTarget.OlderRuleFamily), Assert.Single(firewall.ListBlockedTargets()!));

        store.StateAfterEachWrite.Clear();
        firewall.SyncRules([new FirewallTarget("203.0.113.1", rdp)]);

        Assert.Equal(new[] { FamilyRule(rdp, "TCP"), FamilyRule(rdp, "UDP") }, store.Rules.Keys.Order());
        Assert.All(store.StateAfterEachWrite, state => Assert.Contains("203.0.113.1", state));
        Assert.Equal(new BlockedTarget("203.0.113.1", rdp.RuleFamily), Assert.Single(firewall.ListBlockedTargets()!));
    }

    [Fact]
    public void An_older_rule_pair_becomes_all_ports_when_that_is_what_is_wanted()
    {
        var store = new FakeRuleStore();
        store.Rules["WinGuard_Block_0001_TCP"] = (WindowsFirewall.ProtocolTcp, "3389", "203.0.113.1/255.255.255.255");
        store.Rules["WinGuard_Block_0001_UDP"] = (WindowsFirewall.ProtocolUdp, "3389", "203.0.113.1/255.255.255.255");

        Create(store).SyncRules(["203.0.113.1"]);

        var rule = Assert.Single(store.Rules);
        Assert.Equal(WindowsFirewall.ProtocolAny, rule.Value.Protocol);
    }

    [Fact]
    public void Nothing_is_added_to_an_older_rule_pair()
    {
        // What it covers is unknown, so an all-ports target added to it could end up covering less.
        var store = new FakeRuleStore();
        store.Rules["WinGuard_Block_0001_TCP"] = (WindowsFirewall.ProtocolTcp, "3389", "203.0.113.1/255.255.255.255");

        Create(store).Block("203.0.113.2");

        Assert.DoesNotContain("203.0.113.2", store.Rules["WinGuard_Block_0001_TCP"].Remote);
        Assert.Contains("203.0.113.1", store.Rules["WinGuard_Block_0001_TCP"].Remote);
        Assert.Contains("203.0.113.2", store.Rules["WinGuard_Block_0002"].Remote);
    }

    [Fact]
    public void A_rule_named_like_a_family_but_not_one_is_left_alone()
    {
        var store = new FakeRuleStore();
        store.Rules["WinGuard_Block_Something_0001"] = (WindowsFirewall.ProtocolAny, null, "203.0.113.1/255.255.255.255");

        Assert.Empty(Create(store).ListBlocked()!);
    }

    [Fact]
    public void Clear_all_removes_every_family()
    {
        var store = new FakeRuleStore();
        var firewall = Create(store);
        firewall.Block("203.0.113.1", PortSet.Parse(["3389"]));
        firewall.Block("203.0.113.2", PortSet.Parse(["1433"]));
        firewall.Block("203.0.113.3");

        Assert.True(firewall.TryClearAll(out var error));
        Assert.Null(error);
        Assert.Empty(store.Rules);
    }

    [Fact]
    public void Clear_all_removes_every_rule()
    {
        var store = new FakeRuleStore();
        var firewall = Create(store);
        firewall.Block("203.0.113.1");

        Assert.True(firewall.TryClearAll(out var error));
        Assert.Null(error);
        Assert.Empty(store.Rules);
        Assert.Empty(firewall.ListBlocked()!);
    }

    private static WindowsFirewall Create(FakeRuleStore store, int maxPerRule = 1000) =>
        new(NullLogger<WindowsFirewall>.Instance, store, maxPerRule);

    private static string FamilyRule(PortSet ports, string kind, int index = 1) =>
        $"WinGuard_Block_{ports.RuleFamily}_{index:D4}_{kind}";

    /// <summary>In-memory rule store that reports addresses in the format Windows uses.</summary>
    internal sealed class FakeRuleStore : IFirewallRuleStore
    {
        public Dictionary<string, (int Protocol, string? LocalPorts, string Remote)> Rules { get; } = new(StringComparer.OrdinalIgnoreCase);

        public List<string> RemovedNames { get; } = [];

        public int UpsertCount { get; private set; }

        /// <summary>When true, reading fails the way it does with the firewall service stopped.</summary>
        public bool FailReads { get; set; }

        /// <summary>Every rule's remote addresses after each write, to see what a write sequence exposes.</summary>
        public List<string> StateAfterEachWrite { get; } = [];

        public IReadOnlyList<FirewallRuleInfo> ReadRules() => FailReads
            ? throw new InvalidOperationException("The RPC server is unavailable.")
            : Rules.Select(pair => new FirewallRuleInfo(pair.Key, pair.Value.Remote)).ToList();

        public void Upsert(string name, int protocol, string? localPorts, string remoteAddresses)
        {
            UpsertCount++;
            var ports = localPorts ?? (Rules.TryGetValue(name, out var existing) ? existing.LocalPorts : null);
            Rules[name] = (protocol, ports, AsWindowsReportsIt(remoteAddresses));
            StateAfterEachWrite.Add(string.Join(",", Rules.Values.Select(rule => rule.Remote)));
        }

        public void Remove(string name)
        {
            RemovedNames.Add(name);
            Rules.Remove(name);
        }

        private static string AsWindowsReportsIt(string csv) =>
            string.Join(",", csv.Split(',', StringSplitOptions.RemoveEmptyEntries).Select(address =>
                address.Contains('/')
                    ? address
                    : IPAddress.Parse(address).AddressFamily == AddressFamily.InterNetwork
                        ? $"{address}/255.255.255.255"
                        : $"{address}-{address}"));
    }
}
