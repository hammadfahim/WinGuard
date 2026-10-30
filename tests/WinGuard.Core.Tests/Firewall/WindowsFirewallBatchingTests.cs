using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Firewall;
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
        var settings = new WinGuardSettings();
        var store = new FakeRuleStore();
        store.Rules["WinGuard_Block_0001"] = (WindowsFirewall.ProtocolAny, null, "*");
        var firewall = new WindowsFirewall(NullLogger<WindowsFirewall>.Instance, store, 1000, () => settings);
        firewall.SyncRules(["203.0.113.1"]);
        store.Rules["WinGuard_Block_0002"] = (WindowsFirewall.ProtocolAny, null, "*");

        settings.BlockedPorts = ["3389"];
        Assert.Single(firewall.ListBlocked()!);

        Assert.DoesNotContain(store.Rules.Values, rule => rule.Remote.Length == 0);
        Assert.DoesNotContain(store.Rules.Keys, name => name.StartsWith("WinGuard_Block_0002", StringComparison.Ordinal));
    }

    [Fact]
    public void Changing_the_blocked_ports_rewrites_existing_rules()
    {
        var settings = new WinGuardSettings();
        var store = new FakeRuleStore();
        var firewall = new WindowsFirewall(NullLogger<WindowsFirewall>.Instance, store, 1000, () => settings);

        firewall.SyncRules(["203.0.113.1"]);
        Assert.Equal(new[] { "WinGuard_Block_0001" }, store.Rules.Keys);

        settings.BlockedPorts = ["3389", "1433"];
        Assert.Single(firewall.ListBlocked()!);
        Assert.Equal(new[] { "WinGuard_Block_0001_TCP", "WinGuard_Block_0001_UDP" }, store.Rules.Keys.Order());
        Assert.All(store.Rules.Values, rule => Assert.Equal("3389,1433", rule.LocalPorts));

        settings.BlockedPorts = ["3389"];
        firewall.Block("203.0.113.2");
        Assert.All(store.Rules.Values, rule => Assert.Equal("3389", rule.LocalPorts));

        settings.BlockedPorts = [];
        Assert.Equal(2, firewall.ListBlocked()!.Count);
        Assert.Equal(new[] { "WinGuard_Block_0001" }, store.Rules.Keys);
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

    /// <summary>In-memory rule store that reports addresses in the format Windows uses.</summary>
    private sealed class FakeRuleStore : IFirewallRuleStore
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
