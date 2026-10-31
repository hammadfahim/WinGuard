using System.Runtime.Versioning;
using WinGuard.Core.Firewall;
using WinGuard.Core.Model;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>
/// Checks the rule WinGuard builds against the REAL Windows Firewall COM API. Creating and filling
/// a rule object needs no administrator rights (only registering it does), so these run everywhere
/// Windows does — and they fail if a property is given a value the API rejects.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class FirewallComContractTests
{
    [Fact]
    public void The_api_accepts_the_all_ports_rule_and_it_is_an_inbound_block()
    {
        dynamic rule = ComFirewallRuleStore.BuildRule("WinGuard_Block_Test", WindowsFirewall.ProtocolAny, null, "203.0.113.1,2001:db8::1");

        Assert.Equal(0, (int)rule.Action);      // NET_FW_ACTION_BLOCK (1 would be ALLOW)
        Assert.Equal(1, (int)rule.Direction);   // NET_FW_RULE_DIR_IN
        Assert.True((bool)rule.Enabled);
        Assert.Equal(256, (int)rule.Protocol);  // any
        Assert.Equal("WinGuard_Block_Test", (string)rule.Name);
    }

    [Fact]
    public void The_api_accepts_the_port_restricted_rules()
    {
        dynamic tcp = ComFirewallRuleStore.BuildRule("WinGuard_Block_Test_TCP", WindowsFirewall.ProtocolTcp, "3389,1433", "203.0.113.1");
        dynamic udp = ComFirewallRuleStore.BuildRule("WinGuard_Block_Test_UDP", WindowsFirewall.ProtocolUdp, "3389,1433", "203.0.113.1");

        Assert.Equal("3389,1433", (string)tcp.LocalPorts);
        Assert.Equal(6, (int)tcp.Protocol);
        Assert.Equal(17, (int)udp.Protocol);
        Assert.Equal(0, (int)udp.Action);
    }

    [Fact]
    public void The_api_accepts_a_family_rule_with_the_ports_as_a_port_set_writes_them()
    {
        var ports = PortSet.Parse(["3389", "21", "50000-50100"]);
        var name = $"WinGuard_Block_{ports.RuleFamily}_0001_TCP";

        dynamic rule = ComFirewallRuleStore.BuildRule(name, WindowsFirewall.ProtocolTcp, ports.Text, "203.0.113.1");

        Assert.Equal(name, (string)rule.Name);
        Assert.Equal("21,3389,50000-50100", (string)rule.LocalPorts);
    }

    [Fact]
    public void Ranges_read_back_from_the_api_keep_their_identity()
    {
        // Reconcile compares what it reads with what it wrote: a blocklist entry that came back in
        // another form would look missing on every pass.
        string[] written = ["203.0.113.0/24", "198.51.100.4/31", "1.0.0.0/8", "2001:db8::/32", "2001:db9:1:2::/64", "192.0.2.9", "2001:dba::1"];

        dynamic rule = ComFirewallRuleStore.BuildRule("WinGuard_Block_Test", WindowsFirewall.ProtocolAny, null, string.Join(',', written));

        Assert.Equal(written.Order(), ReadBack(rule));
    }

    [Fact]
    public void The_api_drops_an_entry_a_wider_one_in_the_same_rule_covers()
    {
        // Why blocklist entries must be collapsed before they get here: what Windows leaves out
        // would read back as missing, and reconcile would chase it on every pass.
        dynamic rule = ComFirewallRuleStore.BuildRule("WinGuard_Block_Test", WindowsFirewall.ProtocolAny, null, "198.51.100.5,198.51.100.0/24,198.51.101.0/25");

        Assert.Equal(new[] { "198.51.100.0/24", "198.51.101.0/25" }, ReadBack(rule));
    }

    private static List<string> ReadBack(dynamic rule)
    {
        var parsed = new List<string>();
        foreach (var token in ((string)rule.RemoteAddresses).Split(','))
        {
            Assert.True(WindowsFirewall.TryParseRuleAddress(token, out var normalized), $"could not parse '{token}'");
            parsed.Add(normalized);
        }

        parsed.Sort(StringComparer.Ordinal);
        return parsed;
    }

    [Fact]
    public void Addresses_read_back_from_the_api_are_understood()
    {
        dynamic rule = ComFirewallRuleStore.BuildRule("WinGuard_Block_Test", WindowsFirewall.ProtocolAny, null, "203.0.113.1,198.51.100.7,2001:db8::1");

        var readBack = ((string)rule.RemoteAddresses).Split(',');
        var parsed = new List<string>();
        foreach (var token in readBack)
        {
            Assert.True(WindowsFirewall.TryParseRuleAddress(token, out var normalized), $"could not parse '{token}'");
            parsed.Add(normalized);
        }

        Assert.Equal(new[] { "198.51.100.7", "2001:db8::1", "203.0.113.1" }, parsed.Order());
    }
}
