using System.Runtime.Versioning;
using WinGuard.Core.Config;

namespace WinGuard.Core.Firewall;

/// <summary>One WinGuard-owned firewall rule as read back from the rule store.</summary>
/// <param name="Name">Rule name (starts with <see cref="Defaults.RuleNamePrefix"/>).</param>
/// <param name="RemoteAddresses">
/// The remote-address list exactly as the store reports it. Windows rewrites what was written:
/// <c>1.2.3.4</c> comes back as <c>1.2.3.4/255.255.255.255</c> and an IPv6 host as <c>a::1-a::1</c>.
/// </param>
internal sealed record FirewallRuleInfo(string Name, string RemoteAddresses);

/// <summary>
/// Minimal storage surface the batching logic in <see cref="WindowsFirewall"/> needs. The production
/// implementation talks to the Windows Firewall COM API; tests use an in-memory fake so the batching
/// and read-back parsing are covered without administrator rights.
/// </summary>
internal interface IFirewallRuleStore
{
    /// <summary>All rules whose name starts with <see cref="Defaults.RuleNamePrefix"/>.</summary>
    IReadOnlyList<FirewallRuleInfo> ReadRules();

    /// <summary>Creates the inbound block rule, or updates its addresses/ports when it already exists.</summary>
    void Upsert(string name, int protocol, string? localPorts, string remoteAddresses);

    /// <summary>Deletes the rule with the given name; a missing rule is not an error.</summary>
    void Remove(string name);
}

/// <summary>
/// <see cref="IFirewallRuleStore"/> over <c>HNetCfg.FwPolicy2</c> / <c>HNetCfg.FWRule</c> through
/// <c>dynamic</c>. No interop assembly, no <c>netsh</c>.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class ComFirewallRuleStore : IFirewallRuleStore
{
    private const string PolicyProgId = "HNetCfg.FwPolicy2";
    private const string RuleProgId = "HNetCfg.FWRule";

    private const int RuleDirectionIn = 1;      // NET_FW_RULE_DIR_IN
    private const int RuleActionBlock = 2;      // NET_FW_ACTION_BLOCK
    private const int ProfileAll = 0x7FFFFFFF;  // NET_FW_PROFILE2_ALL

    private const string RuleDescription = "WinGuard managed block rule (auto-generated - do not edit).";
    private const string RuleGrouping = "WinGuard";

    /// <inheritdoc />
    public IReadOnlyList<FirewallRuleInfo> ReadRules()
    {
        var result = new List<FirewallRuleInfo>();
        dynamic policy = CreatePolicy();
        foreach (dynamic rule in policy.Rules)
        {
            string? name;
            try
            {
                name = (string?)rule.Name;
            }
            catch (Exception)
            {
                continue;
            }

            if (name is null || !name.StartsWith(Defaults.RuleNamePrefix, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            string? remote;
            try
            {
                remote = (string?)rule.RemoteAddresses;
            }
            catch (Exception)
            {
                remote = null;
            }

            result.Add(new FirewallRuleInfo(name, remote ?? string.Empty));
        }

        return result;
    }

    /// <inheritdoc />
    public void Upsert(string name, int protocol, string? localPorts, string remoteAddresses)
    {
        dynamic policy = CreatePolicy();
        dynamic rules = policy.Rules;

        dynamic? existing = null;
        try
        {
            existing = rules.Item(name);
        }
        catch (Exception)
        {
            // Item() throws when no rule has this name.
        }

        if (existing is not null)
        {
            existing.RemoteAddresses = remoteAddresses;
            if (localPorts is not null)
            {
                existing.LocalPorts = localPorts;
            }

            // Self-heal a rule an administrator switched off or turned into an allow rule.
            existing.Action = RuleActionBlock;
            existing.Enabled = true;
            return;
        }

        var type = Type.GetTypeFromProgID(RuleProgId, throwOnError: false)
            ?? throw new PlatformNotSupportedException(
                "The Windows Firewall COM API (HNetCfg.FWRule) is unavailable. This operation requires Windows.");

        dynamic rule = Activator.CreateInstance(type)!;
        rule.Name = name;
        rule.Description = RuleDescription;
        rule.Grouping = RuleGrouping;
        rule.Direction = RuleDirectionIn;
        rule.Action = RuleActionBlock;
        rule.Enabled = true;
        rule.Profiles = ProfileAll;
        rule.Protocol = protocol;
        if (localPorts is not null)
        {
            rule.LocalPorts = localPorts;
        }

        rule.RemoteAddresses = remoteAddresses;
        rules.Add(rule);
    }

    /// <inheritdoc />
    public void Remove(string name)
    {
        dynamic policy = CreatePolicy();
        policy.Rules.Remove(name);
    }

    private static dynamic CreatePolicy()
    {
        var type = Type.GetTypeFromProgID(PolicyProgId, throwOnError: false)
            ?? throw new PlatformNotSupportedException(
                "The Windows Firewall COM API (HNetCfg.FwPolicy2) is unavailable. This operation requires Windows.");
        return Activator.CreateInstance(type)!;
    }
}
