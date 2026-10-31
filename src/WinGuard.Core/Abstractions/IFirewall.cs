using WinGuard.Core.Model;

namespace WinGuard.Core.Abstractions;

/// <summary>A ban target and the local ports its block applies to.</summary>
public sealed record FirewallTarget(string Address, PortSet Ports);

/// <summary>
/// A target read back from the firewall. Rules are told apart by <see cref="PortSet.RuleFamily"/>,
/// which is what their names keep; the ports themselves are not read back.
/// </summary>
public sealed record BlockedTarget(string Address, string RuleFamily)
{
    /// <summary>
    /// The family of a TCP/UDP rule pair written before families existed. What it covers is unknown,
    /// and no <see cref="PortSet"/> has this family, so a sync moves its addresses to where they belong.
    /// </summary>
    public const string OlderRuleFamily = "older";
}

/// <summary>
/// Firewall abstraction. MVP implementation is the Windows Firewall COM API
/// (INetFwPolicy2) with batched WinGuard_Block_* rules. All operations must be
/// idempotent: blocking an already-blocked IP is a no-op; unblocking a missing
/// IP does not throw. Implementations must validate IPs before touching rules
/// (never pass raw log text to the firewall API).
/// </summary>
public interface IFirewall
{
    /// <summary>
    /// Adds a ban target to a batch block rule on all ports (creating the next rule when full). A
    /// target is either a single host IP (normalized) or a canonical CIDR range such as
    /// <c>2001:db8:1:2::/64</c> (IPv6 aggregate bans, blacklisted subnets). Anything else is
    /// rejected — including firewall tokens like <c>LocalSubnet</c>.
    /// </summary>
    void Block(string ipOrRange);

    /// <summary>
    /// Like <see cref="Block(string)"/> for the given ports. A target held for other ports moves:
    /// it is added to the new rule before it leaves the old one, so a ban widens without a gap.
    /// </summary>
    void Block(string ipOrRange, PortSet ports);

    /// <summary>Removes the target from whichever batch rule holds it, whatever its ports.</summary>
    void Unblock(string ipOrRange);

    /// <summary>Like <see cref="SyncRules(IEnumerable{FirewallTarget})"/> with every target on all ports.</summary>
    void SyncRules(IEnumerable<string> targets);

    /// <summary>
    /// Makes the WinGuard_* batch rules hold exactly the given targets (active bans, blacklisted
    /// ranges and blocklist entries) for their ports and nothing else (startup reconcile /
    /// self-heal). One call however many targets differ; a target that is wanted and already
    /// blocked stays blocked throughout, also when its ports change.
    /// </summary>
    void SyncRules(IEnumerable<FirewallTarget> targets);

    /// <summary>
    /// All targets currently present in WinGuard_* block rules, or <see langword="null"/> when the
    /// rules could not be read. That is not the same as empty: nothing is known about them.
    /// </summary>
    IReadOnlyList<string>? ListBlocked();

    /// <summary>Like <see cref="ListBlocked"/>, with the rule family holding each target.</summary>
    IReadOnlyList<BlockedTarget>? ListBlockedTargets();

    /// <summary>Delete every WinGuard_* rule.</summary>
    void ClearAll();

    /// <summary>True when the Windows Defender Firewall service is running (rules only take effect when it is).</summary>
    bool IsServiceRunning();
}
