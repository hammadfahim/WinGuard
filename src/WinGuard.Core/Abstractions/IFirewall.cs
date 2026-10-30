namespace WinGuard.Core.Abstractions;

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
    /// Adds a ban target to a batch block rule (creating the next rule when full). A target is
    /// either a single host IP (normalized) or a canonical CIDR range such as
    /// <c>2001:db8:1:2::/64</c> (IPv6 aggregate bans, blacklisted subnets). Anything else is
    /// rejected — including firewall tokens like <c>LocalSubnet</c>.
    /// </summary>
    void Block(string ipOrRange);

    /// <summary>Removes the target from whichever batch rule holds it.</summary>
    void Unblock(string ipOrRange);

    /// <summary>
    /// Makes the WinGuard_* batch rules hold exactly the given targets (active bans and blacklisted
    /// ranges) and nothing else (startup reconcile / self-heal). One call however many targets
    /// differ; a target that is wanted and already blocked stays blocked throughout.
    /// </summary>
    void SyncRules(IEnumerable<string> targets);

    /// <summary>
    /// All targets currently present in WinGuard_* block rules, or <see langword="null"/> when the
    /// rules could not be read. That is not the same as empty: nothing is known about them.
    /// </summary>
    IReadOnlyList<string>? ListBlocked();

    /// <summary>Delete every WinGuard_* rule.</summary>
    void ClearAll();

    /// <summary>True when the Windows Defender Firewall service is running (rules only take effect when it is).</summary>
    bool IsServiceRunning();
}
