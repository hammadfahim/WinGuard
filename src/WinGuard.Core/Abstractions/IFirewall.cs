using WinGuard.Core.Model;

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

    /// <summary>Rebuild all WinGuard_* batch rules from the given active bans (startup reconcile / self-heal).</summary>
    void SyncRules(IEnumerable<BanEntry> activeBans);

    /// <summary>All IPs currently present in WinGuard_* block rules.</summary>
    IReadOnlyList<string> ListBlocked();

    /// <summary>Delete every WinGuard_* rule.</summary>
    void ClearAll();

    /// <summary>True when the Windows Defender Firewall service is running (rules only take effect when it is).</summary>
    bool IsServiceRunning();
}
