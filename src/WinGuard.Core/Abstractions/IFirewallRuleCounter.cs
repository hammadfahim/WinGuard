namespace WinGuard.Core.Abstractions;

/// <summary>
/// Optional side of an <see cref="IFirewall"/> that knows its rule count without asking Windows.
/// Enumerating the firewall is slow, so metrics take what is already known or nothing.
/// </summary>
public interface IFirewallRuleCounter
{
    /// <summary>WinGuard rules as of the last read or write; null when nothing is cached.</summary>
    int? CachedRuleCount { get; }
}
