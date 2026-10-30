using WinGuard.Core.Model;

namespace WinGuard.Core.Engine;

/// <summary>
/// In-memory stand-in for the failed_logins table, used only while the store rejects writes, so a
/// database problem (locked, disk full) does not stop attackers from being counted and blocked.
/// Not thread-safe: owned by BanEngine's gate.
/// </summary>
internal sealed class FallbackFailureCounter
{
    // A flood of distinct addresses during a long outage must not grow memory without limit.
    private const int MaxTrackedIps = 100_000;

    private readonly Dictionary<string, List<(ProtocolSource Source, DateTime TimestampUtc)>> _recent = new(StringComparer.Ordinal);

    /// <summary>Failures held here for this IP and source since <paramref name="sinceUtc"/>.</summary>
    public int Count(string ip, ProtocolSource source, DateTime sinceUtc) =>
        _recent.TryGetValue(ip, out var failures)
            ? failures.Count(failure => failure.Source == source && failure.TimestampUtc >= sinceUtc)
            : 0;

    /// <summary>Failures held here for this IP from any source since <paramref name="sinceUtc"/>.</summary>
    public int Count(string ip, DateTime sinceUtc) =>
        _recent.TryGetValue(ip, out var failures)
            ? failures.Count(failure => failure.TimestampUtc >= sinceUtc)
            : 0;

    /// <summary>Records one failure the store refused.</summary>
    public void Record(string ip, ProtocolSource source, DateTime timestampUtc)
    {
        if (!_recent.TryGetValue(ip, out var failures))
        {
            if (_recent.Count >= MaxTrackedIps)
            {
                _recent.Clear();
            }

            failures = [];
            _recent[ip] = failures;
        }

        failures.Add((source, timestampUtc));
    }

    /// <summary>Forgets an IP (it was banned or unbanned).</summary>
    public void Remove(string ip) => _recent.Remove(ip);

    /// <summary>Drops failures older than <paramref name="olderThanUtc"/>.</summary>
    public void Trim(DateTime olderThanUtc)
    {
        foreach (var ip in _recent.Keys.ToList())
        {
            var failures = _recent[ip];
            failures.RemoveAll(failure => failure.TimestampUtc < olderThanUtc);
            if (failures.Count == 0)
            {
                _recent.Remove(ip);
            }
        }
    }
}
