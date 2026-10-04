namespace WinGuard.Core.Engine;

/// <summary>One persisted escalation record.</summary>
internal sealed record OffenseRecord(int Count, DateTime LastUtc);

/// <summary>
/// In-memory per-IP offense counters that drive ban-tier escalation (24h -> 7d -> 30d), plus the
/// time of the last offense used for pruning. Not thread-safe: owned by BanEngine's gate.
/// </summary>
internal sealed class OffenseTracker
{
    private readonly Dictionary<string, int> _counts = new(StringComparer.Ordinal);
    private readonly Dictionary<string, DateTime> _last = new(StringComparer.Ordinal);

    /// <summary>Current offense count for an IP (0 when unknown).</summary>
    public int GetCount(string ip) => _counts.GetValueOrDefault(ip);

    /// <summary>Raises the count to at least <paramref name="count"/> and records the last-offense time.</summary>
    public void Seed(string ip, int count, DateTime lastUtc)
    {
        if (!_counts.TryGetValue(ip, out var existing) || existing < count)
        {
            _counts[ip] = count;
        }

        _last[ip] = lastUtc;
    }

    /// <summary>Sets the count and last-offense time unconditionally.</summary>
    public void Set(string ip, int count, DateTime lastUtc)
    {
        _counts[ip] = count;
        _last[ip] = lastUtc;
    }

    /// <summary>Updates only the last-offense time (e.g. when a ban ends).</summary>
    public void Touch(string ip, DateTime lastUtc) => _last[ip] = lastUtc;

    /// <summary>Forgets an IP entirely.</summary>
    public void Remove(string ip)
    {
        _counts.Remove(ip);
        _last.Remove(ip);
    }

    /// <summary>Forgets everything.</summary>
    public void Clear()
    {
        _counts.Clear();
        _last.Clear();
    }

    /// <summary>Copy for persistence; IPs without a last-offense time get <paramref name="now"/>.</summary>
    public Dictionary<string, OffenseRecord> Snapshot(DateTime now) =>
        _counts.ToDictionary(kv => kv.Key, kv => new OffenseRecord(kv.Value, _last.TryGetValue(kv.Key, out var l) ? l : now));

    /// <summary>Removes IPs that are not in <paramref name="activeIps"/> and whose last offense is older than <paramref name="cutoff"/>.</summary>
    /// <returns>Number of IPs removed.</returns>
    public int PruneStale(HashSet<string> activeIps, DateTime cutoff)
    {
        var stale = _counts.Keys
            .Where(ip => !activeIps.Contains(ip) && (!_last.TryGetValue(ip, out var l) || l < cutoff))
            .ToList();
        foreach (var ip in stale)
        {
            Remove(ip);
        }

        return stale.Count;
    }
}
