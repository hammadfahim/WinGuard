using WinGuard.Core.Model;

namespace WinGuard.Core.Engine;

/// <summary>
/// In-memory per-IP offense counters that drive ban-tier escalation (24h -> 7d -> 30d), plus the
/// time of the last offense used for pruning. It keeps track of which IPs changed since they were
/// last saved, so a failed save is repeated by the next one. Not thread-safe: owned by BanEngine's gate.
/// </summary>
internal sealed class OffenseTracker
{
    private readonly Dictionary<string, int> _counts = new(StringComparer.Ordinal);
    private readonly Dictionary<string, DateTime> _last = new(StringComparer.Ordinal);
    private readonly HashSet<string> _unsaved = new(StringComparer.Ordinal);

    /// <summary>Current offense count for an IP (0 when unknown).</summary>
    public int GetCount(string ip) => _counts.GetValueOrDefault(ip);

    /// <summary>
    /// Raises the count to at least <paramref name="count"/> and moves the last-offense time forward.
    /// Loads what is already stored, so nothing is marked as changed.
    /// </summary>
    public void Seed(string ip, int count, DateTime lastUtc)
    {
        if (!_counts.TryGetValue(ip, out var existing) || existing < count)
        {
            _counts[ip] = count;
        }

        if (!_last.TryGetValue(ip, out var last) || last < lastUtc)
        {
            _last[ip] = lastUtc;
        }
    }

    /// <summary>Sets the count and last-offense time unconditionally.</summary>
    public void Set(string ip, int count, DateTime lastUtc)
    {
        _counts[ip] = count;
        _last[ip] = lastUtc;
        _unsaved.Add(ip);
    }

    /// <summary>Updates only the last-offense time (e.g. when a ban ends) of an IP that has a count.</summary>
    public void Touch(string ip, DateTime lastUtc)
    {
        if (_counts.ContainsKey(ip))
        {
            _last[ip] = lastUtc;
            _unsaved.Add(ip);
        }
    }

    /// <summary>Forgets an IP entirely.</summary>
    public void Remove(string ip)
    {
        _counts.Remove(ip);
        _last.Remove(ip);
        _unsaved.Add(ip);
    }

    /// <summary>Forgets everything.</summary>
    public void Clear()
    {
        _unsaved.UnionWith(_counts.Keys);
        _counts.Clear();
        _last.Clear();
    }

    /// <summary>What changed since the last <see cref="MarkSaved"/>.</summary>
    public (List<OffenseCountEntry> Changed, List<string> Removed) GetUnsaved()
    {
        var changed = new List<OffenseCountEntry>();
        var removed = new List<string>();
        foreach (var ip in _unsaved)
        {
            if (_counts.TryGetValue(ip, out var count))
            {
                changed.Add(new OffenseCountEntry { IpAddress = ip, Count = count, LastUtc = _last[ip] });
            }
            else
            {
                removed.Add(ip);
            }
        }

        return (changed, removed);
    }

    /// <summary>Records that everything <see cref="GetUnsaved"/> returned reached the store.</summary>
    public void MarkSaved() => _unsaved.Clear();

    /// <summary>Removes IPs that are not in <paramref name="activeIps"/> and whose last offense is older than <paramref name="cutoff"/>.</summary>
    /// <returns>Number of IPs removed.</returns>
    public int PruneStale(HashSet<string> activeIps, DateTime cutoff)
    {
        var stale = _counts.Keys
            .Where(ip => !activeIps.Contains(ip) && _last[ip] < cutoff)
            .ToList();
        foreach (var ip in stale)
        {
            Remove(ip);
        }

        return stale.Count;
    }
}
