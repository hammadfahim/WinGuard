namespace WinGuard.Core.Engine;

/// <summary>
/// RDP de-dup (PLAN 4.2): Security 4625 and RdpCoreTS 140 can both describe the SAME login attempt.
/// Only CROSS-detector pairs within <see cref="Window"/> are merged; two events from the same
/// detector are distinct attempts and always count. In-memory by design. Not thread-safe.
/// </summary>
internal sealed class RdpDeduplicator
{
    /// <summary>Maximum gap between a 4625 and its matching 140.</summary>
    public static readonly TimeSpan Window = TimeSpan.FromSeconds(2);

    private readonly Dictionary<string, List<(string? Detector, DateTime TimestampUtc)>> _recent = new(StringComparer.Ordinal);

    /// <summary>True when the event duplicates a recent one from another detector; always records it.</summary>
    public bool IsDuplicateAndRecord(string ip, string? detector, DateTime timestampUtc)
    {
        if (!_recent.TryGetValue(ip, out var recent))
        {
            recent = [];
            _recent[ip] = recent;
        }

        var duplicate = false;
        foreach (var (seenDetector, seenTimestamp) in recent)
        {
            if (!string.Equals(seenDetector, detector, StringComparison.Ordinal) &&
                Math.Abs((seenTimestamp - timestampUtc).TotalSeconds) <= Window.TotalSeconds)
            {
                duplicate = true;
                break;
            }
        }

        // Entries older than 2x the window can never match again.
        recent.RemoveAll(e => Math.Abs((e.TimestampUtc - timestampUtc).TotalSeconds) > Window.TotalSeconds * 2);
        recent.Add((detector, timestampUtc));
        return duplicate;
    }

    /// <summary>Drops stale entries (housekeeping).</summary>
    public void Trim(DateTime now)
    {
        foreach (var key in _recent.Keys.ToList())
        {
            _recent[key].RemoveAll(e => (now - e.TimestampUtc).Duration() > TimeSpan.FromTicks(Window.Ticks * 2));
            if (_recent[key].Count == 0)
            {
                _recent.Remove(key);
            }
        }
    }

    /// <summary>Forgets everything.</summary>
    public void Clear() => _recent.Clear();
}
