namespace WinGuard.Core.Engine;

/// <summary>
/// RDP de-dup (PLAN 4.2): Security 4625 and RdpCoreTS 140 can both describe the SAME login attempt.
/// An event is a duplicate only when it pairs with a not-yet-paired event from the OTHER detector
/// within <see cref="Window"/>; each event can be paired once, so a fast attack (many attempts
/// inside the window) still counts once per attempt. In-memory by design. Not thread-safe.
/// </summary>
internal sealed class RdpDeduplicator
{
    /// <summary>Maximum gap between a 4625 and its matching 140.</summary>
    public static readonly TimeSpan Window = TimeSpan.FromSeconds(2);

    // A flood of distinct addresses between two housekeeping passes must not grow memory without limit.
    private const int DefaultMaxTrackedIps = 100_000;

    private readonly Dictionary<string, List<Entry>> _recent = new(StringComparer.Ordinal);
    private readonly bool _trimByEventTime;
    private readonly int _maxTrackedIps;
    private int _resets;

    /// <summary>Creates the de-duplicator.</summary>
    /// <param name="trimByEventTime">
    /// Whether an event drops the entries too far from its own timestamp. That only works for live
    /// events, which arrive in time order. Backlog replay reads the two channels independently, so
    /// a replayed 4625 and its 140 can be thousands of events apart and must both stay findable.
    /// </param>
    /// <param name="maxTrackedIps">
    /// How many addresses are remembered at most. Past that the memory is emptied, which can only
    /// count an attempt twice: it never hides a failure.
    /// </param>
    public RdpDeduplicator(bool trimByEventTime = true, int maxTrackedIps = DefaultMaxTrackedIps)
    {
        _trimByEventTime = trimByEventTime;
        _maxTrackedIps = maxTrackedIps;
    }

    /// <summary>
    /// True when the event is the second half of an attempt already seen through the other detector
    /// (or the counterpart of an excluded event). Otherwise the event is remembered and counts.
    /// </summary>
    public bool IsDuplicateAndRecord(string ip, string? detector, DateTime timestampUtc) =>
        IsDuplicateAndRecord(ip, detector, timestampUtc, out _);

    /// <inheritdoc cref="IsDuplicateAndRecord(string, string?, DateTime)"/>
    /// <param name="ip">The client address.</param>
    /// <param name="detector">The detector that saw the event.</param>
    /// <param name="timestampUtc">When the event happened.</param>
    /// <param name="partnerCounted">True when the other half was counted, not removed by an exclusion rule.</param>
    public bool IsDuplicateAndRecord(string ip, string? detector, DateTime timestampUtc, out bool partnerCounted)
    {
        partnerCounted = false;
        var recent = GetAndTrim(ip, timestampUtc);
        var partner = FindUnpairedPartner(recent, detector, timestampUtc);
        if (partner is not null)
        {
            partner.Paired = true;
            partnerCounted = !partner.Excluded;
            return true;
        }

        recent.Add(new Entry(detector, timestampUtc, Excluded: false));
        return false;
    }

    /// <summary>
    /// Records an event that an exclusion rule removed, so its counterpart from the other detector
    /// is dropped too. Returns <see langword="true"/> when that counterpart had ALREADY been counted
    /// (it arrived first); the caller must then take that one count back.
    /// </summary>
    public bool RecordExcluded(string ip, string? detector, DateTime timestampUtc)
    {
        var recent = GetAndTrim(ip, timestampUtc);
        var partner = FindUnpairedPartner(recent, detector, timestampUtc);
        if (partner is not null)
        {
            partner.Paired = true;
            return !partner.Excluded;
        }

        recent.Add(new Entry(detector, timestampUtc, Excluded: true));
        return false;
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

    /// <summary>How many addresses are remembered right now.</summary>
    public int TrackedIps => _recent.Count;

    /// <summary>How many times the limit emptied the memory since the last call, for the caller to report.</summary>
    public int TakeResets()
    {
        var resets = _resets;
        _resets = 0;
        return resets;
    }

    private List<Entry> GetAndTrim(string ip, DateTime timestampUtc)
    {
        if (!_recent.TryGetValue(ip, out var recent))
        {
            if (_recent.Count >= _maxTrackedIps)
            {
                MakeRoom(timestampUtc);
            }

            recent = [];
            _recent[ip] = recent;
        }

        // Entries older than 2x the window can never pair again.
        if (_trimByEventTime)
        {
            recent.RemoveAll(e => Math.Abs((e.TimestampUtc - timestampUtc).TotalSeconds) > Window.TotalSeconds * 2);
        }

        return recent;
    }

    /// <summary>Drops what is stale; with nothing stale to drop, everything goes.</summary>
    private void MakeRoom(DateTime timestampUtc)
    {
        if (_trimByEventTime)
        {
            Trim(timestampUtc);
        }

        if (_recent.Count >= _maxTrackedIps)
        {
            _recent.Clear();
            _resets++;
        }
    }

    private static Entry? FindUnpairedPartner(List<Entry> recent, string? detector, DateTime timestampUtc)
    {
        // Oldest first, so interleaved attempts pair in arrival order.
        foreach (var entry in recent)
        {
            if (!entry.Paired
                && !string.Equals(entry.Detector, detector, StringComparison.Ordinal)
                && Math.Abs((entry.TimestampUtc - timestampUtc).TotalSeconds) <= Window.TotalSeconds)
            {
                return entry;
            }
        }

        return null;
    }

    private sealed record Entry(string? Detector, DateTime TimestampUtc, bool Excluded)
    {
        public bool Paired { get; set; }
    }
}
