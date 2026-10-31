namespace WinGuard.Gui.Services;

/// <summary>
/// Builds the dashboard's per-minute activity from what the service exposes. The service keeps no
/// per-minute history: detections are only available as a running total for the day, so they are
/// differenced between polls, while blocks carry real timestamps in the event feed. The detection line
/// therefore starts when the console starts; earlier minutes read as zero.
/// </summary>
public sealed class LiveActivityTracker
{
    private readonly int _minutes;
    private readonly double[] _detections;
    private readonly double[] _blocks;
    private DateTime _newestMinute;
    private DateTime? _lastSampleUtc;
    private long? _lastTotal;

    /// <summary>Creates a tracker holding the most recent <paramref name="minutes"/> minutes.</summary>
    public LiveActivityTracker(int minutes = 60)
    {
        _minutes = minutes;
        _detections = new double[minutes];
        _blocks = new double[minutes];
    }

    /// <summary>Number of minutes kept.</summary>
    public int Minutes => _minutes;

    /// <summary>The minute of the newest bucket (UTC).</summary>
    public DateTime NewestMinute => _newestMinute;

    /// <summary>Detections per minute, oldest first.</summary>
    public IReadOnlyList<double> Detections => _detections;

    /// <summary>Blocks per minute, oldest first.</summary>
    public IReadOnlyList<double> Blocks => _blocks;

    /// <summary>Detections recorded in the last hour of buckets.</summary>
    public double DetectionsLastHour => _detections.Sum();

    /// <summary>
    /// Feeds the service's running detections total. Returns true when a bucket changed or time moved
    /// on. A gap (the window was hidden) spreads the difference evenly across the missed minutes rather
    /// than drawing one false spike. A smaller total means the service rolled to a new day or restarted.
    /// </summary>
    public bool Sample(DateTime nowUtc, long detectionsTotal)
    {
        var moved = Advance(nowUtc);

        if (_lastTotal is not { } previous || _lastSampleUtc is not { } lastSample)
        {
            _lastTotal = detectionsTotal;
            _lastSampleUtc = nowUtc;
            return moved;
        }

        var delta = detectionsTotal >= previous ? detectionsTotal - previous : detectionsTotal;
        _lastTotal = detectionsTotal;
        _lastSampleUtc = nowUtc;
        if (delta <= 0)
        {
            return moved;
        }

        var spanned = Math.Clamp((int)Math.Ceiling((nowUtc - lastSample).TotalMinutes), 1, _minutes);
        var share = delta / (double)spanned;
        for (var i = 0; i < spanned; i++)
        {
            _detections[_minutes - 1 - i] += share;
        }

        return true;
    }

    /// <summary>Counts one block at its real time. Returns false when it is older than the window.</summary>
    public bool AddBlock(DateTime whenUtc, DateTime nowUtc)
    {
        Advance(nowUtc);
        var index = _minutes - 1 - (int)((_newestMinute - Floor(whenUtc)).TotalMinutes);
        if (index < 0 || index >= _minutes)
        {
            return false;
        }

        _blocks[index]++;
        return true;
    }

    private static DateTime Floor(DateTime utc) => new(utc.Ticks - (utc.Ticks % TimeSpan.TicksPerMinute), DateTimeKind.Utc);

    private bool Advance(DateTime nowUtc)
    {
        var minute = Floor(nowUtc);
        if (_newestMinute == default)
        {
            _newestMinute = minute;
            return true;
        }

        var steps = (int)((minute - _newestMinute).TotalMinutes);
        if (steps <= 0)
        {
            return false;
        }

        Shift(_detections, steps);
        Shift(_blocks, steps);
        _newestMinute = minute;
        return true;
    }

    private void Shift(double[] buckets, int steps)
    {
        if (steps >= _minutes)
        {
            Array.Clear(buckets);
            return;
        }

        Array.Copy(buckets, steps, buckets, 0, _minutes - steps);
        Array.Clear(buckets, _minutes - steps, steps);
    }
}
