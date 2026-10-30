using WinGuard.Core.Ipc;

namespace WinGuard.Gui.Services;

/// <summary>Events accepted from one poll.</summary>
/// <param name="Events">The new events, oldest first.</param>
/// <param name="Skipped">How many events fell between the previous read and this batch and could not be fetched.</param>
public sealed record EventBatch(IReadOnlyList<EventDto> Events, long Skipped)
{
    /// <summary>A poll that found nothing.</summary>
    public static EventBatch None { get; } = new([], 0);
}

/// <summary>
/// Tracks how far the console has read the service's event feed.
/// <para>
/// ListEvents returns the NEWEST rows after the cursor, so a burst larger than one request's limit
/// comes back with its oldest part missing, and moving the cursor to the newest id then loses that
/// part for good. Two things keep that from happening: the poller asks for as many rows as the service
/// will return, which matches what the event feed can hold anyway, and the cursor survives hiding the
/// window and reconnecting, so whatever arrived meanwhile is read instead of being jumped over. What
/// still cannot be fetched is counted and reported rather than dropped silently, because the id gap
/// says exactly how many rows are missing.
/// </para>
/// </summary>
public sealed class EventCursor
{
    /// <summary>The newest event id read so far; null before the first read.</summary>
    public long? LastId { get; private set; }

    /// <summary>Accepts one response.</summary>
    /// <param name="newestFirst">The rows, in the order the service returned them.</param>
    /// <param name="requested">The limit that was asked for.</param>
    public EventBatch Accept(IReadOnlyList<EventDto> newestFirst, int requested)
    {
        if (newestFirst.Count == 0)
        {
            return EventBatch.None;
        }

        var ordered = newestFirst.OrderBy(dto => dto.Id).ToList();
        var oldest = ordered[0].Id;
        var newest = ordered[^1].Id;

        // Only a full batch can have been cut off. The first read has no earlier position to compare
        // with: it simply starts the feed at "the latest N".
        var skipped = LastId is { } last && newestFirst.Count >= requested && oldest > last + 1
            ? oldest - last - 1
            : 0;

        LastId = Math.Max(newest, LastId ?? newest);
        return new EventBatch(ordered, skipped);
    }

    /// <summary>
    /// Compares the cursor with the service's newest event. A smaller id means the store was recreated
    /// or emptied and ids started over, in which case the cursor would otherwise never see anything
    /// again. Returns true when the cursor was reset.
    /// </summary>
    public bool ObserveNewest(long newestId)
    {
        if (LastId is { } last && newestId < last)
        {
            LastId = null;
            return true;
        }

        return false;
    }
}
