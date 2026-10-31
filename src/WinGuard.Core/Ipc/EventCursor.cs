namespace WinGuard.Core.Ipc;

/// <summary>Events accepted from one poll.</summary>
/// <param name="Events">The new events, oldest first.</param>
/// <param name="Skipped">How many events fell between the previous read and this batch and could not be fetched: only a service that cannot page leaves such a gap.</param>
public sealed record EventBatch(IReadOnlyList<EventDto> Events, long Skipped)
{
    /// <summary>A poll that found nothing.</summary>
    public static EventBatch None { get; } = new([], 0);
}

/// <summary>
/// Tracks how far the console has read the service's event feed.
/// <para>
/// The first read takes the newest rows, which starts the feed at "the latest N". From then on
/// <see cref="PipeClient.ReadNewEventsAsync"/> walks forward with <see cref="ListEventsParams.OldestFirst"/>,
/// page after page, so a burst of any size is recovered whole and in order, and the cursor survives
/// hiding the window and reconnecting, so whatever arrived meanwhile is read instead of being jumped
/// over. A service without paging ignores that flag and answers with the NEWEST rows after the cursor:
/// such a full batch has lost its older part, and the id gap says exactly how many rows are missing,
/// so they are counted and reported rather than dropped silently.
/// </para>
/// </summary>
public sealed class EventCursor
{
    /// <summary>The newest event id read so far; null before the first read.</summary>
    public long? LastId { get; private set; }

    /// <summary>Accepts one response.</summary>
    /// <param name="rows">The rows, in the order the service returned them.</param>
    /// <param name="requested">The limit that was asked for.</param>
    public EventBatch Accept(IReadOnlyList<EventDto> rows, int requested)
    {
        if (rows.Count == 0)
        {
            return EventBatch.None;
        }

        var ordered = rows.OrderBy(dto => dto.Id).ToList();
        var oldest = ordered[0].Id;
        var newest = ordered[^1].Id;

        // Only a full newest-first batch can have been cut off: a page walking forward starts right
        // after the cursor, and a gap in its ids is rows pruned from the store, not rows it left out.
        // The first read has no earlier position to compare with: it starts the feed at "the latest N".
        var newestFirst = rows[0].Id > rows[^1].Id;
        var skipped = LastId is { } last && newestFirst && rows.Count >= requested && oldest > last + 1
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
