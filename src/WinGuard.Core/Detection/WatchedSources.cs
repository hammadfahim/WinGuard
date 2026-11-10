namespace WinGuard.Core.Detection;

/// <summary>What one poll cycle found for a log source.</summary>
/// <param name="Files">The files to read this cycle; empty while the source cannot be listed.</param>
/// <param name="ReadNewFilesFromStart">
/// Whether a file the tailer has not seen before is new content (the next daily log) rather than
/// history. True only for a source that was polled before and has been readable since.
/// </param>
/// <param name="BecameUnavailable">The source could be listed last cycle and cannot be now.</param>
/// <param name="Returned">The source cannot have been listed for a while and can be again.</param>
internal readonly record struct WatchedSourceFiles(
    IReadOnlyList<string> Files,
    bool ReadNewFilesFromStart,
    bool BecameUnavailable,
    bool Returned);

/// <summary>
/// Remembers, from one poll cycle to the next, which log sources were being watched and which files
/// each one had. The file detectors need two answers from it.
/// <para>
/// Whether a file that turns up is new. Under a source that was already being watched it is (the
/// next daily log), and it is read from its first line; under a source seen for the first time it
/// is history, and the tailer skips to its end.
/// </para>
/// <para>
/// What to do when a source cannot be listed: its folder is gone for a moment, its volume is
/// offline, or the listing fails. That is not the same as the source having no files. The files it
/// had stay <see cref="HeldFiles">held</see>, so the tailer keeps their positions, and when the
/// source is back each one continues where it stopped. Without this the positions were dropped and
/// every file counted as new on the source's return: years of logs read again from the first line,
/// and for a custom source every address in them banned afresh. On the cycle a source returns,
/// files it did not have before are treated as history too, since nothing says whether they were
/// written or restored while it was away.
/// </para>
/// Not thread-safe: owned by one detector's poll loop.
/// </summary>
internal sealed class WatchedSources
{
    private Dictionary<string, SourceState> _previous = new(StringComparer.OrdinalIgnoreCase);
    private Dictionary<string, SourceState> _current = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>How many sources the last finished cycle saw.</summary>
    public int Count => _previous.Count;

    /// <summary>
    /// The files of sources that cannot be listed in this cycle. They are not read, but their
    /// positions must survive the tailer's prune.
    /// </summary>
    public IEnumerable<string> HeldFiles => _current.Values.Where(state => state.Unavailable).SelectMany(state => state.Files);

    /// <summary>Lists the files of one source for this cycle.</summary>
    /// <param name="sourceKey">Identifies the source across cycles.</param>
    /// <param name="pathOrGlob">File path, folder, or folder + glob.</param>
    /// <param name="defaultFolderPattern">Pattern used when the path is a folder without a glob.</param>
    public WatchedSourceFiles Resolve(string sourceKey, string? pathOrGlob, string defaultFolderPattern)
    {
        var known = _previous.TryGetValue(sourceKey, out var before);
        if (!LogFileTailer.TryResolveFiles(pathOrGlob, defaultFolderPattern, out var files))
        {
            // Only a source that had files has positions worth keeping. One that never had any
            // (its log does not exist yet) stays an ordinary watched source, so the file is read
            // from its first line when it is created.
            var held = known ? before!.Files : [];
            var wasUnavailable = known && before!.Unavailable;
            _current[sourceKey] = new SourceState(held, Unavailable: held.Count > 0);
            return new WatchedSourceFiles([], ReadNewFilesFromStart: false, BecameUnavailable: held.Count > 0 && !wasUnavailable, Returned: false);
        }

        var returned = known && before!.Unavailable;
        _current[sourceKey] = new SourceState(files, Unavailable: false);
        return new WatchedSourceFiles(files, ReadNewFilesFromStart: known && !returned, BecameUnavailable: false, Returned: returned);
    }

    /// <summary>Ends the cycle: sources that were not resolved in it are forgotten.</summary>
    public void EndCycle()
    {
        _previous = _current;
        _current = new Dictionary<string, SourceState>(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>Forgets every source, so the next cycle starts as the first one does.</summary>
    public void Clear()
    {
        _previous.Clear();
        _current.Clear();
    }

    private sealed record SourceState(IReadOnlyList<string> Files, bool Unavailable);
}
