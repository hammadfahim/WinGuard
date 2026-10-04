using System.Text;

namespace WinGuard.Core.Detection;

/// <summary>
/// Shared incremental file reader used by the FTP and custom-log detectors.
/// <para>
/// It keeps a byte offset and a partial-line buffer per file in memory, so every poll
/// cycle returns only the lines appended since the previous cycle. Log rotation or
/// truncation is detected by the file shrinking (the offset resets to 0), and the number
/// of bytes read per call is capped so one huge file cannot stall the poller. A line that
/// straddles a read boundary is retained and completed on the next cycle, so callers only
/// ever see whole lines.
/// </para>
/// <para>
/// On first sight of a file the cursor is positioned at the file's current length
/// (skip-to-end), so a service restart never replays historical failures found in an
/// existing log file. Rotation/truncation still resets the offset to 0 so the newly
/// rotated file is read fully. Set <see cref="ProcessExistingContent"/> (or the
/// constructor flag) to read pre-existing content on first sight, for tests/tooling.
/// </para>
/// </summary>
public sealed class LogFileTailer
{
    /// <summary>Default maximum number of bytes read from a single file per <see cref="ReadNewLines"/> call.</summary>
    public const int DefaultMaxBytesPerCycle = 1024 * 1024;

    /// <summary>Upper bound on buffered partial-line length; older data is discarded if exceeded.</summary>
    private const int MaxPendingChars = 64 * 1024;

    private readonly int _maxBytesPerCycle;
    private readonly object _gate = new();
    private readonly Dictionary<string, FileCursor> _cursors = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// When <see langword="false"/> (the default), the first time a file is seen its cursor is
    /// positioned at the end of the file, so only content appended after the tailer started is
    /// read: a restart never replays historical failures. When <see langword="true"/>, the whole
    /// existing file is read on first sight (tests/tooling only).
    /// </summary>
    public bool ProcessExistingContent { get; }

    /// <summary>Creates a tailer that reads at most <paramref name="maxBytesPerCycle"/> bytes per file per call.</summary>
    /// <param name="maxBytesPerCycle">Per-file read cap; values &lt;= 0 fall back to the default.</param>
    /// <param name="processExistingContent">
    /// <see langword="false"/> (default) skips to the end of each file when it is first seen so a
    /// service restart never replays historical failures; <see langword="true"/> reads existing
    /// content from the start of the file (tests/tooling).
    /// </param>
    public LogFileTailer(int maxBytesPerCycle = DefaultMaxBytesPerCycle, bool processExistingContent = false)
    {
        _maxBytesPerCycle = maxBytesPerCycle > 0 ? maxBytesPerCycle : DefaultMaxBytesPerCycle;
        ProcessExistingContent = processExistingContent;
    }

    /// <summary>
    /// Reads newly appended bytes from <paramref name="path"/> and returns the complete lines
    /// found. The trailing partial line, if any, is buffered for the next call.
    /// </summary>
    /// <param name="path">Absolute path of the log file.</param>
    /// <returns>The newly read lines (without line terminators); empty when nothing new or unreadable.</returns>
    public IReadOnlyList<string> ReadNewLines(string path)
    {
        var lines = new List<string>();
        if (string.IsNullOrWhiteSpace(path))
        {
            return lines;
        }

        try
        {
            lock (_gate)
            {
                if (!_cursors.TryGetValue(path, out var cursor))
                {
                    cursor = new FileCursor();
                    _cursors[path] = cursor;
                }

                using var stream = new FileStream(
                    path,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);

                var length = stream.Length;
                if (!cursor.Initialized)
                {
                    cursor.Initialized = true;
                    if (!ProcessExistingContent)
                    {
                        // First sight of the file and we are not reading history: skip to the end
                        // so a restart never replays historical failures (PLAN.md §4.4; phase-3
                        // topic #3 ruling). Rotation below still resets to 0 for new content.
                        cursor.Offset = length;
                        cursor.Pending = string.Empty;
                        return lines;
                    }
                }
                else if (length < cursor.Offset)
                {
                    // File shrank: rotated or truncated. Start again from byte 0 so the rotated
                    // or newly written file is read fully.
                    cursor.Offset = 0;
                    cursor.Pending = string.Empty;
                    cursor.Decoder.Reset();
                }

                var available = length - cursor.Offset;
                if (available <= 0)
                {
                    return lines;
                }

                var toRead = (int)Math.Min(available, _maxBytesPerCycle);
                var buffer = new byte[toRead];
                stream.Seek(cursor.Offset, SeekOrigin.Begin);
                var read = stream.Read(buffer, 0, toRead);
                if (read <= 0)
                {
                    return lines;
                }

                cursor.Offset += read;
                // Stateful decoder: a multi-byte character split across two reads is not corrupted.
                var chunk = new string(DecodeChars(cursor.Decoder, buffer, read));
                if (cursor.Pending.Length == 0 && chunk.Length > 0 && chunk[0] == '\uFEFF')
                {
                    chunk = chunk[1..];
                }

                var text = cursor.Pending + chunk;
                var start = 0;
                for (var i = 0; i < text.Length; i++)
                {
                    if (text[i] != '\n')
                    {
                        continue;
                    }

                    var end = i;
                    if (end > start && text[end - 1] == '\r')
                    {
                        end--;
                    }

                    lines.Add(text[start..end]);
                    start = i + 1;
                }

                var pending = text[start..];
                if (pending.Length > MaxPendingChars)
                {
                    pending = pending[^MaxPendingChars..];
                }

                cursor.Pending = pending;
            }
        }
        catch (IOException)
        {
            // Locked/deleted mid-read: try again next cycle.
        }
        catch (UnauthorizedAccessException)
        {
            // No read permission: try again next cycle.
        }
        catch (NotSupportedException)
        {
            // Malformed path: ignore this file.
        }

        return lines;
    }

    /// <summary>Drops offset state for files that are no longer part of a source, keeping memory bounded.</summary>
    /// <param name="activePaths">Paths still being polled.</param>
    public void Prune(IEnumerable<string> activePaths)
    {
        var active = new HashSet<string>(activePaths, StringComparer.OrdinalIgnoreCase);
        lock (_gate)
        {
            foreach (var key in _cursors.Keys.Where(k => !active.Contains(k)).ToList())
            {
                _cursors.Remove(key);
            }
        }
    }

    /// <summary>
    /// Expands a configured path into concrete files. The input may be an explicit file,
    /// a directory (everything matching <paramref name="defaultFolderPattern"/>), or a
    /// directory plus glob such as <c>C:\logs\*.log</c>. Environment variables are expanded.
    /// </summary>
    /// <param name="pathOrGlob">File path, folder, or folder + glob.</param>
    /// <param name="defaultFolderPattern">Pattern used when the input is a directory without a glob.</param>
    /// <returns>Matching absolute file paths, sorted; empty when the path is missing/unreadable.</returns>
    public static IReadOnlyList<string> ResolveFiles(string? pathOrGlob, string defaultFolderPattern = "*")
    {
        var files = new List<string>();
        if (string.IsNullOrWhiteSpace(pathOrGlob))
        {
            return files;
        }

        var expanded = Environment.ExpandEnvironmentVariables(pathOrGlob.Trim());
        try
        {
            if (expanded.IndexOfAny(new[] { '*', '?' }) >= 0)
            {
                var directory = Path.GetDirectoryName(expanded);
                var pattern = Path.GetFileName(expanded);
                if (string.IsNullOrEmpty(directory))
                {
                    directory = Directory.GetCurrentDirectory();
                }

                if (Directory.Exists(directory))
                {
                    files.AddRange(Directory.EnumerateFiles(directory, pattern, SearchOption.TopDirectoryOnly));
                }
            }
            else if (Directory.Exists(expanded))
            {
                files.AddRange(Directory.EnumerateFiles(expanded, defaultFolderPattern, SearchOption.TopDirectoryOnly));
            }
            else if (File.Exists(expanded))
            {
                files.Add(expanded);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            // Unreadable or invalid path: report nothing this cycle.
        }

        files.Sort(StringComparer.OrdinalIgnoreCase);
        return files;
    }

    private static char[] DecodeChars(Decoder decoder, byte[] buffer, int count)
    {
        var chars = new char[decoder.GetCharCount(buffer, 0, count, flush: false)];
        var written = decoder.GetChars(buffer, 0, count, chars, 0, flush: false);
        return written == chars.Length ? chars : chars[..written];
    }

    private sealed class FileCursor
    {
        public Decoder Decoder = new UTF8Encoding(false).GetDecoder();
        public long Offset;
        public string Pending = string.Empty;
        public bool Initialized;
    }
}