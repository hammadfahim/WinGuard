using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace WinGuard.Core.Detection;

/// <summary>
/// Shared incremental file reader used by the FTP and custom-log detectors.
/// <para>
/// It keeps a byte offset and a partial-line buffer per file in memory, so every poll
/// cycle returns only the lines appended since the previous cycle. Log rotation or
/// truncation is detected by the file's identity changing or by it shrinking (the offset
/// resets to 0), and the number of bytes read per call is capped so one huge file cannot
/// stall the poller. A line that straddles a read boundary is retained and completed on the
/// next cycle, so callers only ever see whole lines.
/// </para>
/// <para>
/// The encoding comes from the BOM at the start of the file (UTF-8, UTF-16 or UTF-32), read
/// again after a rotation; a file without one is read as UTF-8.
/// </para>
/// <para>
/// On first sight of a file the cursor is positioned at the file's current length
/// (skip-to-end), so a service restart never replays historical failures found in an
/// existing log file. A file that appears later under a source that was already being watched
/// (the next daily log) is read from its first byte, and rotation/truncation resets the offset to
/// 0 so the newly rotated file is read fully. Set <see cref="ProcessExistingContent"/> (or the
/// constructor flag) to read pre-existing content on first sight, for tests/tooling.
/// </para>
/// </summary>
public sealed class LogFileTailer
{
    /// <summary>Default maximum number of bytes read from a single file per <see cref="ReadNewLines"/> call.</summary>
    public const int DefaultMaxBytesPerCycle = 1024 * 1024;

    /// <summary>Upper bound on buffered partial-line length; a longer line is dropped whole.</summary>
    private const int MaxPendingChars = 64 * 1024;

    /// <summary>How many cursors of rotated-away files are kept in case the file reappears under a new name.</summary>
    private const int MaxRotatedCursors = 32;

    /// <summary>Environment variables can point at each other; stop expanding after this many rounds.</summary>
    private const int MaxExpansionRounds = 8;

    private readonly int _maxBytesPerCycle;
    private readonly object _gate = new();
    private readonly Dictionary<string, FileCursor> _cursors = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<FileCursor> _rotated = [];

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
    /// <param name="readFromStartIfNew">
    /// What to do the first time this file is seen. <see langword="false"/> (default) skips to the
    /// end: the file already existed when its source started being watched, so its content is
    /// history. <see langword="true"/> reads it from the first byte: the caller knows the source was
    /// already being watched, so this is a file created since (e.g. the next daily log) and all of
    /// it is new.
    /// </param>
    /// <param name="crLfRecords">
    /// <see langword="true"/> when the file's writer ends every record with CRLF and may log client
    /// text containing a bare LF. Only CRLF then ends a line: splitting at the LF would turn the rest
    /// of the client's text into a line of its own, complete with an address the client chose.
    /// </param>
    /// <returns>The newly read lines (without line terminators); empty when nothing new or unreadable.</returns>
    public IReadOnlyList<string> ReadNewLines(string path, bool readFromStartIfNew = false, bool crLfRecords = false)
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
                    // Decided at first sight, not at first successful open: a file that was merely
                    // locked on the first attempt must not be mistaken for a new one later.
                    cursor = new FileCursor { FromStart = readFromStartIfNew };
                    _cursors[path] = cursor;
                }

                using var stream = new FileStream(
                    path,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);

                var length = stream.Length;

                // Rotation that replaces the file (delete or rename, then create) can leave a new
                // file as large as the old one, which the shrink check below cannot see. The file's
                // identity on the volume changes in that case. (Its creation time does not: NTFS
                // "tunnels" the old creation time onto a file recreated under the same name.)
                var identity = GetFileIdentity(stream.SafeFileHandle);
                if (cursor.Initialized && identity is not null && cursor.Identity is not null
                    && !string.Equals(identity, cursor.Identity, StringComparison.Ordinal))
                {
                    // The old file may come back under a new name; see ContinueRenamedFile.
                    _rotated.Add(cursor);
                    if (_rotated.Count > MaxRotatedCursors)
                    {
                        _rotated.RemoveAt(0);
                    }

                    cursor = _cursors[path] = new FileCursor { Initialized = true };
                }

                cursor.Identity = identity;
                if (!cursor.Initialized)
                {
                    cursor.Initialized = true;
                    if (!ContinueRenamedFile(cursor) && !ProcessExistingContent && !cursor.FromStart)
                    {
                        // First sight of the file and we are not reading history: skip to the end
                        // so a restart never replays historical failures (PLAN.md §4.4; phase-3
                        // topic #3 ruling). Rotation below still resets to 0 for new content. The
                        // BOM is at the start, so the encoding has to be read before skipping it.
                        DetectEncoding(cursor, stream);
                        cursor.Offset = AlignToChar(cursor, length);
                        cursor.Pending = string.Empty;
                        return lines;
                    }
                }

                if (length < cursor.Offset)
                {
                    // File shrank: rotated or truncated. Start again from byte 0 so the rotated
                    // or newly written file is read fully.
                    cursor = _cursors[path] = new FileCursor { Initialized = true, Identity = identity };
                }

                DetectEncoding(cursor, stream);
                var available = length - cursor.Offset;
                if (available <= 0 || cursor.Decoder is null)
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
                    else if (crLfRecords)
                    {
                        continue;
                    }

                    if (cursor.DroppingLongLine)
                    {
                        cursor.DroppingLongLine = false;
                    }
                    else
                    {
                        lines.Add(text[start..end]);
                    }

                    start = i + 1;
                }

                var pending = text[start..];
                if (pending.Length > MaxPendingChars)
                {
                    // Keeping only the tail would pass off the end of the line, which may be text a
                    // client chose, as a line of its own. Drop the whole line instead.
                    pending = string.Empty;
                    cursor.DroppingLongLine = true;
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
        if (!IsLocalPath(expanded))
        {
            // The service runs as SYSTEM: opening a UNC path would authenticate the machine
            // account to whatever host the path names.
            return files;
        }

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

    /// <summary>
    /// False for UNC and device paths (<c>\\server\share</c>, <c>\\?\</c>, <c>\\.\</c>, <c>\??\</c>),
    /// whichever separators they use and whether written out or reached through environment
    /// variables. Log sources must be on a local drive.
    /// </summary>
    public static bool IsLocalPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var expanded = path.Trim();
        for (var round = 0; round < MaxExpansionRounds; round++)
        {
            var next = Environment.ExpandEnvironmentVariables(expanded);
            if (next == expanded)
            {
                break;
            }

            expanded = next;
        }

        // Windows treats '/' and '\' alike, so \/server\share and /\server\share are UNC paths too.
        var normalized = expanded.Trim().Trim('"').Replace('/', '\\');
        return !(normalized.StartsWith(@"\\", StringComparison.Ordinal) || normalized.StartsWith(@"\??\", StringComparison.Ordinal));
    }

    /// <summary>
    /// Reads the encoding from the BOM once per file. Waits for the file to have content, and the
    /// cursor then starts after the BOM.
    /// </summary>
    private static void DetectEncoding(FileCursor cursor, FileStream stream)
    {
        if (cursor.Decoder is not null || stream.Length == 0)
        {
            return;
        }

        Span<byte> head = stackalloc byte[4];
        stream.Seek(0, SeekOrigin.Begin);
        head = head[..stream.ReadAtLeast(head, head.Length, throwOnEndOfStream: false)];

        // UTF-32 first: its little-endian BOM begins with the UTF-16 one.
        (Encoding Encoding, int BomLength, int CharSize) detected = head switch
        {
            [0xFF, 0xFE, 0x00, 0x00] => (new UTF32Encoding(false, false), 4, 4),
            [0x00, 0x00, 0xFE, 0xFF] => (new UTF32Encoding(true, false), 4, 4),
            [0xFF, 0xFE, ..] => (new UnicodeEncoding(false, false), 2, 2),
            [0xFE, 0xFF, ..] => (new UnicodeEncoding(true, false), 2, 2),
            [0xEF, 0xBB, 0xBF, ..] => (new UTF8Encoding(false), 3, 1),
            _ => (new UTF8Encoding(false), 0, 1),
        };

        cursor.Encoding = detected.Encoding;
        cursor.Decoder = detected.Encoding.GetDecoder();
        cursor.BomLength = detected.BomLength;
        cursor.CharSize = detected.CharSize;
        cursor.Offset = Math.Max(cursor.Offset, detected.BomLength);
    }

    /// <summary>Moves an offset back to the start of a character, so a half-written one cannot shift all later decoding.</summary>
    private static long AlignToChar(FileCursor cursor, long offset) =>
        offset - ((offset - cursor.BomLength) % cursor.CharSize);

    /// <summary>
    /// A file seen for the first time may be one we already follow, renamed by rotation
    /// (<c>app.log</c> to <c>app.log.1</c>) into a folder or glob we watch. Reading it as new would
    /// count its whole history again, so the read continues where the old name stopped; that also
    /// picks up lines written just before the rotation.
    /// </summary>
    private bool ContinueRenamedFile(FileCursor cursor)
    {
        if (cursor.Identity is null)
        {
            return false;
        }

        bool SameFile(FileCursor other) => other.Initialized
            && !ReferenceEquals(other, cursor)
            && string.Equals(other.Identity, cursor.Identity, StringComparison.Ordinal);

        var previous = _cursors.Values.FirstOrDefault(SameFile) ?? _rotated.LastOrDefault(SameFile);
        if (previous is null)
        {
            return false;
        }

        cursor.Encoding = previous.Encoding;
        cursor.Decoder = previous.Encoding?.GetDecoder();
        cursor.BomLength = previous.BomLength;
        cursor.CharSize = previous.CharSize;
        cursor.Offset = AlignToChar(previous, previous.Offset);
        cursor.Pending = previous.Pending;
        cursor.DroppingLongLine = previous.DroppingLongLine;
        return true;
    }

    /// <summary>Volume serial + file index: stable for a file's lifetime, different for its replacement.</summary>
    private static string? GetFileIdentity(SafeFileHandle handle)
    {
        try
        {
            if (OperatingSystem.IsWindows() && GetFileInformationByHandle(handle, out var info))
            {
                return $"{info.VolumeSerialNumber:x8}:{info.FileIndexHigh:x8}{info.FileIndexLow:x8}";
            }
        }
        catch (Exception)
        {
            // Fall through: without an identity only the shrink check applies.
        }

        return null;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public long CreationTime;
        public long LastAccessTime;
        public long LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out ByHandleFileInformation information);

    private sealed class FileCursor
    {
        public Encoding? Encoding;
        public Decoder? Decoder;
        public int BomLength;
        public int CharSize = 1;
        public long Offset;
        public string Pending = string.Empty;
        public bool DroppingLongLine;
        public bool Initialized;
        public bool FromStart;
        public string? Identity;
    }
}