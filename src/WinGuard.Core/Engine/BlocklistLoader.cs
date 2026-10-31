using System.Security;
using System.Text;
using WinGuard.Core.Detection;
using WinGuard.Core.Model;

namespace WinGuard.Core.Engine;

/// <summary>What one <see cref="BlocklistLoader.Refresh"/> found.</summary>
/// <param name="EntriesChanged">The entries differ from before, so they need saving and enforcing.</param>
/// <param name="CountsChanged">Something a reader of the status would want an event about changed.</param>
/// <param name="Warnings">New problems. A problem that persists is reported once.</param>
internal sealed record BlocklistRefresh(bool EntriesChanged, bool CountsChanged, IReadOnlyList<string> Warnings);

/// <summary>
/// Keeps the blocklist files in memory. A file is read again only when its timestamp or size
/// changes. It runs outside the engine's gate, so a large file never holds up detection, and it has
/// its own lock because housekeeping and an IPC request can both get here.
/// <para>
/// Losing a file must not unblock what it listed, so each file keeps its last good entries until a
/// new version of it can be read, or until it is taken off the settings. A file that turns up with
/// nothing valid in it counts as losing it: that is what an error page saved in its place looks
/// like. So does one that shrank to under half, which is what an interrupted download looks like;
/// taking the file off the list and adding it back accepts it. <see cref="ExportLastGood"/> and
/// <see cref="Seed"/> carry the entries across a restart, when a data drive may come up after the
/// service.
/// </para>
/// </summary>
internal sealed class BlocklistLoader
{
    // Far above any published list; refuses a file that is not one before it is read into memory.
    private const long MaxFileBytes = 64L * 1024 * 1024;

    // A new version under half of a list this size looks cut off rather than cleaned up. Small lists
    // swing by that much in the normal course of things.
    private const int MinEntriesForTruncationCheck = 100;

    private readonly object _sync = new();
    private readonly int _maxEntries;
    private readonly Dictionary<string, FileRecord> _files = new(StringComparer.OrdinalIgnoreCase);
    private bool _seeded;
    private BlocklistSnapshot _current = BlocklistSnapshot.Empty;

    /// <summary>Creates a loader keeping at most <paramref name="maxEntries"/> firewall entries.</summary>
    public BlocklistLoader(int maxEntries)
    {
        _maxEntries = maxEntries;
    }

    /// <summary>The latest state; safe to read from any thread.</summary>
    public BlocklistSnapshot Current => Volatile.Read(ref _current);

    /// <summary>Brings the state up to date with the configured files, reading the ones that changed.</summary>
    /// <param name="paths">The configured paths.</param>
    /// <param name="nowUtc">The engine's clock.</param>
    public BlocklistRefresh Refresh(IReadOnlyCollection<string> paths, DateTime nowUtc)
    {
        lock (_sync)
        {
            var dirty = _seeded;
            _seeded = false;

            var configured = new HashSet<string>(paths, StringComparer.OrdinalIgnoreCase);
            foreach (var gone in _files.Keys.Where(path => !configured.Contains(path)).ToList())
            {
                _files.Remove(gone);
                dirty = true;
            }

            var warnings = new List<string>();
            foreach (var path in configured)
            {
                if (!_files.TryGetValue(path, out var file))
                {
                    file = new FileRecord(path);
                    _files[path] = file;
                    dirty = true;
                }

                dirty |= RefreshFile(file, nowUtc, warnings);
            }

            if (!dirty)
            {
                return new BlocklistRefresh(false, false, warnings);
            }

            var previous = Current;
            var merged = BlocklistParser.Collapse(_files.Values.SelectMany(file => file.Blocks), _maxEntries, out var capped);
            var entries = merged.Select(BlocklistParser.ToTarget).ToArray();
            var entriesChanged = !entries.SequenceEqual(previous.Entries);
            var next = new BlocklistSnapshot(
                entriesChanged ? entries : previous.Entries,
                _files.Values.Sum(file => file.Skipped),
                capped + _files.Values.Sum(file => file.Capped),
                paths.Select(path => _files[path].State()).ToList());
            Volatile.Write(ref _current, next);

            var countsChanged = entriesChanged || next.Skipped != previous.Skipped || next.Capped != previous.Capped;
            return new BlocklistRefresh(entriesChanged, countsChanged, warnings);
        }
    }

    /// <summary>The entries each file currently contributes, for <see cref="Seed"/> at the next start.</summary>
    public Dictionary<string, string[]> ExportLastGood()
    {
        lock (_sync)
        {
            return _files.Values.ToDictionary(
                file => file.Path,
                file => file.Blocks.Select(BlocklistParser.ToTarget).ToArray(),
                StringComparer.OrdinalIgnoreCase);
        }
    }

    /// <summary>
    /// Restores last good entries saved by an earlier run. They stand in for a file until it is
    /// read, so one that is readable replaces them at once. Entries are checked again like a list's.
    /// </summary>
    public void Seed(IReadOnlyDictionary<string, string[]> lastGood)
    {
        lock (_sync)
        {
            foreach (var (path, entries) in lastGood)
            {
                var file = _files.GetValueOrDefault(path) ?? new FileRecord(path);
                if (file.LastLoadedUtc is not null)
                {
                    continue;
                }

                var blocks = new List<AddressBlock>(entries.Length);
                foreach (var entry in entries)
                {
                    if (BlocklistParser.TryParseEntry(entry, out var block))
                    {
                        blocks.Add(block);
                    }
                }

                file.Blocks = blocks.ToArray();
                file.Loaded = blocks.Count;
                _files[path] = file;
                _seeded = true;
            }
        }
    }

    private bool RefreshFile(FileRecord file, DateTime nowUtc, List<string> warnings)
    {
        if (!LogFileTailer.IsLocalPath(file.Path))
        {
            return file.Fail("network (UNC) and device paths are not allowed", warnings);
        }

        try
        {
            var info = new FileInfo(Environment.ExpandEnvironmentVariables(file.Path.Trim('"')));
            if (!info.Exists)
            {
                return file.Fail("the file is missing", warnings);
            }

            var stamp = (info.LastWriteTimeUtc, info.Length);
            if (file.Stamp == stamp)
            {
                return false;
            }

            if (info.Length > MaxFileBytes)
            {
                return file.Fail($"the file is larger than {MaxFileBytes / (1024 * 1024)} MB", warnings);
            }

            using var stream = new FileStream(info.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            var blocks = BlocklistParser.Parse(reader, out var skipped);
            var collapsed = BlocklistParser.Collapse(blocks, _maxEntries, out var capped);
            if (Refusal(blocks.Count, skipped, collapsed.Count, file.Blocks.Length) is { } refusal)
            {
                // Nothing new can come of reading this version again.
                var changed = file.Fail(refusal, warnings) || file.Skipped != skipped;
                file.Skipped = skipped;
                file.Stamp = stamp;
                return changed;
            }

            file.Blocks = collapsed.ToArray();
            file.Capped = capped;
            file.Loaded = blocks.Count;
            file.Skipped = skipped;
            file.Stamp = stamp;
            file.LastLoadedUtc = nowUtc;
            file.Problem = null;
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException or ArgumentException or NotSupportedException)
        {
            return file.Fail("the file cannot be read: " + ex.Message, warnings);
        }
    }

    /// <summary>Why a readable new version must not replace the last good one, or null.</summary>
    private static string? Refusal(int parsed, int skipped, int entries, int lastGoodEntries)
    {
        if (parsed == 0 && (skipped > 0 || lastGoodEntries > 0))
        {
            return "the file holds no valid entry";
        }

        return lastGoodEntries >= MinEntriesForTruncationCheck && entries < lastGoodEntries / 2
            ? $"the file holds {entries} entries where the last good version held {lastGoodEntries}, so it looks cut off; if it is meant to be this short, take it off the list and add it back"
            : null;
    }

    private sealed class FileRecord(string path)
    {
        public string Path { get; } = path;

        public AddressBlock[] Blocks { get; set; } = [];

        public int Loaded { get; set; }

        public int Skipped { get; set; }

        public int Capped { get; set; }

        public DateTime? LastLoadedUtc { get; set; }

        public string? Problem { get; set; }

        /// <summary>The version last read, so an unchanged file stays unread.</summary>
        public (DateTime Written, long Length)? Stamp { get; set; }

        public BlocklistFileState State() => new(Path, Loaded, Skipped, LastLoadedUtc, Problem);

        /// <summary>Records a problem, keeping the last good entries; returns whether it is a new one.</summary>
        public bool Fail(string problem, List<string> warnings)
        {
            Stamp = null;
            if (Problem == problem)
            {
                return false;
            }

            Problem = problem;
            warnings.Add($"{Path}: {problem}");
            return true;
        }
    }
}
