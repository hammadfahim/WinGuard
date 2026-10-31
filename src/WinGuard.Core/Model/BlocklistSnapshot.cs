namespace WinGuard.Core.Model;

/// <summary>What the blocklist files amount to at one moment; immutable, so it can be read without a lock.</summary>
/// <param name="Entries">Ban targets, collapsed and capped, before the whitelist is taken out.</param>
/// <param name="Skipped">Lines refused across all files.</param>
/// <param name="Capped">Entries left out because of the cap.</param>
/// <param name="Files">The state of each configured file.</param>
public sealed record BlocklistSnapshot(
    IReadOnlyList<string> Entries,
    int Skipped,
    int Capped,
    IReadOnlyList<BlocklistFileState> Files)
{
    /// <summary>No files, nothing loaded.</summary>
    public static BlocklistSnapshot Empty { get; } = new([], 0, 0, []);
}

/// <summary>One blocklist file.</summary>
/// <param name="Path">The path as configured.</param>
/// <param name="Loaded">Valid entries when it was last read.</param>
/// <param name="Skipped">Lines refused when it was last read.</param>
/// <param name="LastLoadedUtc">When it was last read successfully, if ever.</param>
/// <param name="Problem">Why it is not being read; its last good entries stay in force meanwhile.</param>
public sealed record BlocklistFileState(string Path, int Loaded, int Skipped, DateTime? LastLoadedUtc, string? Problem);
