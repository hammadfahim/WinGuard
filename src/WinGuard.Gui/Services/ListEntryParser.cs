using WinGuard.Core.Engine;

namespace WinGuard.Gui.Services;

/// <summary>Why a pasted or typed list value is, or is not, usable.</summary>
public enum EntryStatus
{
    /// <summary>A usable address or range.</summary>
    Valid,

    /// <summary>Not an address or CIDR range.</summary>
    Invalid,

    /// <summary>Wider than the service accepts (shorter than /8 for IPv4 or /32 for IPv6).</summary>
    TooBroad,

    /// <summary>Already on this list, or repeated in the same paste.</summary>
    Duplicate,
}

/// <summary>One value from typed or pasted text.</summary>
/// <param name="Text">The value as entered.</param>
/// <param name="Canonical">The normalized value when usable.</param>
/// <param name="Status">The verdict.</param>
public sealed record ParsedEntry(string Text, string Canonical, EntryStatus Status);

/// <summary>Pure parsing behind the Lists page: live validation, paste of many entries, and import.</summary>
public static class ListEntryParser
{
    private static readonly char[] Separators = ['\r', '\n', ',', ';', '\t', ' '];

    /// <summary>
    /// Splits text into candidate values. Accepts newlines, commas, semicolons and spaces, ignores
    /// '#' comments, and takes the first cell of a CSV row that starts with a value.
    /// </summary>
    public static IReadOnlyList<string> Split(string? text)
    {
        var values = new List<string>();
        if (string.IsNullOrWhiteSpace(text))
        {
            return values;
        }

        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine;
            var comment = line.IndexOf('#');
            if (comment >= 0)
            {
                line = line[..comment];
            }

            foreach (var token in line.Split(Separators, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                values.Add(token.Trim('"', '\''));
            }
        }

        return values;
    }

    /// <summary>Judges one value.</summary>
    /// <param name="text">The value.</param>
    /// <param name="existing">Canonical values already on the list, compared case-insensitively.</param>
    public static ParsedEntry Parse(string text, ISet<string>? existing = null)
    {
        var value = text.Trim();
        var shape = IpText.Shape(value);
        if (!shape.IsValid)
        {
            return new ParsedEntry(value, string.Empty, EntryStatus.Invalid);
        }

        if (shape.IsRange && !IpMatcher.IsBannableRange(shape.Canonical))
        {
            return new ParsedEntry(value, shape.Canonical, EntryStatus.TooBroad);
        }

        return existing is not null && existing.Contains(shape.Canonical)
            ? new ParsedEntry(value, shape.Canonical, EntryStatus.Duplicate)
            : new ParsedEntry(value, shape.Canonical, EntryStatus.Valid);
    }

    /// <summary>Judges everything in a paste or an imported file, in order, flagging repeats.</summary>
    public static IReadOnlyList<ParsedEntry> ParseMany(string? text, IEnumerable<string> existing)
    {
        var seen = new HashSet<string>(existing, StringComparer.OrdinalIgnoreCase);
        var result = new List<ParsedEntry>();
        foreach (var value in Split(text))
        {
            var entry = Parse(value, seen);
            if (entry.Status == EntryStatus.Valid)
            {
                seen.Add(entry.Canonical);
            }

            result.Add(entry);
        }

        return result;
    }

    /// <summary>The one-line reading of a verdict.</summary>
    public static string Explain(EntryStatus status) => status switch
    {
        EntryStatus.Invalid => "Not an IP address or CIDR range",
        EntryStatus.TooBroad => "Too broad: the service refuses prefixes shorter than /8 (IPv4) or /32 (IPv6)",
        EntryStatus.Duplicate => "Already on this list",
        _ => string.Empty,
    };
}
