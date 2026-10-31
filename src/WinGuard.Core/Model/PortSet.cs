using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace WinGuard.Core.Model;

/// <summary>
/// The local ports a firewall block applies to, in canonical form: ranges sorted and merged, so
/// <c>1433,3389</c> and <c>3389, 1433, 3389</c> are one set and share one rule family. No ports at
/// all means every port, as an empty <c>BlockedPorts</c> always has.
/// </summary>
public sealed class PortSet : IEquatable<PortSet>
{
    private const int FamilyHashLength = 8;

    private readonly (int First, int Last)[] _ranges;

    private PortSet((int First, int Last)[] ranges)
    {
        _ranges = ranges;
        Tokens = ranges.Select(Format).ToArray();
        Text = string.Join(',', Tokens);
        RuleFamily = ranges.Length == 0
            ? string.Empty
            : "P" + Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(Text)))[..FamilyHashLength];
    }

    /// <summary>Every port: one <c>Protocol=Any</c> rule per batch, the cheapest firewall condition.</summary>
    public static PortSet All { get; } = new([]);

    /// <summary>True when the block applies to every port.</summary>
    public bool IsAll => _ranges.Length == 0;

    /// <summary>The canonical ports and ranges, e.g. <c>21</c> and <c>50000-50100</c>; empty for all ports.</summary>
    public IReadOnlyList<string> Tokens { get; }

    /// <summary>The canonical text as the firewall's <c>LocalPorts</c> takes it; empty for all ports.</summary>
    public string Text { get; }

    /// <summary>
    /// Identifies the rules of this set in their names, so what a rule covers is known from reading
    /// it back; empty for all ports, whose rules keep their plain <c>WinGuard_Block_NNNN</c> name.
    /// </summary>
    public string RuleFamily { get; }

    /// <summary>
    /// Builds a set from <c>port</c> and <c>start-end</c> tokens, ignoring anything else. Nothing
    /// usable means all ports.
    /// </summary>
    public static PortSet Parse(IEnumerable<string>? tokens)
    {
        var ranges = new List<(int First, int Last)>();
        foreach (var token in tokens ?? [])
        {
            if (TryParseRange(token, out var first, out var last))
            {
                ranges.Add((first, last));
            }
        }

        return ranges.Count == 0 ? All : new PortSet(Merge(ranges));
    }

    /// <summary>Parses one <c>port</c> or <c>start-end</c> token; the only forms the firewall's <c>LocalPorts</c> gets.</summary>
    public static bool TryParseRange(string? token, out int first, out int last)
    {
        first = last = 0;
        var parts = token?.Trim().Split('-');
        if (parts is null || parts.Length > 2
            || !ushort.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out var start)
            || !ushort.TryParse(parts[^1], NumberStyles.None, CultureInfo.InvariantCulture, out var end)
            || start > end)
        {
            return false;
        }

        first = start;
        last = end;
        return true;
    }

    /// <summary>True when a rule name's family part is one <see cref="RuleFamily"/> can produce.</summary>
    internal static bool IsRuleFamily(string family) =>
        family.Length == FamilyHashLength + 1 && family[0] == 'P' && family.Skip(1).All(char.IsAsciiHexDigitUpper);

    /// <summary>The set covering both this one and <paramref name="other"/>; all ports when either is.</summary>
    public PortSet Union(PortSet other)
    {
        ArgumentNullException.ThrowIfNull(other);
        return IsAll || other.IsAll ? All : new PortSet(Merge(_ranges.Concat(other._ranges)));
    }

    /// <summary>True when every port of <paramref name="other"/> is in this set.</summary>
    public bool Covers(PortSet other)
    {
        ArgumentNullException.ThrowIfNull(other);
        return IsAll
            || (!other.IsAll && other._ranges.All(range => _ranges.Any(own => own.First <= range.First && range.Last <= own.Last)));
    }

    /// <inheritdoc />
    public bool Equals(PortSet? other) => other is not null && Text == other.Text;

    /// <inheritdoc />
    public override bool Equals(object? obj) => Equals(obj as PortSet);

    /// <inheritdoc />
    public override int GetHashCode() => Text.GetHashCode(StringComparison.Ordinal);

    /// <inheritdoc />
    public override string ToString() => IsAll ? "all ports" : Text;

    private static (int First, int Last)[] Merge(IEnumerable<(int First, int Last)> ranges)
    {
        var merged = new List<(int First, int Last)>();
        foreach (var range in ranges.OrderBy(r => r.First))
        {
            if (merged.Count > 0 && range.First <= merged[^1].Last + 1)
            {
                merged[^1] = (merged[^1].First, Math.Max(merged[^1].Last, range.Last));
            }
            else
            {
                merged.Add(range);
            }
        }

        return merged.ToArray();
    }

    private static string Format((int First, int Last) range) => range.First == range.Last
        ? range.First.ToString(CultureInfo.InvariantCulture)
        : string.Create(CultureInfo.InvariantCulture, $"{range.First}-{range.Last}");
}
