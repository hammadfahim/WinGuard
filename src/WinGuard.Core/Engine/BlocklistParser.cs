using System.Buffers.Binary;
using System.Globalization;
using System.Net;

namespace WinGuard.Core.Engine;

/// <summary>A run of consecutive addresses of one family, as numbers.</summary>
internal readonly record struct AddressBlock(bool IsIPv6, UInt128 First, UInt128 Last);

/// <summary>
/// Reads blocklist text and reduces it to as few firewall entries as possible. A list is third-party
/// input: nothing from it reaches the firewall except through <see cref="IpMatcher"/>'s checks.
/// </summary>
internal static class BlocklistParser
{
    private const int IPv4Bits = 32;
    private const int IPv6Bits = 128;

    // The broadest prefixes IpMatcher.IsBannableRange accepts.
    private const int MinIPv4Prefix = 8;
    private const int MinIPv6Prefix = 32;

    /// <summary>Reads one IP or CIDR per line; <c>#</c> and <c>;</c> start a comment, also after an entry.</summary>
    /// <param name="reader">The list's text.</param>
    /// <param name="skipped">Lines that held something other than a blockable entry.</param>
    public static List<AddressBlock> Parse(TextReader reader, out int skipped)
    {
        var blocks = new List<AddressBlock>();
        skipped = 0;
        while (reader.ReadLine() is { } line)
        {
            var comment = line.AsSpan().IndexOfAny('#', ';');
            var text = (comment >= 0 ? line[..comment] : line).Trim();
            if (text.Length == 0)
            {
                continue;
            }

            if (TryParseEntry(text, out var block))
            {
                blocks.Add(block);
            }
            else
            {
                skipped++;
            }
        }

        return blocks;
    }

    /// <summary>
    /// Parses one entry. Refused: anything but an IP or CIDR, an address written in a form that
    /// could mean another one (<c>010.0.0.0/8</c> is 8.0.0.0/8 to the parser), a prefix too broad for
    /// <see cref="IpMatcher.IsBannableRange"/>, and addresses that are never a client.
    /// </summary>
    public static bool TryParseEntry(string text, out AddressBlock block)
    {
        block = default;
        var slash = text.IndexOf('/');
        if (!IpMatcher.TryNormalize(slash >= 0 ? text[..slash] : text, out _)
            || !IpMatcher.TryNormalizeRange(text, out var canonical)
            || !IpMatcher.IsBannableRange(canonical)
            || !IpMatcher.IsBannable(canonical[..canonical.IndexOf('/')])
            || !IpMatcher.TryParseCidr(canonical, out var network))
        {
            return false;
        }

        var bytes = network.BaseAddress.GetAddressBytes();
        var isIPv6 = bytes.Length == IPv6Bits / 8;
        var first = isIPv6 ? BinaryPrimitives.ReadUInt128BigEndian(bytes) : BinaryPrimitives.ReadUInt32BigEndian(bytes);
        var hostBits = (isIPv6 ? IPv6Bits : IPv4Bits) - network.PrefixLength;
        block = new AddressBlock(isIPv6, first, first + ((UInt128.One << hostBits) - 1));
        return true;
    }

    /// <summary>
    /// Merges overlapping and adjacent blocks and cuts the result into CIDR blocks, none broader
    /// than a ban target may be. Over <paramref name="maxEntries"/>, the broadest blocks are kept:
    /// they cover the most addresses per firewall entry.
    /// </summary>
    /// <param name="blocks">Blocks in any order.</param>
    /// <param name="maxEntries">How many blocks may come back.</param>
    /// <param name="capped">How many were left out.</param>
    /// <returns>CIDR blocks sorted by address.</returns>
    public static List<AddressBlock> Collapse(IEnumerable<AddressBlock> blocks, int maxEntries, out int capped)
    {
        var merged = new List<AddressBlock>();
        foreach (var block in blocks.OrderBy(b => b.IsIPv6).ThenBy(b => b.First))
        {
            var mergesWithLast = merged.Count > 0
                && merged[^1].IsIPv6 == block.IsIPv6
                && (block.First <= merged[^1].Last || block.First == merged[^1].Last + 1);
            if (mergesWithLast)
            {
                merged[^1] = merged[^1] with { Last = UInt128.Max(merged[^1].Last, block.Last) };
            }
            else
            {
                merged.Add(block);
            }
        }

        var cidrs = merged.SelectMany(ToCidrBlocks).ToList();
        capped = Math.Max(0, cidrs.Count - maxEntries);
        return capped == 0
            ? cidrs
            : cidrs.OrderBy(BreadthRank).Take(maxEntries).OrderBy(b => b.IsIPv6).ThenBy(b => b.First).ToList();
    }

    /// <summary>The ban target of a CIDR block: a bare address for a single host.</summary>
    public static string ToTarget(AddressBlock block)
    {
        var bytes = new byte[block.IsIPv6 ? IPv6Bits / 8 : IPv4Bits / 8];
        if (block.IsIPv6)
        {
            BinaryPrimitives.WriteUInt128BigEndian(bytes, block.First);
        }
        else
        {
            BinaryPrimitives.WriteUInt32BigEndian(bytes, (uint)block.First);
        }

        var prefix = (block.IsIPv6 ? IPv6Bits : IPv4Bits) - HostBits(block);
        var text = new IPAddress(bytes) + "/" + prefix.ToString(CultureInfo.InvariantCulture);
        return IpMatcher.TryNormalizeBanTarget(text, out var target) ? target : text;
    }

    private static IEnumerable<AddressBlock> ToCidrBlocks(AddressBlock range)
    {
        var bits = range.IsIPv6 ? IPv6Bits : IPv4Bits;
        var widest = bits - (range.IsIPv6 ? MinIPv6Prefix : MinIPv4Prefix);
        var first = range.First;
        while (true)
        {
            // The largest block aligned on this address that stays inside the range.
            var hostBits = Math.Min(first == 0 ? bits : (int)UInt128.TrailingZeroCount(first), widest);
            var size = (UInt128.One << hostBits) - 1;
            while (size > range.Last - first)
            {
                size >>= 1;
            }

            yield return new AddressBlock(range.IsIPv6, first, first + size);
            if (first + size == range.Last)
            {
                yield break;
            }

            first += size + 1;
        }
    }

    private static int HostBits(AddressBlock block) => block.First == block.Last
        ? 0
        : IPv6Bits - (int)UInt128.LeadingZeroCount(block.Last - block.First);

    /// <summary>A block's share of its address family as a sortable number: smaller is broader.</summary>
    private static double BreadthRank(AddressBlock block)
    {
        var bits = block.IsIPv6 ? IPv6Bits : IPv4Bits;
        return (bits - HostBits(block)) / (double)bits;
    }
}
