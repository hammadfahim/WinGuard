using System.Globalization;
using System.Net;
using System.Net.Sockets;
using WinGuard.Core.Engine;

namespace WinGuard.Gui.Services;

/// <summary>What a list entry or ban target is, for labels, sorting and confirmation summaries.</summary>
/// <param name="IsValid">Whether the text is an address or a CIDR range at all.</param>
/// <param name="IsRange">True for a prefix that covers more than one address.</param>
/// <param name="IsIpv6">True for IPv6.</param>
/// <param name="Prefix">Prefix length (32 or 128 for a single address).</param>
/// <param name="Canonical">Normalized text (a bare address, or network/prefix).</param>
public readonly record struct IpShape(bool IsValid, bool IsRange, bool IsIpv6, int Prefix, string Canonical);

/// <summary>
/// Reads addresses and prefixes for display. A ban can be a whole IPv6 prefix such as
/// 2001:db8:1:2::/64, so nothing here assumes a row holds one address.
/// </summary>
public static class IpText
{
    /// <summary>Classifies a host or CIDR text.</summary>
    public static IpShape Shape(string? text)
    {
        if (!IpMatcher.TryParseCidr(text, out var network) || network.BaseAddress is not { } address)
        {
            return default;
        }

        var isIpv6 = address.AddressFamily == AddressFamily.InterNetworkV6;
        var full = isIpv6 ? 128 : 32;
        var isRange = network.PrefixLength < full;
        var canonical = isRange
            ? address.ToString().ToLowerInvariant() + "/" + network.PrefixLength.ToString(CultureInfo.InvariantCulture)
            : address.ToString().ToLowerInvariant();
        return new IpShape(true, isRange, isIpv6, network.PrefixLength, canonical);
    }

    /// <summary>"IPv4", "IPv6", "IPv4 /24", "IPv6 /64".</summary>
    public static string KindLabel(IpShape shape)
    {
        if (!shape.IsValid)
        {
            return string.Empty;
        }

        var family = shape.IsIpv6 ? "IPv6" : "IPv4";
        return shape.IsRange ? $"{family} /{shape.Prefix}" : family;
    }

    /// <summary>"1 address", "256 addresses", "2^64 addresses".</summary>
    public static string CoverageLabel(IpShape shape)
    {
        if (!shape.IsValid)
        {
            return string.Empty;
        }

        if (!shape.IsRange)
        {
            return "1 address";
        }

        var hostBits = (shape.IsIpv6 ? 128 : 32) - shape.Prefix;
        return hostBits <= 24
            ? (1L << hostBits).ToString("N0", CultureInfo.CurrentCulture) + " addresses"
            : $"2^{hostBits} addresses";
    }

    /// <summary>
    /// A value that orders addresses numerically instead of as text, IPv4 before IPv6, so 9.9.9.9 sorts
    /// before 10.0.0.1. Prefixes sort by their network address.
    /// </summary>
    public static UInt128 SortKey(string? text)
    {
        var address = IpMatcher.TryParseCidr(text, out var network) && network.BaseAddress is { } parsed ? parsed : null;
        if (address is null)
        {
            return UInt128.MaxValue;
        }

        var bytes = address.GetAddressBytes();
        var value = UInt128.Zero;
        foreach (var part in bytes)
        {
            value = (value << 8) | part;
        }

        // IPv4 occupies the low 32 bits; a set top bit keeps every IPv6 address after them.
        return address.AddressFamily == AddressFamily.InterNetwork ? value : value | (UInt128.One << 127);
    }

    /// <summary>True for a private, loopback or link-local address, which is worth a second look before blocking.</summary>
    public static bool IsInternal(string? text) => IpMatcher.TryNormalize(text, out var ip) && IpMatcher.IsInternal(ip);
}
