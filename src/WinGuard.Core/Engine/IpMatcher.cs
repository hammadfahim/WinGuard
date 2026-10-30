using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace WinGuard.Core.Engine;

/// <summary>
/// IP validation and whitelist/blacklist matching (PLAN.md §5, §11).
/// <para>
/// All matching is textual/no-DNS: a value is accepted only when it is already an
/// IPv4 or IPv6 literal (optionally with a port / brackets). Hostnames and firewall
/// tokens such as <c>LocalSubnet</c> are rejected so they can never reach the firewall.
/// </para>
/// <para>
/// Whitelist always wins over blacklist. Invalid list entries are ignored rather than
/// aborting construction.
/// </para>
/// </summary>
public sealed class IpMatcher
{
    private static readonly IPNetwork Nat64Prefix = IPNetwork.Parse("64:ff9b::/96");

    private readonly List<IPNetwork> _whitelist = [];
    private readonly List<IPNetwork> _blacklist = [];

    /// <summary>
    /// Creates a matcher from raw list entries. Each entry may be a single IP or a CIDR.
    /// Entries that are not valid IP/CIDR tokens are silently ignored.
    /// </summary>
    /// <param name="whitelist">Whitelist entries (IP or CIDR).</param>
    /// <param name="blacklist">Blacklist entries (IP or CIDR).</param>
    public IpMatcher(IEnumerable<string>? whitelist, IEnumerable<string>? blacklist)
    {
        Load(whitelist, _whitelist);
        Load(blacklist, _blacklist);
    }

    /// <summary>
    /// Normalizes a user/log supplied value into a bare IP string: strips an optional
    /// IPv4 <c>:port</c>, strips <c>[brackets]</c> and a following <c>:port</c>, lowercases
    /// IPv6, drops any IPv6 scope id. Returns <see langword="false"/> for null/empty,
    /// <c>"-"</c>, hostnames and firewall tokens. Never performs DNS resolution.
    /// </summary>
    /// <param name="raw">The raw value (may include port/brackets).</param>
    /// <param name="normalized">The bare normalized IP when the method returns <see langword="true"/>.</param>
    /// <returns><see langword="true"/> when <paramref name="raw"/> is a valid IP literal.</returns>
    public static bool TryNormalize(string? raw, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(raw))
        {
            return false;
        }

        var candidate = raw.Trim();
        if (candidate == "-")
        {
            return false;
        }

        if (candidate.Length > 1 && candidate[0] == '[')
        {
            // [ipv6] or [ipv6]:port
            var end = candidate.IndexOf(']');
            if (end <= 1)
            {
                return false;
            }

            var after = candidate[(end + 1)..];
            if (after.Length != 0 &&
                (after[0] != ':' || !int.TryParse(after.AsSpan(1), NumberStyles.None, CultureInfo.InvariantCulture, out _)))
            {
                return false;
            }

            candidate = candidate[1..end];
        }
        else
        {
            // Bare IPv4 with a port: exactly one colon and the host part is an IPv4 literal.
            var firstColon = candidate.IndexOf(':');
            if (firstColon >= 0 && candidate.IndexOf(':', firstColon + 1) < 0)
            {
                var hostPart = candidate[..firstColon];
                var portPart = candidate[(firstColon + 1)..];
                if (IPAddress.TryParse(hostPart, out var hostAddress) &&
                    hostAddress.AddressFamily == AddressFamily.InterNetwork &&
                    int.TryParse(portPart, NumberStyles.None, CultureInfo.InvariantCulture, out _))
                {
                    candidate = hostPart;
                }
            }
        }

        if (!IPAddress.TryParse(candidate, out var address))
        {
            return false;
        }

        // Reject legacy IPAddress.TryParse short forms such as "1.2.3" (=> 1.2.0.3)
        // so crafted log values cannot smuggle in an unexpected address.
        if (address.AddressFamily == AddressFamily.InterNetwork && !IsCanonicalIPv4(candidate))
        {
            return false;
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6 && address.ScopeId != 0)
        {
            // Drop the scope id; a bare address is what the firewall/DB should hold.
            address = new IPAddress(address.GetAddressBytes());
        }

        if (address.IsIPv4MappedToIPv6)
        {
            // Canonicalize ::ffff:a.b.c.d to plain IPv4 so whitelist/bans/firewall see a
            // single identity per address (a mapped form must not bypass an IPv4 whitelist).
            address = address.MapToIPv4();
        }

        normalized = address.ToString().ToLowerInvariant();
        return true;
    }

    /// <summary>Returns <see langword="true"/> when <paramref name="ip"/> normalizes to a valid IP literal.</summary>
    public static bool IsValid(string ip) => TryNormalize(ip, out _);

    /// <summary>
    /// Normalizes a CIDR entry into its canonical text form (network address + "/prefix",
    /// e.g. <c>203.0.113.0/24</c> or <c>2001:db8::/64</c>). Host bits are masked off. A bare
    /// IP is accepted and returns <c>ip/32</c> (IPv4) or <c>ip/128</c> (IPv6). Returns
    /// <see langword="false"/> for anything that is not an IP or CIDR literal.
    /// </summary>
    public static bool TryNormalizeRange(string? cidr, out string normalized)
    {
        normalized = string.Empty;
        if (!TryParseCidr(cidr, out var network) || network.BaseAddress is not { } baseAddress)
        {
            return false;
        }

        normalized = baseAddress.ToString().ToLowerInvariant() + "/" + network.PrefixLength.ToString(CultureInfo.InvariantCulture);
        return true;
    }

    /// <summary>
    /// True for a canonical CIDR text produced by <see cref="TryNormalizeRange"/> whose prefix is at
    /// least /8 (IPv4) or /32 (IPv6): the minimum WinGuard accepts for a firewall range entry, so a
    /// crafted value can never collapse the whole internet into one rule.
    /// </summary>
    public static bool IsBannableRange(string normalizedRange)
    {
        if (!TryNormalizeRange(normalizedRange, out var canonical))
        {
            return false;
        }

        var slash = canonical.IndexOf('/');
        if (!IPAddress.TryParse(canonical[..slash], out var address))
        {
            return false;
        }

        var prefix = int.Parse(canonical[(slash + 1)..], CultureInfo.InvariantCulture);
        var isIPv6 = address.AddressFamily == AddressFamily.InterNetworkV6;
        var minimum = isIPv6 ? 32 : 8;
        return prefix >= minimum && prefix <= (isIPv6 ? 128 : 32);
    }

    /// <summary>
    /// Normalizes a ban target: a single host IP (bare form) or a canonical CIDR range that passes
    /// <see cref="IsBannableRange"/>. A /32 or /128 "range" folds to the bare host so the same
    /// address always has one identity. Firewall tokens, hostnames and over-broad prefixes are rejected.
    /// </summary>
    /// <param name="value">The raw host or CIDR value.</param>
    /// <param name="target">The normalized target when the method returns <see langword="true"/>.</param>
    public static bool TryNormalizeBanTarget(string? value, out string target)
    {
        if (TryNormalize(value, out var host))
        {
            target = host;
            return true;
        }

        if (TryNormalizeRange(value, out var range) && IsBannableRange(range))
        {
            // Single-host CIDR forms collapse to the bare host identity.
            var slash = range.IndexOf('/');
            if (int.TryParse(range[(slash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out var prefix)
                && (prefix == 32 || prefix == 128)
                && TryNormalize(range[..slash], out var single))
            {
                target = single;
                return true;
            }

            target = range;
            return true;
        }

        target = string.Empty;
        return false;
    }

    /// <summary>
    /// Aggregates an IPv6 host address to its /N network prefix in canonical form
    /// (<c>2001:db8:1:2:3:4:5:6</c> with prefix 64 → <c>2001:db8:1:2::/64</c>). IPv4 inputs return
    /// <see langword="false"/> (IPv4 aggregation is not supported; attackers do not rotate /24s the
    /// way IPv6 clients rotate /64 interface identifiers).
    /// </summary>
    /// <param name="normalizedIp">A normalized IPv6 host address.</param>
    /// <param name="prefixLength">Target prefix length, 32..128.</param>
    /// <param name="prefix">Canonical prefix text (e.g. <c>2001:db8:1:2::/64</c>).</param>
    public static bool TryAggregateIpv6(string normalizedIp, int prefixLength, out string prefix)
    {
        prefix = string.Empty;
        if (prefixLength is < 32 or > 128
            || !IPAddress.TryParse(normalizedIp, out var address)
            || address.AddressFamily != AddressFamily.InterNetworkV6
            || address.IsIPv4MappedToIPv6)
        {
            return false;
        }

        prefix = new IPNetwork(MaskAddress(address, prefixLength), prefixLength).ToString().ToLowerInvariant();
        return true;
    }

    /// <summary>
    /// Returns <see langword="true"/> for addresses the public internet cannot be the source of:
    /// loopback (127.0.0.0/8, ::1), RFC1918 (10/8, 172.16/12, 192.168/16), link-local (169.254/16,
    /// fe80::/10), carrier-grade NAT (100.64/10, RFC 6598: ISP subscribers, Tailscale peers),
    /// benchmarking (198.18/15, RFC 2544: never routed publicly, so seen only from test labs and
    /// vendors' internal fabrics), IPv6 unique-local (fc00::/7) and site-local (fec0::/10).
    /// <para>
    /// NAT64 (64:ff9b::/96, RFC 6052) is deliberately not internal as a whole: such an address is a
    /// real IPv4 client seen through a translator, possibly an attacker on the internet. The IPv4
    /// address embedded in its last 32 bits decides.
    /// </para>
    /// </summary>
    /// <param name="normalizedIp">An IP literal (normalized or not).</param>
    public static bool IsInternal(string normalizedIp)
    {
        if (!TryNormalize(normalizedIp, out var value) || !IPAddress.TryParse(value, out var address))
        {
            return false;
        }

        if (IPAddress.IsLoopback(address))
        {
            return true;
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = address.GetAddressBytes();
            return bytes[0] == 10
                || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                || (bytes[0] == 192 && bytes[1] == 168)
                || (bytes[0] == 169 && bytes[1] == 254)
                || (bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127)
                || (bytes[0] == 198 && bytes[1] is 18 or 19);
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6UniqueLocal)
            {
                return true;
            }

            if (address.IsIPv4MappedToIPv6)
            {
                return IsInternal(address.MapToIPv4().ToString());
            }

            if (Nat64Prefix.Contains(address))
            {
                return IsInternal(new IPAddress(address.GetAddressBytes()[12..]).ToString());
            }
        }

        return false;
    }

    /// <summary>
    /// False for addresses that can never be a remote client and must not reach the ban list or
    /// the firewall: unspecified (0.0.0.0, ::), IPv4 broadcast and multicast.
    /// </summary>
    /// <param name="ip">An IP literal (normalized or not).</param>
    public static bool IsBannable(string ip)
    {
        if (!TryNormalize(ip, out var value) || !IPAddress.TryParse(value, out var address))
        {
            return false;
        }

        if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) || address.Equals(IPAddress.Broadcast))
        {
            return false;
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var first = address.GetAddressBytes()[0];
            return first is not (0 or >= 224 and <= 239);
        }

        return !address.IsIPv6Multicast;
    }

    /// <summary>
    /// Parses an entry into an <see cref="IPNetwork"/>: either a CIDR (<c>1.2.3.0/24</c>)
    /// or a bare IP (treated as <c>/32</c> or <c>/128</c>). Host bits set in a CIDR
    /// (e.g. <c>192.168.1.5/24</c>) are masked to the network address so admin-entered
    /// ranges behave intuitively. Invalid tokens return <see langword="false"/>.
    /// </summary>
    public static bool TryParseCidr(string? cidr, out IPNetwork network)
    {
        network = default;
        if (string.IsNullOrWhiteSpace(cidr))
        {
            return false;
        }

        var text = cidr.Trim();
        if (text.Contains('/'))
        {
            try
            {
                if (IPNetwork.TryParse(text, out network))
                {
                    return true;
                }
            }
            catch (Exception)
            {
                // Fall through to the lenient masking path below.
            }

            var slash = text.LastIndexOf('/');
            var addressPart = text[..slash];
            var prefixPart = text[(slash + 1)..];
            if (!TryNormalize(addressPart, out var addressText) ||
                !IPAddress.TryParse(addressText, out var address) ||
                !int.TryParse(prefixPart, NumberStyles.None, CultureInfo.InvariantCulture, out var prefix))
            {
                return false;
            }

            var maxBits = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            if (prefix < 0 || prefix > maxBits)
            {
                return false;
            }

            try
            {
                network = new IPNetwork(MaskAddress(address, prefix), prefix);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        if (!TryNormalize(text, out var bare) || !IPAddress.TryParse(bare, out var single))
        {
            return false;
        }

        var hostBits = single.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        try
        {
            network = new IPNetwork(single, hostBits);
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>
    /// Returns the machine's operational unicast addresses plus loopback (127.0.0.1, ::1),
    /// normalized. Used to auto-whitelist the host so it can never lock itself out (PLAN.md §5).
    /// Uses <see cref="NetworkInterface"/> only; no name resolution.
    /// </summary>
    public static IReadOnlyList<string> GetLocalAddresses()
    {
        var results = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Add(string? value)
        {
            if (TryNormalize(value, out var normalized) && seen.Add(normalized))
            {
                results.Add(normalized);
            }
        }

        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up)
                {
                    continue;
                }

                if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                {
                    continue;
                }

                foreach (var unicast in nic.GetIPProperties().UnicastAddresses)
                {
                    Add(unicast.Address?.ToString());
                }
            }
        }
        catch (Exception)
        {
            // Network enumeration can fail on locked-down hosts; loopback is still added below.
        }

        Add("127.0.0.1");
        Add("::1");
        return results;
    }

    /// <summary>True when <paramref name="normalizedIp"/> falls inside any whitelist entry.</summary>
    public bool IsWhitelisted(string normalizedIp) => Matches(_whitelist, normalizedIp);

    /// <summary>True when <paramref name="normalizedIp"/> falls inside any blacklist entry.</summary>
    public bool IsBlacklisted(string normalizedIp) => Matches(_blacklist, normalizedIp);

    /// <summary>
    /// True when any address of <paramref name="normalizedRange"/> is whitelisted. A firewall block
    /// rule beats every allow rule, so a range for which this is true would block a whitelisted address.
    /// </summary>
    /// <param name="normalizedRange">A CIDR range (or bare IP).</param>
    public bool OverlapsWhitelist(string normalizedRange) =>
        TryParseCidr(normalizedRange, out var range) && _whitelist.Any(entry => Overlap(entry, range));

    /// <summary>
    /// Splits <paramref name="normalizedRange"/> into the smallest set of ban targets that covers
    /// the range except its whitelisted addresses: the range itself when nothing in it is
    /// whitelisted, nothing when all of it is. Every target has a longer prefix than the range, so
    /// it still satisfies <see cref="IsBannableRange"/>, and single addresses come back bare.
    /// </summary>
    /// <param name="normalizedRange">A canonical CIDR range.</param>
    public IReadOnlyList<string> SubtractWhitelist(string normalizedRange)
    {
        var targets = new List<string>();
        if (TryParseCidr(normalizedRange, out var range))
        {
            Subtract(range, _whitelist.Where(entry => Overlap(entry, range)).ToList(), targets);
        }

        return targets;
    }

    private static void Subtract(IPNetwork network, List<IPNetwork> holes, List<string> targets)
    {
        if (holes.Any(hole => hole.PrefixLength <= network.PrefixLength && hole.Contains(network.BaseAddress)))
        {
            return;
        }

        if (!holes.Any(hole => network.Contains(hole.BaseAddress)))
        {
            targets.Add(TryNormalizeBanTarget(network.ToString(), out var target) ? target : network.ToString().ToLowerInvariant());
            return;
        }

        // Halve the network and keep going on the side(s) that still hold a whitelisted address.
        var prefix = network.PrefixLength + 1;
        var upper = network.BaseAddress.GetAddressBytes();
        upper[network.PrefixLength / 8] |= (byte)(0x80 >> (network.PrefixLength % 8));
        Subtract(new IPNetwork(network.BaseAddress, prefix), holes, targets);
        Subtract(new IPNetwork(new IPAddress(upper), prefix), holes, targets);
    }

    private static bool Overlap(IPNetwork a, IPNetwork b) => a.Contains(b.BaseAddress) || b.Contains(a.BaseAddress);

    private static bool Matches(List<IPNetwork> networks, string ip)
    {
        if (networks.Count == 0 || !TryNormalize(ip, out var normalized) || !IPAddress.TryParse(normalized, out var address))
        {
            return false;
        }

        foreach (var network in networks)
        {
            if (network.BaseAddress is { } baseAddress && baseAddress.AddressFamily == address.AddressFamily && network.Contains(address))
            {
                return true;
            }
        }

        return false;
    }

    private static void Load(IEnumerable<string>? entries, List<IPNetwork> target)
    {
        if (entries is null)
        {
            return;
        }

        foreach (var entry in entries)
        {
            if (TryParseCidr(entry, out var network))
            {
                target.Add(network);
            }
        }
    }

    private static bool IsCanonicalIPv4(string value)
    {
        var parts = value.Split('.');
        if (parts.Length != 4)
        {
            return false;
        }

        foreach (var part in parts)
        {
            if (part.Length is 0 or > 3)
            {
                return false;
            }

            // IPAddress.TryParse reads a leading zero as octal ("010.1.1.1" => 8.1.1.1).
            if (part.Length > 1 && part[0] == '0')
            {
                return false;
            }

            foreach (var c in part)
            {
                if (!char.IsAsciiDigit(c))
                {
                    return false;
                }
            }
        }

        return true;
    }

    private static IPAddress MaskAddress(IPAddress address, int prefixLength)
    {
        var bytes = address.GetAddressBytes();
        for (var i = 0; i < bytes.Length; i++)
        {
            var bitStart = i * 8;
            if (bitStart >= prefixLength)
            {
                bytes[i] = 0;
                continue;
            }

            var remaining = prefixLength - bitStart;
            if (remaining >= 8)
            {
                continue;
            }

            var mask = (byte)(0xFF << (8 - remaining));
            bytes[i] = (byte)(bytes[i] & mask);
        }

        return new IPAddress(bytes);
    }
}