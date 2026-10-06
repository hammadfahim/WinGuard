using WinGuard.Core.Engine;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>
/// Tests for the range helpers added in v0.2: canonical CIDR normalization, the minimum-prefix
/// guard for firewall ranges, and IPv6 /N aggregation.
/// </summary>
public sealed class IpMatcherRangeTests
{
    [Theory]
    [InlineData("203.0.113.0/24", "203.0.113.0/24")]
    [InlineData("203.0.113.99/24", "203.0.113.0/24")]       // host bits masked off
    [InlineData("2001:db8:1:2::/64", "2001:db8:1:2::/64")]
    [InlineData("2001:DB8::1/64", "2001:db8::/64")]          // canonical + lowercase
    [InlineData("203.0.113.5", "203.0.113.5/32")]            // bare IP becomes /32
    [InlineData("2001:db8::1", "2001:db8::1/128")]
    public void TryNormalizeRange_canonicalizes(string input, string expected)
    {
        Assert.True(IpMatcher.TryNormalizeRange(input, out var normalized));
        Assert.Equal(expected, normalized);
    }

    [Theory]
    [InlineData("not-an-ip")]
    [InlineData("LocalSubnet/24")]
    [InlineData("")]
    public void TryNormalizeRange_rejects_non_ip_tokens(string input)
    {
        Assert.False(IpMatcher.TryNormalizeRange(input, out _));
    }

    [Theory]
    [InlineData("203.0.113.0/24", true)]
    [InlineData("10.0.0.0/8", true)]
    [InlineData("2001:db8:1:2::/64", true)]
    [InlineData("2001:db8::/32", true)]
    [InlineData("0.0.0.0/0", false)]       // over-broad: whole internet
    [InlineData("0.0.0.0/7", false)]       // shorter than /8
    [InlineData("2000::/16", false)]       // shorter than /32
    [InlineData("203.0.113.0/33", false)]  // invalid prefix
    public void IsBannableRange_enforces_the_minimum_prefix(string range, bool expected)
    {
        Assert.Equal(expected, IpMatcher.IsBannableRange(range));
    }

    [Theory]
    [InlineData("2001:db8:1:2:3:4:5:6", 64, "2001:db8:1:2::/64")]
    [InlineData("2001:db8:1:2:3:4:5:6", 48, "2001:db8:1::/48")]
    [InlineData("2001:db8:1:2:8000::", 64, "2001:db8:1:2::/64")]
    public void TryAggregateIpv6_masks_to_the_prefix(string address, int prefix, string expected)
    {
        Assert.True(IpMatcher.TryAggregateIpv6(address, prefix, out var aggregated));
        Assert.Equal(expected, aggregated);
    }

    [Theory]
    [InlineData("203.0.113.5", 64)]      // IPv4 is never aggregated
    [InlineData("2001:db8::1", 0)]       // 0 disables
    [InlineData("2001:db8::1", 16)]      // shorter than /32 is refused
    [InlineData("2001:db8::1", 129)]     // longer than /128 is refused
    [InlineData("garbage", 64)]
    public void TryAggregateIpv6_rejects_unsupported_inputs(string address, int prefix)
    {
        Assert.False(IpMatcher.TryAggregateIpv6(address, prefix, out _));
    }
}
