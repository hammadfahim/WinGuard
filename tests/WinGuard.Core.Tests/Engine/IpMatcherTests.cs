using WinGuard.Core.Engine;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>Tests for IP/CIDR parsing, validation and list matching (PLAN.md §5).</summary>
public sealed class IpMatcherTests
{
    // ---------- TryNormalize ----------

    [Theory]
    [InlineData("1.2.3.4", "1.2.3.4")]
    [InlineData("1.2.3.4:5678", "1.2.3.4")]
    [InlineData("203.0.113.45:52914", "203.0.113.45")]
    [InlineData("::1", "::1")]
    [InlineData("[::1]", "::1")]
    [InlineData("[2001:DB8::1]:3389", "2001:db8::1")]
    [InlineData("2001:DB8::1", "2001:db8::1")]
    [InlineData("::ffff:203.0.113.5", "203.0.113.5")]
    [InlineData("0:0:0:0:0:ffff:203.0.113.5", "203.0.113.5")]
    [InlineData("[::ffff:203.0.113.5]:3389", "203.0.113.5")]
    public void TryNormalize_accepts_and_normalizes(string raw, string expected)
    {
        Assert.True(IpMatcher.TryNormalize(raw, out var normalized));
        Assert.Equal(expected, normalized);
    }

    [Theory]
    [InlineData("-")]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("LocalSubnet")]
    [InlineData("example.com")]
    [InlineData("999.1.1.1")]
    [InlineData("not an ip")]
    public void TryNormalize_rejects_non_ips(string? raw)
    {
        Assert.False(IpMatcher.TryNormalize(raw, out _));
    }

    [Fact]
    public void IsValid_delegates_to_normalization()
    {
        Assert.True(IpMatcher.IsValid("1.2.3.4"));
        Assert.True(IpMatcher.IsValid("2001:db8::1"));
        Assert.False(IpMatcher.IsValid("LocalSubnet"));
        Assert.False(IpMatcher.IsValid("-"));
        Assert.False(IpMatcher.IsValid(string.Empty));
    }

    // ---------- IsInternal ----------

    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("10.1.2.3", true)]
    [InlineData("192.168.1.1", true)]
    [InlineData("172.16.0.1", true)]
    [InlineData("169.254.1.1", true)]
    [InlineData("::1", true)]
    [InlineData("fc00::1", true)]
    [InlineData("fd12:3456::1", true)]
    [InlineData("fe80::1", true)]
    [InlineData("8.8.8.8", false)]
    [InlineData("203.0.113.1", false)]
    [InlineData("100.63.255.255", false)]
    [InlineData("100.64.0.0", true)]
    [InlineData("100.100.100.100", true)] // a Tailscale peer
    [InlineData("100.127.255.255", true)]
    [InlineData("100.128.0.0", false)]
    [InlineData("198.17.255.255", false)]
    [InlineData("198.18.0.1", true)]
    [InlineData("198.19.255.255", true)]
    [InlineData("198.20.0.0", false)]
    [InlineData("::ffff:100.64.0.1", true)]
    [InlineData("64:ff9b::808:808", false)]    // NAT64 of 8.8.8.8: a real client behind a translator
    [InlineData("64:ff9b::a00:1", true)]       // NAT64 of 10.0.0.1
    [InlineData("64:ff9b::6440:1", true)]      // NAT64 of 100.64.0.1
    [InlineData("64:ff9b:0:1::808:808", false)] // outside the /96
    public void IsInternal_cases(string ip, bool expected)
    {
        Assert.Equal(expected, IpMatcher.IsInternal(ip));
    }

    // ---------- TryParseCidr ----------

    [Fact]
    public void TryParseCidr_parses_v4_v6_and_bare_hosts()
    {
        Assert.True(IpMatcher.TryParseCidr("10.0.0.0/8", out var v4));
        Assert.Equal(8, v4.PrefixLength);

        Assert.True(IpMatcher.TryParseCidr("1.2.3.4", out var host));
        Assert.Equal(32, host.PrefixLength);

        Assert.True(IpMatcher.TryParseCidr("2001:db8::/32", out var v6));
        Assert.Equal(32, v6.PrefixLength);

        Assert.False(IpMatcher.TryParseCidr("not-a-cidr", out _));
    }

    [Theory]
    [InlineData("203.0.113.7/32", "203.0.113.7")]
    [InlineData("2001:db8::1/128", "2001:db8::1")]
    [InlineData("203.0.113.0/24", "203.0.113.0/24")]
    [InlineData("2001:db8::/32", "2001:db8::/32")] // 2^96 addresses, whatever the number looks like
    [InlineData("2001:db8:1:2::/64", "2001:db8:1:2::/64")]
    public void Only_a_true_single_host_cidr_folds_to_a_bare_address(string value, string expected)
    {
        Assert.True(IpMatcher.TryNormalizeBanTarget(value, out var target));
        Assert.Equal(expected, target);
    }

    // ---------- Instance list matching ----------

    [Fact]
    public void Whitelist_cidr_matches_members()
    {
        var matcher = new IpMatcher(new[] { "10.0.0.0/8" }, Array.Empty<string>());

        Assert.True(matcher.IsWhitelisted("10.1.2.3"));
        Assert.False(matcher.IsWhitelisted("11.1.2.3"));
    }

    [Fact]
    public void Blacklist_single_ip_matches_exactly()
    {
        var matcher = new IpMatcher(Array.Empty<string>(), new[] { "203.0.113.7" });

        Assert.True(matcher.IsBlacklisted("203.0.113.7"));
        Assert.False(matcher.IsBlacklisted("203.0.113.8"));
    }

    [Fact]
    public void Whitelist_wins_over_blacklist()
    {
        var matcher = new IpMatcher(new[] { "203.0.113.5" }, new[] { "203.0.113.5" });

        // The matcher must report the whitelist hit; the engine consults it first
        // (PLAN.md §5 step 2) and never blocks a whitelisted address.
        Assert.True(matcher.IsWhitelisted("203.0.113.5"));
    }

    [Fact]
    public void Ipv6_cidr_membership_works()
    {
        var matcher = new IpMatcher(new[] { "2001:db8::/32" }, Array.Empty<string>());

        Assert.True(matcher.IsWhitelisted("2001:db8:abcd::1"));
        Assert.False(matcher.IsWhitelisted("2001:db9::1"));
    }

    [Fact]
    public void Invalid_entries_are_ignored_without_throwing()
    {
        var matcher = new IpMatcher(
            new[] { "not-an-ip", "LocalSubnet", "1.2.3.4" },
            new[] { "-", "example.com" });

        Assert.True(matcher.IsWhitelisted("1.2.3.4"));
        Assert.False(matcher.IsBlacklisted("8.8.8.8"));
        Assert.False(matcher.IsWhitelisted("8.8.8.8"));
    }

    [Fact]
    public void Whitelist_ipv4_entry_matches_mapped_ipv6_form()
    {
        // Review S-M6: ::ffff:a.b.c.d must canonicalize to plain IPv4 so a whitelist
        // entry can never be bypassed by the mapped form (PLAN §11).
        var matcher = new IpMatcher(new[] { "203.0.113.5" }, Array.Empty<string>());

        Assert.True(IpMatcher.TryNormalize("::ffff:203.0.113.5", out var normalized));
        Assert.Equal("203.0.113.5", normalized);
        Assert.True(matcher.IsWhitelisted(normalized));
    }
}