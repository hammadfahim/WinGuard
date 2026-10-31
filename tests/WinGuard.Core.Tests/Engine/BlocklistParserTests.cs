using WinGuard.Core.Engine;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>Turning blocklist text into as few firewall entries as possible, and refusing the rest.</summary>
public sealed class BlocklistParserTests
{
    [Fact]
    public void A_spamhaus_style_list_is_read()
    {
        const string List = """
            ; Spamhaus DROP List 2026/05/01 - (c) 2026 The Spamhaus Project
            ; Last-Modified: Fri, 01 May 2026 08:15:00 GMT
            1.10.16.0/20 ; SBL256894
            1.19.0.0/16 ; SBL434604

            # our own additions
            203.0.113.7   # seen in the logs
            2001:db8::/32 ; v6
            """;

        var (targets, skipped) = Parse(List);

        Assert.Equal(["1.10.16.0/20", "1.19.0.0/16", "203.0.113.7", "2001:db8::/32"], targets);
        Assert.Equal(0, skipped);
    }

    [Fact]
    public void Blank_and_comment_lines_are_not_counted_as_skipped()
    {
        var (targets, skipped) = Parse("\n   \n# one\n; two\n\t# three\n");

        Assert.Empty(targets);
        Assert.Equal(0, skipped);
    }

    [Theory]
    [InlineData("not an address")]
    [InlineData("example.com")]
    [InlineData("LocalSubnet")]
    [InlineData("*")]
    [InlineData("1.2.3")]
    [InlineData("1.2.3/24")]
    [InlineData("999.1.1.1")]
    [InlineData("1.2.3.0/33")]
    [InlineData("1.2.3.0/-1")]
    [InlineData("1.2.3.0/")]
    [InlineData("/24")]
    [InlineData("1.2.3.4 1.2.3.5")]
    [InlineData("1.2.3.0/24 SBL123")]
    [InlineData("1.2.3.4-1.2.3.9")]
    [InlineData("<html>")]
    public void Anything_but_one_ip_or_cidr_is_skipped_and_counted(string line)
    {
        var (targets, skipped) = Parse(line);

        Assert.Empty(targets);
        Assert.Equal(1, skipped);
    }

    [Theory]
    [InlineData("0.0.0.0/0")]
    [InlineData("1.0.0.0/7")]
    [InlineData("128.0.0.0/1")]
    [InlineData("::/0")]
    [InlineData("2000::/31")]
    public void A_prefix_too_broad_to_ban_is_skipped(string line)
    {
        var (targets, skipped) = Parse(line);

        Assert.Empty(targets);
        Assert.Equal(1, skipped);
    }

    [Theory]
    [InlineData("0.0.0.0")]
    [InlineData("255.255.255.255")]
    [InlineData("224.0.0.1")]
    [InlineData("0.0.0.0/8")]
    [InlineData("224.0.0.0/8")]
    [InlineData("::")]
    [InlineData("ff02::1")]
    public void Addresses_that_are_never_a_client_are_skipped(string line)
    {
        Assert.Equal(1, Parse(line).Skipped);
    }

    [Theory]
    [InlineData("010.0.0.0/8")] // 8.0.0.0/8 to the address parser: the wrong network entirely
    [InlineData("010.1.2.3")]
    [InlineData("0x7f.0.0.1")]
    public void An_address_written_so_it_could_mean_another_one_is_skipped(string line)
    {
        var (targets, skipped) = Parse(line);

        Assert.Empty(targets);
        Assert.Equal(1, skipped);
    }

    [Fact]
    public void Host_bits_in_a_cidr_are_masked()
    {
        Assert.Equal(["1.2.3.0/24"], Parse("1.2.3.4/24").Targets);
    }

    [Fact]
    public void A_single_host_cidr_comes_back_bare()
    {
        Assert.Equal(["1.2.3.4", "2001:db8::1"], Parse("1.2.3.4/32\n2001:db8::1/128").Targets);
    }

    [Fact]
    public void Ipv6_is_compared_as_numbers_not_text()
    {
        Assert.Equal(["2001:db8::/32"], Parse("2001:DB8:0:0::/32\n2001:db8:1::/48").Targets);
    }

    [Fact]
    public void Overlapping_entries_collapse()
    {
        Assert.Equal(["1.2.3.0/24"], Parse("1.2.3.128/25\n1.2.3.0/24\n1.2.3.4\n1.2.3.4").Targets);
    }

    [Fact]
    public void Adjacent_entries_collapse()
    {
        Assert.Equal(["1.2.2.0/23"], Parse("1.2.3.0/24\n1.2.2.0/24").Targets);
        Assert.Equal(["1.2.3.4/31"], Parse("1.2.3.4\n1.2.3.5").Targets);
    }

    [Fact]
    public void Adjacent_entries_that_are_no_single_cidr_stay_apart_in_as_few_as_possible()
    {
        Assert.Equal(["1.2.3.0/24", "1.2.4.0/24"], Parse("1.2.3.0/24\n1.2.4.0/24").Targets);
        Assert.Equal(["1.2.3.5", "1.2.3.6/31", "1.2.3.8"], Parse("1.2.3.5\n1.2.3.6\n1.2.3.7\n1.2.3.8").Targets);
    }

    [Fact]
    public void Collapsing_never_produces_a_prefix_too_broad_to_ban()
    {
        // Merged they would be 8.0.0.0/7, which the firewall layer refuses: the whole entry would vanish.
        Assert.Equal(["8.0.0.0/8", "9.0.0.0/8"], Parse("8.0.0.0/8\n9.0.0.0/8").Targets);
        Assert.Equal(["2001:db8::/32", "2001:db9::/32"], Parse("2001:db8::/32\n2001:db9::/32").Targets);
    }

    [Fact]
    public void A_long_run_of_broad_blocks_all_stay_valid_ban_targets()
    {
        var list = string.Join('\n', Enumerable.Range(1, 100).Select(octet => $"{octet}.0.0.0/8"));

        var targets = Parse(list).Targets;

        Assert.Equal(100, targets.Count);
        Assert.All(targets, target => Assert.True(IpMatcher.TryNormalizeBanTarget(target, out _), target));
    }

    [Fact]
    public void The_two_address_families_never_merge()
    {
        // Numerically consecutive, but ::1.0.0.1 is not the address after 1.0.0.0.
        Assert.Equal(["1.0.0.0", "::1.0.0.1"], Parse("1.0.0.0\n::1.0.0.1").Targets);
    }

    [Fact]
    public void The_top_of_the_ipv6_space_does_not_overflow()
    {
        var blocks = new[]
        {
            new AddressBlock(true, UInt128.MaxValue - 3, UInt128.MaxValue - 2),
            new AddressBlock(true, UInt128.MaxValue - 1, UInt128.MaxValue),
        };

        var collapsed = BlocklistParser.Collapse(blocks, 10, out var capped);

        Assert.Equal(new AddressBlock(true, UInt128.MaxValue - 3, UInt128.MaxValue), Assert.Single(collapsed));
        Assert.Equal(0, capped);
    }

    [Fact]
    public void The_cap_keeps_the_entries_covering_the_most_addresses()
    {
        var blocks = BlocklistParser.Parse(new StringReader("9.9.9.9\n1.2.3.0/24\n5.5.5.0/25\n7.7.7.7"), out _);

        var collapsed = BlocklistParser.Collapse(blocks, 2, out var capped);

        Assert.Equal(["1.2.3.0/24", "5.5.5.0/25"], collapsed.Select(BlocklistParser.ToTarget));
        Assert.Equal(2, capped);
    }

    [Fact]
    public void The_cap_counts_firewall_entries_after_collapsing()
    {
        var blocks = BlocklistParser.Parse(new StringReader("1.2.2.0/24\n1.2.3.0/24"), out _);

        Assert.Single(BlocklistParser.Collapse(blocks, 1, out var capped));
        Assert.Equal(0, capped);
    }

    [Fact]
    public void An_ipv6_address_at_a_power_of_two_boundary_parses()
    {
        Assert.Equal(["2001:db8:8000::/33"], Parse("2001:db8:8000::/33").Targets);
    }

    private static (List<string> Targets, int Skipped) Parse(string text)
    {
        var blocks = BlocklistParser.Parse(new StringReader(text), out var skipped);
        return (BlocklistParser.Collapse(blocks, 50_000, out _).Select(BlocklistParser.ToTarget).ToList(), skipped);
    }
}
