using WinGuard.Core.Detection;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>Regression tests for parser edge cases in the event-log detectors and exclusion rules.</summary>
public sealed class DetectorEdgeCaseTests
{
    // ---------- RdpCoreTS 140 positional fallback ----------

    private const string NamedIp = "<Data Name=\"IPString\">198.51.100.23</Data>";

    [Theory]
    [InlineData("<Data Name=\"ClientBuild\">10.0.26.100</Data>")] // named, but not the address
    [InlineData("<Data>198.51.100.77</Data><Data>203.0.113.8</Data>")] // which one would it be?
    [InlineData("<Data>12345</Data>")] // parses as an address in the legacy short form
    [InlineData("<Data>1.2.3</Data>")]
    [InlineData("<Data>0x7f000001</Data>")]
    [InlineData("<Data>2148074254</Data>")]
    [InlineData("<Data>some text</Data>")]
    [InlineData("<Data></Data>")]
    [InlineData("<Data Name=\"IPString\"></Data><Data>198.51.100.77</Data>")] // no usable IPString
    [InlineData("<Data Name=\"IPString\">not-an-ip</Data>")]
    [InlineData("")]
    public void Event_140_without_a_clear_address_is_dropped(string data)
    {
        var xml = TestData.ReadText("rdpcorets-140.xml").Replace(NamedIp, data);

        Assert.False(RdpCoreTsDetector.TryParse(xml, out var failed));
        Assert.Null(failed);
    }

    [Theory]
    [InlineData("<Data Name=\"IPString\">198.51.100.77</Data><Data>203.0.113.8</Data>", "198.51.100.77")]
    [InlineData("<Data Name=\"Other\">x</Data><Data Name=\"ipstring\">198.51.100.77</Data>", "198.51.100.77")]
    [InlineData("<Data>2001:DB8::1</Data>", "2001:db8::1")]
    public void Event_140_address_is_taken_from_the_named_field_or_a_lone_unnamed_one(string data, string expected)
    {
        var xml = TestData.ReadText("rdpcorets-140.xml").Replace(NamedIp, data);

        Assert.True(RdpCoreTsDetector.TryParse(xml, out var failed));
        Assert.Equal(expected, failed!.IpAddress);
    }

    // ---------- MS SQL ignore patterns ----------

    [Fact]
    public void A_login_name_spelled_like_an_ignore_pattern_does_not_stop_the_counting()
    {
        var xml = TestData.ReadText("mssql-18456.xml").Replace("<Data>sa</Data>", "<Data>Failed to open the explicitly specified database</Data>");
        const string message = "Login failed for user 'Failed to open the explicitly specified database'. Reason: Password did not match that for the login provided. [CLIENT: 203.0.113.77]";

        Assert.True(MsSqlDetector.TryParse(xml, message, TestData.NewSettings(), TestData.SqlInstances, out var failed));
        Assert.Equal("203.0.113.77", failed!.IpAddress);
    }

    [Fact]
    public void A_real_ignorable_reason_is_still_ignored_for_a_short_login_name()
    {
        var xml = TestData.ReadText("mssql-18456.xml");
        var settings = TestData.NewSettings();
        settings.MsSql.IgnoreMessagePatterns = ["Password did not match"];
        const string message = "Login failed for user 'sa'. Reason: Password did not match that for the login provided. [CLIENT: 203.0.113.77]";

        Assert.False(MsSqlDetector.TryParse(xml, message, settings, TestData.SqlInstances, out _));
    }

    // ---------- exclusion wildcards ----------

    [Theory]
    [InlineData("a*bc", "a*c", true)] // the literal '*' in the input used to consume the wildcard
    [InlineData("backup*-1", "backup*1", true)]
    [InlineData("**", "*", true)]
    [InlineData("a*b", "a*c", false)]
    public void Wildcards_work_on_input_containing_a_literal_star(string input, string pattern, bool expected)
    {
        Assert.Equal(expected, ExclusionEvaluator.MatchesWildcard(input, pattern));
    }
}
