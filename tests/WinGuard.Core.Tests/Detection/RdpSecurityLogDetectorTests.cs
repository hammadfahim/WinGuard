using WinGuard.Core.Config;
using WinGuard.Core.Detection;
using WinGuard.Core.Model;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>Parser tests for the Security log 4625 detector (PLAN.md §4.1, samples/logs/README.md).</summary>
public sealed class RdpSecurityLogDetectorTests
{
    private static readonly DateTime ExpectedTimestamp =
        new DateTime(2026, 10, 4, 9, 15, 32, DateTimeKind.Utc).AddTicks(1234567);

    [Fact]
    public void Parses_4625_record_exactly()
    {
        var xml = TestData.ReadText("security-4625.xml");
        var settings = TestData.NewSettings();

        Assert.True(RdpSecurityLogDetector.TryParse(xml, settings, out var failed));
        Assert.NotNull(failed);

        Assert.Equal("203.0.113.45", failed!.IpAddress);
        Assert.Equal("administrator", failed.UserName);
        Assert.Equal(ProtocolSource.Rdp, failed.Source);
        Assert.Equal("4625", failed.Detector);
        Assert.Equal(ExpectedTimestamp.Ticks, failed.TimestampUtc.Ticks);
        Assert.Equal(DateTimeKind.Utc, failed.TimestampUtc.Kind);
        Assert.False(string.IsNullOrWhiteSpace(failed.RawLog));
    }

    [Fact]
    public void Empty_ip_record_is_dropped()
    {
        var xml = TestData.ReadText("security-4625-empty-ip.xml");
        var settings = TestData.NewSettings();

        Assert.False(RdpSecurityLogDetector.TryParse(xml, settings, out var failed));
        Assert.Null(failed);
    }

    [Fact]
    public void Exclusion_rule_on_username_drops_event()
    {
        var xml = TestData.ReadText("security-4625.xml");
        var settings = TestData.NewSettings();
        settings.Rdp.ExclusionRules = ["TargetUserName=administrator"];

        Assert.False(RdpSecurityLogDetector.TryParse(xml, settings, out _));
    }

    [Fact]
    public void Exclusion_rule_with_wildcard_drops_event()
    {
        var xml = TestData.ReadText("security-4625.xml");
        var settings = TestData.NewSettings();
        settings.Rdp.ExclusionRules = ["TargetUserName=admin*"];

        Assert.False(RdpSecurityLogDetector.TryParse(xml, settings, out _));
    }

    [Fact]
    public void Exclusion_rule_that_does_not_match_keeps_event()
    {
        var xml = TestData.ReadText("security-4625.xml");
        var settings = TestData.NewSettings();
        // The fixture has LogonType=10, so a LogonType=2 exclusion must not apply.
        settings.Rdp.ExclusionRules = ["LogonType=2"];

        Assert.True(RdpSecurityLogDetector.TryParse(xml, settings, out var failed));
        Assert.Equal("203.0.113.45", failed!.IpAddress);
    }

    [Fact]
    public void Or_between_exclusion_rules_keeps_event_when_none_match()
    {
        var xml = TestData.ReadText("security-4625.xml");
        var settings = TestData.NewSettings();
        settings.Rdp.ExclusionRules = ["LogonType=2", "TargetUserName=bob"];

        Assert.True(RdpSecurityLogDetector.TryParse(xml, settings, out _));
    }
}