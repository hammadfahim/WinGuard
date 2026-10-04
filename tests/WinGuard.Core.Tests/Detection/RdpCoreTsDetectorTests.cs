using WinGuard.Core.Detection;
using WinGuard.Core.Model;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>Parser tests for the RdpCoreTS/Operational 140 fallback detector (PLAN.md §4.2).</summary>
public sealed class RdpCoreTsDetectorTests
{
    [Fact]
    public void Parses_140_record_exactly()
    {
        var xml = TestData.ReadText("rdpcorets-140.xml");

        Assert.True(RdpCoreTsDetector.TryParse(xml, out var failed));
        Assert.NotNull(failed);

        Assert.Equal("198.51.100.23", failed!.IpAddress);
        Assert.Null(failed.UserName);
        Assert.Equal(ProtocolSource.Rdp, failed.Source);

        var expected = new DateTime(2026, 10, 4, 9, 20, 11, DateTimeKind.Utc).AddTicks(4567890);
        Assert.Equal(expected.Ticks, failed.TimestampUtc.Ticks);
        Assert.Equal(DateTimeKind.Utc, failed.TimestampUtc.Kind);
    }

    [Fact]
    public void Wrong_event_id_is_rejected()
    {
        var xml = TestData.ReadText("rdpcorets-140.xml")
            .Replace("<EventID>140</EventID>", "<EventID>141</EventID>");

        Assert.False(RdpCoreTsDetector.TryParse(xml, out var failed));
        Assert.Null(failed);
    }
}