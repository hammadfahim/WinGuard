using WinGuard.Core.Detection;
using WinGuard.Core.Model;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>Parser tests for the MS SQL Server Application 18456 detector (PLAN.md §4.3).</summary>
public sealed class MsSqlDetectorTests
{
    [Fact]
    public void Extracts_client_ip_and_user_from_message()
    {
        var xml = TestData.ReadText("mssql-18456.xml");
        var message = TestData.ReadText("mssql-18456-message.txt");
        var settings = TestData.NewSettings();

        Assert.True(MsSqlDetector.TryParse(xml, message, settings, out var failed));
        Assert.NotNull(failed);

        Assert.Equal("203.0.113.77", failed!.IpAddress);
        Assert.Equal("sa", failed.UserName);
        Assert.Equal(ProtocolSource.MsSql, failed.Source);
        Assert.Equal("18456", failed.Detector);
    }

    [Fact]
    public void Ignores_message_matching_default_ignore_patterns()
    {
        var xml = TestData.ReadText("mssql-18456.xml");
        var ignored = TestData.ReadText("mssql-18456-message-ignored.txt");
        var settings = TestData.NewSettings();

        Assert.Contains(
            "Failed to open the explicitly specified database",
            settings.MsSql.IgnoreMessagePatterns);

        Assert.False(MsSqlDetector.TryParse(xml, ignored, settings, out var failed));
        Assert.Null(failed);
    }

    [Fact]
    public void Null_message_falls_back_to_xml_and_drops_when_no_client()
    {
        var xml = TestData.ReadText("mssql-18456.xml");
        var settings = TestData.NewSettings();

        // The fixture XML contains no "[CLIENT: ...]" text at all.
        Assert.False(MsSqlDetector.TryParse(xml, null, settings, out var failed));
        Assert.Null(failed);
    }
}