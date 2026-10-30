using System.Threading.Channels;
using System.Xml.Linq;
using Microsoft.Extensions.Logging.Abstractions;
using WinGuard.Core.Detection;
using WinGuard.Core.Model;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>Parser and subscription tests for the Security 4624 detector (samples/logs/README.md).</summary>
public sealed class LogonSuccessDetectorTests
{
    private static readonly DateTime ExpectedTimestamp =
        new DateTime(2026, 10, 4, 9, 21, 47, DateTimeKind.Utc).AddTicks(7654321);

    private static string Fixture => TestData.ReadText("security-4624.xml");

    private static string WithData(string name, string oldValue, string newValue) =>
        Fixture.Replace($"<Data Name=\"{name}\">{oldValue}</Data>", $"<Data Name=\"{name}\">{newValue}</Data>", StringComparison.Ordinal);

    private static bool Parse(string xml, out FailedLogin? logon) => LogonSuccessDetector.TryParse(xml, TestData.NewSettings(), out logon);

    [Fact]
    public void Parses_an_rdp_logon_exactly()
    {
        Assert.True(Parse(Fixture, out var logon));
        Assert.NotNull(logon);

        Assert.True(logon!.IsSuccess);
        Assert.Equal("203.0.113.45", logon.IpAddress);
        Assert.Equal("administrator", logon.UserName);
        Assert.Equal(ProtocolSource.Rdp, logon.Source);
        Assert.Equal("4624", logon.Detector);
        Assert.Equal(10, logon.LogonType);
        Assert.Equal(ExpectedTimestamp.Ticks, logon.TimestampUtc.Ticks);
        Assert.Equal(DateTimeKind.Utc, logon.TimestampUtc.Kind);
    }

    [Fact]
    public void Parses_a_network_logon()
    {
        Assert.True(Parse(WithData("LogonType", "10", "3"), out var logon));
        Assert.Equal(3, logon!.LogonType);
    }

    [Theory]
    [InlineData("2")]
    [InlineData("4")]
    [InlineData("5")]
    [InlineData("7")]
    [InlineData("8")]
    [InlineData("11")]
    [InlineData("")]
    [InlineData("x")]
    public void Other_logon_types_are_dropped(string logonType)
    {
        Assert.False(Parse(WithData("LogonType", "10", logonType), out var logon));
        Assert.Null(logon);
    }

    [Fact]
    public void An_anonymous_logon_is_dropped()
    {
        Assert.False(Parse(TestData.ReadText("security-4624-anonymous.xml"), out _));
    }

    [Theory]
    [InlineData("-")]
    [InlineData("")]
    [InlineData("not-an-address")]
    public void A_logon_without_a_client_address_is_dropped(string ip)
    {
        Assert.False(Parse(WithData("IpAddress", "203.0.113.45", ip), out _));
    }

    [Theory]
    [InlineData("VPS-01$")]
    [InlineData("-")]
    [InlineData("")]
    public void Machine_accounts_and_blank_names_are_dropped(string user)
    {
        Assert.False(Parse(WithData("TargetUserName", "administrator", user), out _));
    }

    [Fact]
    public void Internal_addresses_are_dropped_unless_they_are_processed()
    {
        var xml = WithData("IpAddress", "203.0.113.45", "192.168.1.20");
        var settings = TestData.NewSettings();

        Assert.False(LogonSuccessDetector.TryParse(xml, settings, out _));

        settings.ProcessInternalIPs = true;
        Assert.True(LogonSuccessDetector.TryParse(xml, settings, out var logon));
        Assert.Equal("192.168.1.20", logon!.IpAddress);
    }

    [Fact]
    public void An_ipv6_client_is_normalized()
    {
        Assert.True(Parse(WithData("IpAddress", "203.0.113.45", "2001:DB8::45"), out var logon));
        Assert.Equal("2001:db8::45", logon!.IpAddress);
    }

    [Fact]
    public void A_mapped_ipv4_client_is_normalized()
    {
        Assert.True(Parse(WithData("IpAddress", "203.0.113.45", "::ffff:203.0.113.45"), out var logon));
        Assert.Equal("203.0.113.45", logon!.IpAddress);
    }

    [Fact]
    public void A_failure_event_is_not_a_logon()
    {
        Assert.False(Parse(TestData.ReadText("security-4625.xml"), out _));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("<Event><unclosed>")]
    [InlineData("not xml at all")]
    public void Malformed_records_are_dropped(string xml)
    {
        Assert.False(Parse(xml, out _));
    }

    [Fact]
    public void A_record_with_a_dtd_is_refused()
    {
        Assert.False(Parse("<!DOCTYPE Event [<!ENTITY x \"y\">]>" + Fixture, out _));
    }

    [Fact]
    public void Single_quoted_attributes_as_written_by_the_event_log_parse_the_same()
    {
        Assert.True(Parse(Fixture.Replace('"', '\''), out var logon));
        Assert.Equal("administrator", logon!.UserName);
    }

    [Fact]
    public void An_older_event_version_without_the_extra_fields_parses()
    {
        var document = XDocument.Parse(Fixture);
        var eventData = document.Root!.Elements().Single(e => e.Name.LocalName == "EventData");
        eventData.Elements()
            .Where(e => (string?)e.Attribute("Name") is "ImpersonationLevel" or "ElevatedToken" or "VirtualAccount" or "RestrictedAdminMode")
            .Remove();

        Assert.True(Parse(document.ToString(), out var logon));
        Assert.Equal("203.0.113.45", logon!.IpAddress);
    }

    // ---------- filters ----------

    [Fact]
    public void The_subscription_query_is_well_formed_and_as_tight_as_xpath_allows()
    {
        var select = XDocument.Parse(LogonSuccessDetector.SubscriptionXPath).Descendants("Select").Single();

        Assert.Equal("Security", (string?)select.Attribute("Path"));
        Assert.StartsWith("*[System[(EventID=4624)] and EventData[", select.Value, StringComparison.Ordinal);
        Assert.Contains("Data[@Name='LogonType']='3' or Data[@Name='LogonType']='10'", select.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("='7'", select.Value, StringComparison.Ordinal);
        Assert.Contains("Data[@Name='IpAddress']!='-'", select.Value, StringComparison.Ordinal);
        Assert.Contains("Data[@Name='TargetUserSid']!='S-1-5-7'", select.Value, StringComparison.Ordinal);
    }

    [Fact]
    public void The_replay_query_keeps_the_payload_filter_outside_system()
    {
        var from = new DateTime(2026, 10, 4, 9, 0, 0, DateTimeKind.Utc);

        var xpath = EventLogDetectorBase.BuildReplayXPath("EventID=4624", from, from.AddMinutes(30), LogonSuccessDetector.EventDataXPath);

        Assert.Equal(
            "*[System[EventID=4624 and TimeCreated[@SystemTime>='2026-10-04T09:00:00.000Z' and @SystemTime<'2026-10-04T09:30:00.000Z']] and "
                + LogonSuccessDetector.EventDataXPath + "]",
            xpath);
    }

    // ---------- the shared channel ----------

    [Fact]
    public void Logons_stop_short_of_crowding_failures_out_of_the_channel()
    {
        var sink = Channel.CreateBounded<FailedLogin>(20_000);
        for (var i = 0; i < LogonSuccessDetector.MaxQueuedBeforeDropping - 1; i++)
        {
            sink.Writer.TryWrite(new FailedLogin());
        }

        Assert.True(LogonSuccessDetector.HasRoom(sink));

        sink.Writer.TryWrite(new FailedLogin());
        Assert.False(LogonSuccessDetector.HasRoom(sink));

        sink.Reader.TryRead(out _);
        Assert.True(LogonSuccessDetector.HasRoom(sink));
    }

    [Fact]
    public async Task While_the_feature_is_off_the_detector_stays_away_from_the_security_log()
    {
        var settings = TestData.NewSettings();
        var detector = new LogonSuccessDetector(() => settings, NullLogger<LogonSuccessDetector>.Instance);
        var sink = Channel.CreateUnbounded<FailedLogin>();
        using var cts = new CancellationTokenSource();

        await detector.StartAsync(sink, cts.Token);
        detector.TrySubscribe();
        await cts.CancelAsync();

        Assert.False(detector.IsRunning);
        Assert.Equal(0, sink.Reader.Count);
    }
}
