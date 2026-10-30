using System.Diagnostics;
using System.Text;
using System.Threading.Channels;
using Microsoft.Extensions.Logging.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Detection;
using WinGuard.Core.Model;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>Poll-cycle behavior of the FTP detector: the W3C header, daily rotation and crafted lines.</summary>
public sealed class FtpLogDetectorPollTests : IDisposable
{
    // Default-looking data under a header that moves c-ip: only the header tells the columns apart.
    private const string CustomHeader = "#Fields: date time s-ip cs-username c-ip s-port cs-method cs-uri-stem sc-status sc-substatus sc-win32-status time-taken";

    private readonly string _dir = Directory.CreateTempSubdirectory("winguard-ftp-").FullName;

    public void Dispose() => Directory.Delete(_dir, true);

    [Fact]
    public void The_header_is_found_when_it_is_far_behind_the_tail_of_a_busy_file()
    {
        var path = Path.Combine(_dir, "u_ex261004.log");
        File.WriteAllText(path, BusyLog(sizeBytes: 3 * 1024 * 1024));
        var (detector, settings, sink) = Start();
        detector.PollOnce(settings, sink);

        File.AppendAllText(path, CustomLine("09:00:05", "203.0.113.9"));
        detector.PollOnce(settings, sink);

        var failure = Assert.Single(Drain(sink));
        Assert.Equal("203.0.113.9", failure.IpAddress);
        Assert.Equal("admin", failure.UserName);
    }

    [Fact]
    public void The_last_header_in_a_file_wins()
    {
        var text = "#Fields: date time c-ip\r\n1 2 3\r\n" + CustomHeader + "\r\n";

        Assert.Equal(CustomHeader, FtpLogDetector.FindLastFieldsHeader(Stream(text)));
    }

    [Fact]
    public void A_header_straddling_two_search_blocks_is_read_whole()
    {
        // The search blocks count back from the end of the file in steps of 1 MB.
        const int blockSize = 1024 * 1024;
        var tail = new string('x', blockSize - 20) + "\r\n";
        var text = "padding\r\n" + CustomHeader + "\r\n" + tail;

        Assert.Equal(CustomHeader, FtpLogDetector.FindLastFieldsHeader(Stream(text)));
    }

    [Fact]
    public void A_header_at_the_very_start_of_a_file_is_found()
    {
        Assert.Equal(CustomHeader, FtpLogDetector.FindLastFieldsHeader(Stream(CustomHeader + "\r\nrow\r\n")));
    }

    [Fact]
    public void The_header_of_a_huge_file_is_found_at_its_start()
    {
        using var stream = new MemoryStream();
        stream.Write(Encoding.ASCII.GetBytes(CustomHeader + "\r\n"));
        stream.SetLength(70L * 1024 * 1024);

        Assert.Equal(CustomHeader, FtpLogDetector.FindLastFieldsHeader(stream));
    }

    [Fact]
    public void Text_that_only_contains_the_header_marker_is_not_a_header()
    {
        Assert.Null(FtpLogDetector.FindLastFieldsHeader(Stream("2026-10-04 09:00:01 #Fields: x\r\nrow\r\n")));
    }

    [Fact]
    public void The_next_daily_log_at_utc_midnight_is_read_with_its_own_header()
    {
        var yesterday = Path.Combine(_dir, "u_ex261004.log");
        File.WriteAllText(yesterday, CustomHeader + "\r\n" + CustomLine("23:59:50", "203.0.113.1"));
        var (detector, settings, sink) = Start();
        detector.PollOnce(settings, sink);

        // A late flush to yesterday's log, then IIS rolls over with a different field selection.
        File.AppendAllText(yesterday, CustomLine("23:59:59", "203.0.113.2"));
        const string nextHeader = "#Fields: date time c-ip cs-method sc-status cs-username";
        File.WriteAllText(
            Path.Combine(_dir, "u_ex261005.log"),
            "#Software: Microsoft Internet Information Services 10.0\r\n#Version: 1.0\r\n#Date: 2026-10-05 00:00:01\r\n"
            + nextHeader + "\r\n2026-10-05 00:00:01 203.0.113.3 PASS 530 bob\r\n");
        detector.PollOnce(settings, sink);

        var failures = Drain(sink);
        Assert.Equal(new[] { "203.0.113.2", "203.0.113.3" }, failures.Select(f => f.IpAddress));
        Assert.Equal(new DateTime(2026, 10, 4, 23, 59, 59, DateTimeKind.Utc), failures[0].TimestampUtc);
        Assert.Equal(new DateTime(2026, 10, 5, 0, 0, 1, DateTimeKind.Utc), failures[1].TimestampUtc);
    }

    [Fact]
    public void A_daily_log_created_empty_gets_its_header_as_it_is_written()
    {
        var (detector, settings, sink) = Start();
        detector.PollOnce(settings, sink);

        var today = Path.Combine(_dir, "u_ex261005.log");
        File.WriteAllText(today, string.Empty);
        detector.PollOnce(settings, sink);

        File.AppendAllText(today, CustomHeader + "\r\n" + CustomLine("00:00:02", "203.0.113.4"));
        detector.PollOnce(settings, sink);

        Assert.Equal("203.0.113.4", Assert.Single(Drain(sink)).IpAddress);
    }

    [Fact]
    public void A_line_with_a_shifted_column_cannot_pick_the_address()
    {
        const string header = "#Fields: date time cs-username c-ip cs-method sc-status";

        // A raw space in the user name would move everything after it.
        Assert.False(FtpLogDetector.TryParseIisLine(
            "2026-10-04 09:00:05 x 198.51.100.9 203.0.113.1 PASS 530", header, out _));
        Assert.True(FtpLogDetector.TryParseIisLine(
            "2026-10-04 09:00:05 x 203.0.113.1 PASS 530", header, out var failed));
        Assert.Equal("203.0.113.1", failed!.IpAddress);
    }

    [Fact]
    public void A_long_crafted_filezilla_line_does_not_reach_the_regex()
    {
        var line = "(000001) 2026-10-04 09:05:20 - (not logged in) (203.0.113.44)> USER "
            + new string('a', 2_000_000) + " 530 Login or password incorrect!";

        var watch = Stopwatch.StartNew();
        Assert.False(FtpLogDetector.TryParseFileZillaLine(line, out _));

        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(10), $"took {watch.Elapsed}");
    }

    [Fact]
    public void A_filezilla_session_marker_typed_after_the_response_is_never_used()
    {
        const string line = "(000001) 2026-10-04 09:05:20 - (not logged in) (203.0.113.44)> 530 Login or password incorrect! (198.51.100.9)>";

        Assert.True(FtpLogDetector.TryParseFileZillaLine(line, out var failed));
        Assert.Equal("203.0.113.44", failed!.IpAddress);
    }

    [Fact]
    public void A_very_long_failure_line_is_capped_in_the_raw_log()
    {
        var line = "(000001) 2026-10-04 09:05:20 - (not logged in) (203.0.113.44)> 530 Login or password incorrect! "
            + new string('x', 10_000);

        Assert.True(FtpLogDetector.TryParseFileZillaLine(line, out var failed));
        Assert.True(failed!.RawLog.Length <= 2048);
    }

    private (FtpLogDetector Detector, WinGuardSettings Settings, Channel<FailedLogin> Sink) Start()
    {
        var settings = new WinGuardSettings();
        settings.Ftp.Sources.Add(new FtpLogSource { Kind = FtpServerKind.IisFtp, Path = _dir });
        return (
            new FtpLogDetector(() => settings, NullLogger<FtpLogDetector>.Instance),
            settings,
            Channel.CreateUnbounded<FailedLogin>());
    }

    private static string CustomLine(string time, string ip) =>
        $"2026-10-04 {time} 10.0.0.5 admin {ip} 21 PASS - 530 1 1326 15\r\n";

    private static string BusyLog(int sizeBytes)
    {
        var text = new StringBuilder(CustomHeader).Append("\r\n");
        while (text.Length < sizeBytes)
        {
            text.Append("2026-10-04 08:00:00 10.0.0.5 - 198.51.100.1 21 USER admin 331 0 0 0\r\n");
        }

        return text.ToString();
    }

    private static MemoryStream Stream(string text) => new(Encoding.ASCII.GetBytes(text));

    private static List<FailedLogin> Drain(Channel<FailedLogin> sink)
    {
        var items = new List<FailedLogin>();
        while (sink.Reader.TryRead(out var item))
        {
            items.Add(item);
        }

        return items;
    }
}
