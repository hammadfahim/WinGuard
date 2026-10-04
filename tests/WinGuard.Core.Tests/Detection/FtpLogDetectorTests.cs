using WinGuard.Core.Detection;
using WinGuard.Core.Model;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>Parser tests for the IIS FTP W3C and FileZilla text formats (PLAN.md §4.4).</summary>
public sealed class FtpLogDetectorTests
{
    // ---------- IIS / W3C ----------

    [Fact]
    public void Iis_parses_pass_530_lines_only()
    {
        var lines = TestData.ReadLines("iis-ftp-w3c.log");
        var header = lines.First(l => l.StartsWith("#Fields:", StringComparison.Ordinal));

        var failures = new List<FailedLogin>();
        foreach (var line in lines.Where(l => !l.StartsWith("#", StringComparison.Ordinal)))
        {
            if (FtpLogDetector.TryParseIisLine(line, header, out var failed) && failed is not null)
            {
                failures.Add(failed);
            }
        }

        Assert.Equal(3, failures.Count);
        Assert.Equal(2, failures.Count(f => f.IpAddress == "203.0.113.9"));
        Assert.Single(failures, f => f.IpAddress == "198.51.100.44");
        Assert.All(failures, f => Assert.Equal(ProtocolSource.Ftp, f.Source));
        Assert.All(failures, f => Assert.Equal("iis-ftp", f.Detector));

        var admin = failures.Where(f => f.IpAddress == "203.0.113.9").ToList();
        Assert.All(admin, f => Assert.Equal("admin", f.UserName));
        Assert.Equal("bob", failures.Single(f => f.IpAddress == "198.51.100.44").UserName);

        // IIS W3C date+time columns are UTC and must be used verbatim. The three 530 lines are at
        // 09:00:05, 09:00:12 and 09:01:09 in the fixture and are collected in file order.
        var expectedTimestamps = new[]
        {
            new DateTime(2026, 10, 4, 9, 0, 5, DateTimeKind.Utc),
            new DateTime(2026, 10, 4, 9, 0, 12, DateTimeKind.Utc),
            new DateTime(2026, 10, 4, 9, 1, 9, DateTimeKind.Utc),
        };
        Assert.Equal(expectedTimestamps, failures.Select(f => f.TimestampUtc));
        Assert.All(failures, f => Assert.Equal(DateTimeKind.Utc, f.TimestampUtc.Kind));
    }

    [Fact]
    public void Iis_pass_230_line_is_not_a_failure()
    {
        var lines = TestData.ReadLines("iis-ftp-w3c.log");
        var header = lines.First(l => l.StartsWith("#Fields:", StringComparison.Ordinal));
        var success = lines.First(l => l.Contains(" PASS ", StringComparison.Ordinal)
                                       && l.Contains(" 230 ", StringComparison.Ordinal));

        Assert.False(FtpLogDetector.TryParseIisLine(success, header, out var failed));
        Assert.Null(failed);
    }

    [Fact]
    public void Iis_user_line_is_not_a_failure()
    {
        var lines = TestData.ReadLines("iis-ftp-w3c.log");
        var header = lines.First(l => l.StartsWith("#Fields:", StringComparison.Ordinal));
        var userLine = lines.First(l => l.Contains(" USER ", StringComparison.Ordinal));

        Assert.False(FtpLogDetector.TryParseIisLine(userLine, header, out var failed));
        Assert.Null(failed);
    }

    [Fact]
    public void Iis_respects_custom_fields_order()
    {
        const string header = "#Fields: date time sc-status c-ip cs-method cs-username";
        const string line = "2026-10-04 09:00:05 530 203.0.113.9 PASS admin";

        Assert.True(FtpLogDetector.TryParseIisLine(line, header, out var failed));
        Assert.NotNull(failed);
        Assert.Equal("203.0.113.9", failed!.IpAddress);
        Assert.Equal("admin", failed.UserName);
    }

    // ---------- FileZilla ----------

    [Fact]
    public void FileZilla_parses_530_lines_only()
    {
        var lines = TestData.ReadLines("filezilla-server.log");

        var failures = new List<FailedLogin>();
        foreach (var line in lines)
        {
            if (FtpLogDetector.TryParseFileZillaLine(line, out var failed) && failed is not null)
            {
                failures.Add(failed);
            }
        }

        Assert.Equal(3, failures.Count);
        Assert.Contains(failures, f => f.IpAddress == "203.0.113.44");
        Assert.Contains(failures, f => f.IpAddress == "192.0.2.99");
        Assert.Contains(failures, f => f.IpAddress == "203.0.113.55");
        Assert.DoesNotContain(failures, f => f.IpAddress == "198.51.100.7");
        Assert.All(failures, f => Assert.Equal(ProtocolSource.Ftp, f.Source));
        Assert.All(failures, f => Assert.Equal("filezilla", f.Detector));

        // "(not logged in)" lines yield a null username; the bare-name shape preserves the user.
        Assert.Null(failures.Single(f => f.IpAddress == "203.0.113.44").UserName);
        Assert.Null(failures.Single(f => f.IpAddress == "192.0.2.99").UserName);
        Assert.Equal("bob", failures.Single(f => f.IpAddress == "203.0.113.55").UserName);

        // FileZilla writes local time; the parser must convert it to UTC. Compute the expected
        // value the same way so the assertion is independent of the machine's time zone.
        Assert.Equal(
            LocalToUtc(2026, 10, 4, 9, 5, 20).Ticks,
            failures.Single(f => f.IpAddress == "203.0.113.44").TimestampUtc.Ticks);
        Assert.Equal(
            LocalToUtc(2026, 10, 4, 9, 6, 55).Ticks,
            failures.Single(f => f.IpAddress == "192.0.2.99").TimestampUtc.Ticks);
        Assert.Equal(
            LocalToUtc(2026, 10, 4, 9, 7, 20).Ticks,
            failures.Single(f => f.IpAddress == "203.0.113.55").TimestampUtc.Ticks);
        Assert.All(failures, f => Assert.Equal(DateTimeKind.Utc, f.TimestampUtc.Kind));
    }

    [Fact]
    public void FileZilla_bare_username_before_ip_is_captured()
    {
        const string line = "(000004) 2026-10-04 09:07:20 - bob (203.0.113.55)> 530 Login or password incorrect!";

        Assert.True(FtpLogDetector.TryParseFileZillaLine(line, out var failed));
        Assert.NotNull(failed);
        Assert.Equal("bob", failed!.UserName);
        Assert.Equal("203.0.113.55", failed.IpAddress);
        Assert.Equal("filezilla", failed.Detector);
    }

    [Fact]
    public void FileZilla_230_logon_line_is_not_a_failure()
    {
        var lines = TestData.ReadLines("filezilla-server.log");
        var logon = lines.Single(l => l.Contains("230 Logged on", StringComparison.Ordinal));

        Assert.False(FtpLogDetector.TryParseFileZillaLine(logon, out var failed));
        Assert.Null(failed);
    }

    [Fact]
    public void FileZilla_user_and_pass_lines_are_not_failures_on_their_own()
    {
        var lines = TestData.ReadLines("filezilla-server.log");
        var userLine = lines.First(l => l.Contains("> USER ", StringComparison.Ordinal));
        var passLine = lines.First(l => l.Contains("> PASS ", StringComparison.Ordinal));

        Assert.False(FtpLogDetector.TryParseFileZillaLine(userLine, out _));
        Assert.False(FtpLogDetector.TryParseFileZillaLine(passLine, out _));
    }

    /// <summary>Builds a UTC DateTime from a FileZilla local-time stamp, time-zone independently.</summary>
    private static DateTime LocalToUtc(int year, int month, int day, int hour, int minute, int second) =>
        DateTime.SpecifyKind(new DateTime(year, month, day, hour, minute, second), DateTimeKind.Local)
            .ToUniversalTime();
}