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

        var admin = failures.Where(f => f.IpAddress == "203.0.113.9").ToList();
        Assert.All(admin, f => Assert.Equal("admin", f.UserName));
        Assert.Equal("bob", failures.Single(f => f.IpAddress == "198.51.100.44").UserName);
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

        Assert.Equal(2, failures.Count);
        Assert.Contains(failures, f => f.IpAddress == "203.0.113.44");
        Assert.Contains(failures, f => f.IpAddress == "192.0.2.99");
        Assert.DoesNotContain(failures, f => f.IpAddress == "198.51.100.7");
        Assert.All(failures, f => Assert.Equal(ProtocolSource.Ftp, f.Source));
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
}