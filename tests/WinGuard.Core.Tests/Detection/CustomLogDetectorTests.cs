using WinGuard.Core.Detection;
using WinGuard.Core.Model;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>Parser tests for the generic regex-based custom log detector (PLAN.md §4.5).</summary>
public sealed class CustomLogDetectorTests
{
    private const string Regex = "LOGIN FAILED user=(?<username>\\S+) ip=(?<ipaddress>\\S+)";

    [Fact]
    public void Parses_matching_lines_with_named_groups()
    {
        var lines = TestData.ReadLines("custom-app.log");

        var failures = new List<FailedLogin>();
        foreach (var line in lines)
        {
            if (CustomLogDetector.TryParseLine(line, Regex, out var failed) && failed is not null)
            {
                failures.Add(failed);
            }
        }

        Assert.Equal(3, failures.Count);
        Assert.Equal(
            new[] { "203.0.113.99", "203.0.113.99", "192.0.2.15" },
            failures.Select(f => f.IpAddress));
        Assert.Equal(
            new[] { "jsmith", "admin", "root" },
            failures.Select(f => f.UserName));
        Assert.All(failures, f => Assert.Equal(ProtocolSource.Custom, f.Source));
    }

    [Fact]
    public void Non_matching_line_is_not_a_failure()
    {
        var line = TestData.ReadLines("custom-app.log")[0]; // "LOGIN OK ..."

        Assert.False(CustomLogDetector.TryParseLine(line, Regex, out var failed));
        Assert.Null(failed);
    }
}