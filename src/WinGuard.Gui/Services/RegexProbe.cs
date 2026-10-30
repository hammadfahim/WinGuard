using System.Text.RegularExpressions;
using WinGuard.Core.Detection;

namespace WinGuard.Gui.Services;

/// <summary>Outcome of testing a custom-source regex against a sample line.</summary>
public enum ProbeStatus
{
    /// <summary>Nothing to test yet.</summary>
    Idle,

    /// <summary>The line matches and yields a usable address.</summary>
    Match,

    /// <summary>A valid regex that does not match this line.</summary>
    NoMatch,

    /// <summary>The regex matched, but what it captured as the address is not one.</summary>
    BadAddress,

    /// <summary>The regex lacks the required ipaddress group.</summary>
    MissingGroup,

    /// <summary>The regex does not compile.</summary>
    InvalidRegex,

    /// <summary>The regex took too long on this line.</summary>
    Timeout,
}

/// <summary>What a test found.</summary>
/// <param name="Status">The outcome.</param>
/// <param name="Summary">One line for the administrator.</param>
/// <param name="IpAddress">The captured address, normalized.</param>
/// <param name="UserName">The captured user name, when the regex has that group.</param>
public sealed record ProbeResult(ProbeStatus Status, string Summary, string IpAddress = "", string UserName = "");

/// <summary>
/// Tests a regex in the console, without the service. The verdict comes from the same
/// <see cref="CustomLogDetector.TryParseLine"/> the service runs on each log line, so a line that
/// passes here is one the service will count. The extra matching in here only explains failures.
/// </summary>
public static class RegexProbe
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(1);

    /// <summary>Checks that a pattern compiles and names the required group, without a sample line.</summary>
    public static ProbeResult Check(string? pattern)
    {
        if (string.IsNullOrWhiteSpace(pattern))
        {
            return new ProbeResult(ProbeStatus.Idle, string.Empty);
        }

        Regex regex;
        try
        {
            regex = new Regex(pattern, RegexOptions.CultureInvariant, Timeout);
        }
        catch (ArgumentException ex)
        {
            return new ProbeResult(ProbeStatus.InvalidRegex, "Invalid regex: " + ex.Message);
        }

        return regex.GroupNumberFromName("ipaddress") < 0
            ? new ProbeResult(ProbeStatus.MissingGroup, "The regex must contain a named group (?<ipaddress>...).")
            : new ProbeResult(ProbeStatus.Idle, string.Empty);
    }

    /// <summary>Tests a pattern against one sample line.</summary>
    public static ProbeResult Run(string? pattern, string? sampleLine)
    {
        var check = Check(pattern);
        if (check.Status != ProbeStatus.Idle || string.IsNullOrWhiteSpace(pattern))
        {
            return check;
        }

        if (string.IsNullOrWhiteSpace(sampleLine))
        {
            return new ProbeResult(ProbeStatus.Idle, "Paste a sample log line to test this regex.");
        }

        try
        {
            if (CustomLogDetector.TryParseLine(sampleLine, pattern, out var failed) && failed is not null)
            {
                return new ProbeResult(ProbeStatus.Match, "This line would count as one failed login.", failed.IpAddress, failed.UserName ?? string.Empty);
            }

            var regex = new Regex(pattern, RegexOptions.CultureInvariant, Timeout);
            var match = regex.Match(sampleLine);
            if (!match.Success)
            {
                return new ProbeResult(ProbeStatus.NoMatch, "The regex does not match this line.");
            }

            var captured = match.Groups["ipaddress"];
            return new ProbeResult(
                ProbeStatus.BadAddress,
                captured.Success
                    ? $"The line matches, but '{captured.Value}' is not an IP address, so it would be ignored."
                    : "The line matches, but the ipaddress group captured nothing, so it would be ignored.");
        }
        catch (RegexMatchTimeoutException)
        {
            return new ProbeResult(ProbeStatus.Timeout, "The regex took too long on this line. Simplify it: the service would give up the same way.");
        }
    }
}
