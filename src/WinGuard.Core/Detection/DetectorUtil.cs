using System.Globalization;
using System.Xml.Linq;

namespace WinGuard.Core.Detection;

/// <summary>Parsing helpers shared by the event-log detectors.</summary>
internal static class DetectorUtil
{
    /// <summary>Longest log line kept in <c>FailedLogin.RawLog</c>; a client can make lines very long.</summary>
    private const int MaxRawLogLength = 2048;

    /// <summary>Caps a raw log line before it reaches the event store.</summary>
    internal static string LimitRawLog(string line) =>
        line.Length > MaxRawLogLength ? line[..MaxRawLogLength] : line;

    /// <summary>Reads <c>System/TimeCreated@SystemTime</c> as UTC, falling back to now.</summary>
    internal static DateTime ParseSystemTime(XElement system, XNamespace ns)
    {
        var value = (string?)system.Element(ns + "TimeCreated")?.Attribute("SystemTime");
        if (!string.IsNullOrWhiteSpace(value)
            && DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed))
        {
            return parsed.Kind == DateTimeKind.Utc ? parsed : parsed.ToUniversalTime();
        }

        return DateTime.UtcNow;
    }

    /// <summary>Trims a value; blank and "-" become null.</summary>
    internal static string? NormalizeOptional(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var trimmed = value.Trim();
        return trimmed == "-" ? null : trimmed;
    }
}
