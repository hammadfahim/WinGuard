using System.Globalization;
using System.Text;
using WinGuard.Core.Config;
using WinGuard.Core.Model;

namespace WinGuard.Core.Notifications;

/// <summary>
/// Builds syslog messages to RFC 5424 §6: <c>&lt;PRI&gt;1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID
/// STRUCTURED-DATA MSG</c>, optionally with a CEF event as the MSG.
/// <para>
/// STRUCTURED-DATA is always the NILVALUE: a custom SD-ID has to carry a private enterprise number
/// registered with IANA, and WinGuard has none. What a parser wants goes in the MSG instead. Event
/// text can hold anything a log line held, so control characters are escaped: a line break in it
/// must not be able to forge a second message.
/// </para>
/// </summary>
internal static class SyslogFormatter
{
    /// <summary>What RFC 5426 says a receiver should take. Longer messages are cut, not split.</summary>
    internal const int MaxMessageBytes = 2048;

    private const string AppName = "WinGuard";
    private const string NilValue = "-";

    // RFC 5424 §6: field lengths, in PRINTUSASCII characters.
    private const int MaxHostName = 255;
    private const int MaxProcessId = 128;
    private const int MaxMessageId = 32;

    private const int SeverityError = 3;
    private const int SeverityWarning = 4;
    private const int SeverityInformational = 6;

    private const int CefSeverityError = 8;
    private const int CefSeverityWarning = 6;
    private const int CefSeverityInformational = 3;

    private static readonly byte[] Bom = [0xEF, 0xBB, 0xBF];
    private static readonly UTF8Encoding Utf8 = new(encoderShouldEmitUTF8Identifier: false);

    /// <summary>The message as it goes on the wire, without any transport framing.</summary>
    /// <param name="logEvent">The event.</param>
    /// <param name="settings">The channel's settings.</param>
    /// <param name="hostName">This machine, best as an FQDN.</param>
    /// <param name="processId">This process.</param>
    /// <param name="version">The WinGuard version, for CEF.</param>
    public static byte[] Format(LogEvent logEvent, SyslogSettings settings, string hostName, int processId, string version)
    {
        ArgumentNullException.ThrowIfNull(logEvent);
        ArgumentNullException.ThrowIfNull(settings);

        var eventId = WinGuardEventIds.For(logEvent);
        var priority = settings.Facility * 8 + Severity(logEvent.Level);
        var header = string.Join(
            ' ',
            $"<{priority.ToString(CultureInfo.InvariantCulture)}>1",
            Timestamp(logEvent.TimestampUtc),
            HeaderField(hostName, MaxHostName),
            AppName,
            HeaderField(processId.ToString(CultureInfo.InvariantCulture), MaxProcessId),
            HeaderField(eventId.ToString(CultureInfo.InvariantCulture), MaxMessageId),
            NilValue);

        var text = settings.Format == SyslogFormat.Cef
            ? Cef(logEvent, eventId, version)
            : PlainText(logEvent);

        var headerBytes = Encoding.ASCII.GetBytes(header + " ");

        // RFC 5424 §6.4: text that needs Unicode must start with a BOM, and pure ASCII needs none.
        // CEF goes as MSG-ANY without one: collectors look for "CEF:" at the start of the message,
        // and a user name an attacker picks must not be able to move it from there.
        var unicode = settings.Format != SyslogFormat.Cef && text.Any(c => c > 0x7F);
        var bodyLimit = MaxMessageBytes - headerBytes.Length - (unicode ? Bom.Length : 0);
        var body = Truncate(text, bodyLimit);

        var message = new byte[headerBytes.Length + (unicode ? Bom.Length : 0) + body.Length];
        headerBytes.CopyTo(message, 0);
        if (unicode)
        {
            Bom.CopyTo(message, headerBytes.Length);
        }

        body.CopyTo(message, message.Length - body.Length);
        return message;
    }

    private static int Severity(LogEventLevel level) => level switch
    {
        LogEventLevel.Error => SeverityError,
        LogEventLevel.Warning => SeverityWarning,
        _ => SeverityInformational,
    };

    /// <summary>RFC 5424 §6.2.3: upper-case T and Z, at most six fractional digits. An unknown time is the NILVALUE.</summary>
    private static string Timestamp(DateTime timestampUtc) => timestampUtc == default
        ? NilValue
        : timestampUtc.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);

    /// <summary>Header fields are PRINTUSASCII, 33 to 126; whatever is left out of that, or empty, is the NILVALUE.</summary>
    private static string HeaderField(string? value, int maxLength)
    {
        var printable = new string((value ?? string.Empty).Where(c => c is >= '!' and <= '~').Take(maxLength).ToArray());
        return printable.Length == 0 ? NilValue : printable;
    }

    private static string PlainText(LogEvent logEvent)
    {
        var text = new StringBuilder(Escape(logEvent.Message));
        if (logEvent.IpAddress is { } ip)
        {
            text.Append(" ip=").Append(Escape(ip));
        }

        if (logEvent.Source is { } source)
        {
            text.Append(" source=").Append(source.ToString().ToLowerInvariant());
        }

        return text.ToString();
    }

    private static string Cef(LogEvent logEvent, int eventId, string version)
    {
        var severity = logEvent.Level switch
        {
            LogEventLevel.Error => CefSeverityError,
            LogEventLevel.Warning => CefSeverityWarning,
            _ => CefSeverityInformational,
        };

        var text = new StringBuilder("CEF:0|WinGuard|WinGuard|")
            .Append(CefHeader(version)).Append('|')
            .Append(eventId.ToString(CultureInfo.InvariantCulture)).Append('|')
            .Append(CefHeader(EventName(eventId))).Append('|')
            .Append(severity.ToString(CultureInfo.InvariantCulture)).Append('|');

        var extension = new List<string>();
        if (logEvent.TimestampUtc != default)
        {
            var milliseconds = new DateTimeOffset(DateTime.SpecifyKind(logEvent.TimestampUtc, DateTimeKind.Utc)).ToUnixTimeMilliseconds();
            extension.Add("rt=" + milliseconds.ToString(CultureInfo.InvariantCulture));
        }

        if (logEvent.IpAddress is { } ip)
        {
            // src holds an IPv4 address only. IPv6 addresses and aggregate prefixes go in a custom field.
            extension.Add(System.Net.IPAddress.TryParse(ip, out var address) && address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                ? "src=" + CefExtension(ip)
                : "cs1Label=sourceAddress cs1=" + CefExtension(ip));
        }

        if (logEvent.Source is { } source)
        {
            extension.Add("cs2Label=engine cs2=" + source.ToString().ToLowerInvariant());
        }

        // Last: it holds free text, and a truncated message should lose the end of that alone.
        extension.Add("msg=" + CefExtension(logEvent.Message));
        return text.AppendJoin(' ', extension).ToString();
    }

    private static string EventName(int eventId) => eventId switch
    {
        WinGuardEventIds.Blocked => "Address banned",
        WinGuardEventIds.ManualBlock => "Address blocked by an administrator",
        WinGuardEventIds.BanExpired => "Ban expired",
        WinGuardEventIds.ManualUnblock => "Address unblocked by an administrator",
        WinGuardEventIds.RangeUnblocked => "Range ban lifted",
        WinGuardEventIds.NotificationsSuppressed => "Notifications suppressed",
        WinGuardEventIds.PossibleCompromise => "Possible compromise",
        WinGuardEventIds.Disarmed => "Enforcement disarmed",
        WinGuardEventIds.Rearmed => "Enforcement rearmed",
        WinGuardEventIds.DisarmRefused => "Disarm file ignored",
        WinGuardEventIds.Error => "Error",
        WinGuardEventIds.OtherWarning => "Warning",
        _ => "Information",
    };

    /// <summary>Control characters as readable escapes, the way the log file shows them.</summary>
    private static string Escape(string? text)
    {
        var result = new StringBuilder((text ?? string.Empty).Length);
        foreach (var c in text ?? string.Empty)
        {
            if (char.IsControl(c) || c is (char)0x2028 or (char)0x2029)
            {
                result.Append(c switch
                {
                    '\r' => "\\r",
                    '\n' => "\\n",
                    '\t' => "\\t",
                    _ => "\\x" + ((int)c).ToString("X2", CultureInfo.InvariantCulture),
                });
            }
            else
            {
                result.Append(c);
            }
        }

        return result.ToString();
    }

    /// <summary>CEF header fields escape the backslash and the pipe; no line breaks there at all.</summary>
    private static string CefHeader(string text) =>
        Escape(text).Replace("\\", "\\\\", StringComparison.Ordinal).Replace("|", "\\|", StringComparison.Ordinal);

    /// <summary>CEF extension values escape the backslash and the equals sign; a line break is a literal \n.</summary>
    private static string CefExtension(string? text)
    {
        var result = new StringBuilder((text ?? string.Empty).Length);
        foreach (var c in text ?? string.Empty)
        {
            result.Append(c switch
            {
                '\\' => "\\\\",
                '=' => "\\=",
                '\r' => string.Empty,
                '\n' => "\\n",
                _ => char.IsControl(c) || c is (char)0x2028 or (char)0x2029 ? " " : c.ToString(),
            });
        }

        return result.ToString();
    }

    /// <summary>At most this many bytes, cut between characters so the end is still valid UTF-8.</summary>
    private static byte[] Truncate(string text, int maxBytes)
    {
        var bytes = Utf8.GetBytes(text);
        if (bytes.Length <= maxBytes)
        {
            return bytes;
        }

        var end = Math.Max(0, maxBytes);
        while (end > 0 && (bytes[end] & 0xC0) == 0x80)
        {
            end--;
        }

        return bytes[..end];
    }
}
