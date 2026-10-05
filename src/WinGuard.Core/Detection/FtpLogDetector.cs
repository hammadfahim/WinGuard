using System.Globalization;
using System.Text.RegularExpressions;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using WinGuard.Core.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Engine;
using WinGuard.Core.Model;

namespace WinGuard.Core.Detection;

/// <summary>
/// FTP detector for IIS FTP (W3C logs) and FileZilla Server (text logs), which do not write
/// failures to the Windows event log (PLAN.md §4.4).
/// <para>
/// It polls <see cref="FtpSettings.Sources"/> every <see cref="FtpSettings.PollInterval"/> using
/// the shared <see cref="LogFileTailer"/>, parsing only newly appended lines. IIS lines are
/// flagged when <c>cs-method == PASS</c> and <c>sc-status == 530</c>; FileZilla lines are flagged
/// on a <c>530 Login…</c> response (<c>"530 Login or password incorrect!"</c> in Server 0.9.x,
/// <c>"530 Login incorrect."</c> in 1.x). The failure timestamp comes from the log line
/// itself: IIS W3C <c>date</c>+<c>time</c> columns are UTC, and the FileZilla leading
/// <c>(nnnnnn) yyyy-MM-dd HH:mm:ss</c> stamp is local time converted to UTC. Only when the
/// line carries no parseable timestamp does the parser fall back to <see cref="DateTime.UtcNow"/>.
/// </para>
/// </summary>
public sealed class FtpLogDetector : IDetector
{
    /// <summary>Detector discriminator stamped on failures parsed from IIS W3C logs.</summary>
    public const string IisDetectorName = "iis-ftp";

    /// <summary>Detector discriminator stamped on failures parsed from FileZilla Server logs.</summary>
    public const string FileZillaDetectorName = "filezilla";

    private static readonly string[] DefaultW3cFields =
    [
        "date", "time", "c-ip", "cs-username", "s-ip", "s-port", "cs-method", "cs-uri-stem",
        "sc-status", "sc-substatus", "sc-win32-status", "time-taken",
    ];

    private static readonly Regex FileZillaLoginRegex = new(
        @"(?:\((?<parenUser>[^()]*)\)\s*)?(?<bareUser>[^\s()]+)?\s*\((?<ip>[^()]+)\)>",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex FileZillaTimestampRegex = new(
        @"^\s*\(\d+\)\s+(?<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex ParenthesizedRegex = new(
        @"\((?<value>[^()]*)\)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private readonly Func<WinGuardSettings> _settingsAccessor;
    private readonly ILogger<FtpLogDetector> _logger;
    private readonly TimeProvider _timeProvider;
    private readonly LogFileTailer _tailer = new();
    private readonly FileChangeSignal _signal = new();

    // Sources that were already polled at least once: a file that shows up under one of them
    // later is new (e.g. the next daily log) and is read from its first line.
    private HashSet<string> _knownSources = new(StringComparer.OrdinalIgnoreCase);
    private volatile bool _loopRunning;
    private readonly Dictionary<string, string> _fieldsHeaders = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _headerPreReadDone = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Creates the detector.</summary>
    /// <param name="settingsAccessor">Returns the current live settings.</param>
    /// <param name="logger">Logger for polling diagnostics.</param>
    /// <param name="timeProvider">Clock abstraction; defaults to <see cref="TimeProvider.System"/>.</param>
    public FtpLogDetector(
        Func<WinGuardSettings> settingsAccessor,
        ILogger<FtpLogDetector> logger,
        TimeProvider? timeProvider = null)
    {
        _settingsAccessor = settingsAccessor;
        _logger = logger;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public ProtocolSource Source => ProtocolSource.Ftp;

    /// <inheritdoc />
    public string Name => "FTP (IIS/FileZilla logs)";

    /// <inheritdoc />
    public bool IsRunning => _loopRunning;

    /// <inheritdoc />
    public Task StartAsync(Channel<FailedLogin> sink, CancellationToken ct)
    {
        // The loop always runs (Enabled is re-checked every cycle) so enabling FTP in the GUI
        // takes effect without a service restart.
        _ = Task.Run(() => PollLoopAsync(sink, ct), CancellationToken.None);
        _logger.LogInformation("FTP log detector started.");
        return Task.CompletedTask;
    }

    /// <summary>
    /// Parses one IIS FTP W3C log line using the latest <c>#Fields:</c> header. Returns
    /// <see langword="true"/> only for <c>PASS</c> requests answered with status <c>530</c>.
    /// </summary>
    /// <param name="line">A single W3C data line (header/comment lines return false).</param>
    /// <param name="fieldsHeaderLine">
    /// The latest <c>#Fields:</c> line for the file, or null to assume <see cref="DefaultW3cFields"/>.
    /// </param>
    /// <param name="failed">The parsed failure when the method returns <see langword="true"/>.</param>
    public static bool TryParseIisLine(string line, string? fieldsHeaderLine, out FailedLogin? failed)
    {
        failed = null;
        if (string.IsNullOrWhiteSpace(line))
        {
            return false;
        }

        var trimmed = line.Trim();
        if (trimmed.Length == 0 || trimmed[0] == '#')
        {
            return false;
        }

        var fields = ParseFields(fieldsHeaderLine);
        var tokens = trimmed.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length == 0)
        {
            return false;
        }

        string? Get(string name)
        {
            for (var i = 0; i < fields.Length && i < tokens.Length; i++)
            {
                if (string.Equals(fields[i], name, StringComparison.OrdinalIgnoreCase))
                {
                    return tokens[i];
                }
            }

            return null;
        }

        var method = Get("cs-method");
        var status = Get("sc-status");
        if (!string.Equals(method, "PASS", StringComparison.OrdinalIgnoreCase)
            || !string.Equals(status, "530", StringComparison.Ordinal))
        {
            return false;
        }

        if (!IpMatcher.TryNormalize(Get("c-ip"), out var ip))
        {
            return false;
        }

        failed = new FailedLogin
        {
            IpAddress = ip,
            UserName = NormalizeOptional(Get("cs-username")),
            Source = ProtocolSource.Ftp,
            Detector = IisDetectorName,
            TimestampUtc = ParseIisTimestamp(Get("date"), Get("time")),
            RawLog = trimmed,
        };
        return true;
    }

    /// <summary>
    /// Parses one FileZilla Server log line. The session IP is the last <c>(address)</c> token
    /// before <c>'&gt;'</c>; the user is an optional token immediately before that address, which
    /// is either <c>(name)</c> (e.g. <c>(not logged in)</c>, which maps to a null user) or a bare
    /// name after login (e.g. <c>admin (ip)&gt;</c>). Only lines containing
    /// <c>"530 Login or password incorrect!"</c> match.
    /// </summary>
    /// <param name="line">A single FileZilla log line.</param>
    /// <param name="failed">The parsed failure when the method returns <see langword="true"/>.</param>
    public static bool TryParseFileZillaLine(string line, out FailedLogin? failed)
    {
        failed = null;
        if (string.IsNullOrWhiteSpace(line))
        {
            return false;
        }

        var trimmed = line.Trim();
        // "530 Login or password incorrect!" (Server 0.9.x) and "530 Login incorrect." (1.x).
        var responseIndex = trimmed.IndexOf("530 Login", StringComparison.OrdinalIgnoreCase);
        if (responseIndex < 0)
        {
            return false;
        }

        string? user = null;
        string? rawIp;
        var match = FileZillaLoginRegex.Match(trimmed);
        if (match.Success && match.Index < responseIndex)
        {
            rawIp = match.Groups["ip"].Value;
            var parenUser = match.Groups["parenUser"].Success ? match.Groups["parenUser"].Value : null;
            var bareUser = match.Groups["bareUser"].Success ? match.Groups["bareUser"].Value : null;
            user = NormalizeFileZillaUser(parenUser) ?? NormalizeFileZillaUser(bareUser);
        }
        else
        {
            rawIp = LastParenthesizedIp(trimmed) ?? FirstIpToken(trimmed[..responseIndex]);
        }

        if (rawIp is null || !IpMatcher.TryNormalize(rawIp, out var ip))
        {
            return false;
        }

        failed = new FailedLogin
        {
            IpAddress = ip,
            UserName = user,
            Source = ProtocolSource.Ftp,
            Detector = FileZillaDetectorName,
            TimestampUtc = ParseFileZillaTimestamp(trimmed),
            RawLog = trimmed,
        };
        return true;
    }

    private async Task PollLoopAsync(Channel<FailedLogin> sink, CancellationToken ct)
    {
        _loopRunning = true;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var settings = _settingsAccessor();

                // Enabled is re-checked every cycle so a hot settings reload takes effect.
                if (settings.Ftp.Enabled)
                {
                    try
                    {
                        PollOnce(settings, sink);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "FTP detector poll cycle failed.");
                    }
                }
                else if (_knownSources.Count > 0)
                {
                    // Disabled: forget positions so re-enabling starts at the end of each file
                    // instead of replaying what was logged in the meantime.
                    _knownSources = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    _tailer.Prune([]);
                }

                var interval = settings.Ftp.PollInterval > TimeSpan.Zero ? settings.Ftp.PollInterval : Defaults.FtpPollInterval;
                try
                {
                    await _signal.WaitAsync(interval, _timeProvider, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "FTP detector poll loop terminated unexpectedly.");
        }
        finally
        {
            _loopRunning = false;
            _signal.Dispose();
        }
    }

    private void PollOnce(WinGuardSettings settings, Channel<FailedLogin> sink)
    {
        var activeFiles = new List<string>();
        var seenSources = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var source in settings.Ftp.Sources ?? [])
        {
            if (source is null || string.IsNullOrWhiteSpace(source.Path))
            {
                continue;
            }

            var sourceKey = $"{source.Kind}|{source.Path.Trim()}";
            var sourceKnown = _knownSources.Contains(sourceKey);
            seenSources.Add(sourceKey);

            var files = source.Kind == FtpServerKind.FileZilla
                ? LogFileTailer.ResolveFiles(source.Path, "*")
                : LogFileTailer.ResolveFiles(source.Path, "*.log");

            foreach (var file in files)
            {
                activeFiles.Add(file);
                if (source.Kind != FtpServerKind.FileZilla)
                {
                    EnsureFieldsHeaderPreRead(file);
                }

                foreach (var line in _tailer.ReadNewLines(file, readFromStartIfNew: sourceKnown))
                {
                    if (source.Kind == FtpServerKind.FileZilla)
                    {
                        if (TryParseFileZillaLine(line, out var fileZillaFailure) && fileZillaFailure is not null)
                        {
                            Emit(sink, fileZillaFailure);
                        }
                    }
                    else
                    {
                        if (TryUpdateFieldsHeader(file, line))
                        {
                            continue;
                        }

                        var header = _fieldsHeaders.GetValueOrDefault(file);
                        if (TryParseIisLine(line, header, out var iisFailure) && iisFailure is not null)
                        {
                            Emit(sink, iisFailure);
                        }
                    }
                }
            }
        }

        _knownSources = seenSources;
        _tailer.Prune(activeFiles);
        _signal.Watch(activeFiles);

        var activeSet = new HashSet<string>(activeFiles, StringComparer.OrdinalIgnoreCase);
        foreach (var key in _fieldsHeaders.Keys.Where(k => !activeSet.Contains(k)).ToList())
        {
            _fieldsHeaders.Remove(key);
        }

        _headerPreReadDone.RemoveWhere(k => !activeSet.Contains(k));
    }

    private void Emit(Channel<FailedLogin> sink, FailedLogin failure)
    {
        // The log line's own timestamp is authoritative: IIS W3C date+time are UTC and the
        // FileZilla leading stamp is local time converted to UTC by the parser. The parser only
        // falls back to DateTime.UtcNow when the line carries no parseable timestamp. The poller
        // clock is deliberately NOT stamped here, so tail lag or replays cannot distort the
        // BanEngine's rolling count window.
        if (!sink.Writer.TryWrite(failure))
        {
            _logger.LogWarning("FTP detector could not write to the sink channel (closed).");
        }
    }

    private bool TryUpdateFieldsHeader(string file, string line)
    {
        var trimmed = line.TrimStart();
        if (trimmed.StartsWith("#Fields:", StringComparison.OrdinalIgnoreCase))
        {
            _fieldsHeaders[file] = trimmed;
            return true;
        }

        return false;
    }

    /// <summary>
    /// The tailer skips existing content the first time it sees a file, so the
    /// <c>#Fields:</c> header IIS wrote earlier is never streamed to us. Pre-read the file's
    /// tail (last 64 KB) once to recover the active column order; without this, servers with
    /// a custom W3C field selection would be parsed with <see cref="DefaultW3cFields"/> and
    /// could silently mis-detect (integrator fix for the skip-to-end interaction).
    /// </summary>
    private void EnsureFieldsHeaderPreRead(string file)
    {
        // Attempt the 64 KB tail pre-read once per file, not on every poll cycle.
        if (_fieldsHeaders.ContainsKey(file) || !_headerPreReadDone.Add(file))
        {
            return;
        }

        try
        {
            using var stream = new FileStream(
                file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            const int tailBytes = 64 * 1024;
            if (stream.Length == 0)
            {
                return;
            }

            var length = (int)Math.Min(stream.Length, tailBytes);
            stream.Seek(-length, SeekOrigin.End);
            var buffer = new byte[length];
            var read = stream.Read(buffer, 0, length);
            var text = System.Text.Encoding.UTF8.GetString(buffer, 0, read);

            string? lastHeader = null;
            foreach (var line in text.Split('\n'))
            {
                if (line.TrimStart().StartsWith("#Fields:", StringComparison.OrdinalIgnoreCase))
                {
                    lastHeader = line.Trim();
                }
            }

            if (lastHeader is not null)
            {
                _fieldsHeaders[file] = lastHeader;
                _logger.LogDebug("Pre-read the W3C fields header for {File}.", file);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not pre-read the W3C fields header for {File}; using the default column order.", file);
        }
    }

    private static string[] ParseFields(string? fieldsHeaderLine)
    {
        if (string.IsNullOrWhiteSpace(fieldsHeaderLine))
        {
            return DefaultW3cFields;
        }

        var header = fieldsHeaderLine.Trim();
        const string prefix = "#Fields:";
        if (header.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            header = header[prefix.Length..];
        }
        else if (header.StartsWith("#Fields", StringComparison.OrdinalIgnoreCase))
        {
            header = header["#Fields".Length..];
        }

        var fields = header.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        return fields.Length == 0 ? DefaultW3cFields : fields;
    }

    private static string? LastParenthesizedIp(string line)
    {
        var arrow = line.IndexOf('>');
        var region = arrow >= 0 ? line[..arrow] : line;
        string? found = null;
        foreach (Match match in ParenthesizedRegex.Matches(region))
        {
            var candidate = match.Groups["value"].Value;
            if (IpMatcher.TryNormalize(candidate, out _))
            {
                found = candidate;
            }
        }

        return found;
    }

    /// <summary>
    /// The first whitespace/bracket-delimited token that is a valid IP. Used for log layouts the
    /// legacy pattern does not match (FileZilla Server 1.x writes the session address in the line
    /// prefix). Only the text BEFORE the server's 530 response is searched, and the first address
    /// wins, so nothing the client typed later on the line can be mistaken for the session address.
    /// </summary>
    private static string? FirstIpToken(string text)
    {
        foreach (var token in text.Split([' ', '\t', '[', ']', '(', ')', '<', '>', ',', ';'], StringSplitOptions.RemoveEmptyEntries))
        {
            if (IpMatcher.TryNormalize(token, out _))
            {
                return token;
            }
        }

        return null;
    }

    private static string? NormalizeOptional(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var trimmed = value.Trim();
        return trimmed == "-" ? null : trimmed;
    }

    /// <summary>
    /// Parses the W3C <c>date</c>+<c>time</c> columns as a UTC timestamp. W3C/ IIS FTP logs
    /// record UTC; an unparsable or missing pair falls back to <see cref="DateTime.UtcNow"/>.
    /// </summary>
    private static DateTime ParseIisTimestamp(string? date, string? time)
    {
        if (!string.IsNullOrWhiteSpace(date)
            && !string.IsNullOrWhiteSpace(time)
            && DateTime.TryParseExact(
                $"{date.Trim()} {time.Trim()}",
                "yyyy-MM-dd HH:mm:ss",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var parsed))
        {
            return DateTime.SpecifyKind(parsed, DateTimeKind.Utc);
        }

        return DateTime.UtcNow;
    }

    /// <summary>
    /// Parses the leading FileZilla <c>(nnnnnn) yyyy-MM-dd HH:mm:ss</c> stamp as local time and
    /// converts it to UTC. A missing/unparsable stamp falls back to <see cref="DateTime.UtcNow"/>.
    /// </summary>
    private static DateTime ParseFileZillaTimestamp(string line)
    {
        var match = FileZillaTimestampRegex.Match(line);
        if (match.Success
            && DateTime.TryParseExact(
                match.Groups["ts"].Value,
                "yyyy-MM-dd HH:mm:ss",
                CultureInfo.InvariantCulture,
                DateTimeStyles.None,
                out var parsed))
        {
            return DateTime.SpecifyKind(parsed, DateTimeKind.Local).ToUniversalTime();
        }

        // FileZilla Server 1.x starts the line with an ISO-8601 stamp, optionally in < > or [ ].
        var space = line.IndexOf(' ');
        var first = (space > 0 ? line[..space] : line).Trim('<', '>', '[', ']');
        if (first.Length >= 19 && first[10] == 'T'
            && DateTimeOffset.TryParse(
                first,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var iso))
        {
            return iso.UtcDateTime;
        }

        return DateTime.UtcNow;
    }

    /// <summary>
    /// Normalizes a FileZilla user token: <c>-</c> and the pre-login marker
    /// <c>"(not logged in)"</c> (with or without its parentheses, case-insensitive) mean no user.
    /// </summary>
    private static string? NormalizeFileZillaUser(string? value)
    {
        var normalized = NormalizeOptional(value);
        if (normalized is null)
        {
            return null;
        }

        return normalized.Equals("not logged in", StringComparison.OrdinalIgnoreCase)
            || normalized.Equals("(not logged in)", StringComparison.OrdinalIgnoreCase)
            ? null
            : normalized;
    }
}