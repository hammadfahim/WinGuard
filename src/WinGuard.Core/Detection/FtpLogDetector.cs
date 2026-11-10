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

    // Only what comes before the 530 is searched: the session marker has to be there, and this
    // regex must see the first marker on the line, so it stays on the backtracking engine, which
    // guarantees that. NonBacktracking returned a later marker here, one a client could type.
    private static readonly Regex FileZillaLoginRegex = new(
        @"(?:\((?<parenUser>[^()]*)\)\s*)?(?<bareUser>[^\s()]+)?\s*\((?<ip>[^()]+)\)>",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    // A server response starts right after the id, time, user and address. A "530 Login" further
    // along is text a client typed, and a long one would be slow for the regex above.
    private const int MaxFileZillaPrefixChars = 1024;

    private static readonly Regex FileZillaTimestampRegex = new(
        @"^\s*\(\d+\)\s+(?<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private readonly Func<WinGuardSettings> _settingsAccessor;
    private readonly ILogger<FtpLogDetector> _logger;
    private readonly TimeProvider _timeProvider;
    private readonly LogFileTailer _tailer = new();
    private readonly FileChangeSignal _signal = new();

    // Sources that were already polled at least once: a file that shows up under one of them
    // later is new (e.g. the next daily log) and is read from its first line.
    private readonly WatchedSources _sources = new();
    private volatile bool _loopRunning;

    // How far back a busy file is searched for its last #Fields: line before settling for the first.
    private const long MaxFieldsHeaderScanBytes = 64 * 1024 * 1024;
    private const int FieldsHeaderBlockBytes = 1024 * 1024;
    private const int MaxFieldsHeaderBytes = 16 * 1024;

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

        // W3C lines are rectangular. A different token count means the columns cannot be trusted
        // (a raw space in a client field would shift c-ip), so the line is dropped, not guessed at.
        var fields = ParseFields(fieldsHeaderLine);
        var tokens = trimmed.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length != fields.Length)
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
            RawLog = DetectorUtil.LimitRawLog(trimmed),
        };
        return true;
    }

    /// <summary>
    /// Parses one FileZilla Server log line. The session IP is the first <c>(address)&gt;</c> marker
    /// and the 530 response must follow it directly: FileZilla also logs client commands verbatim,
    /// so anything later on the line may be typed by the client, and a line of any other shape is
    /// dropped instead of being attributed to an address the client chose. The user is an optional
    /// token immediately before that address, which is either <c>(name)</c> (e.g.
    /// <c>(not logged in)</c>, which maps to a null user) or a bare name after login (e.g.
    /// <c>admin (ip)&gt;</c>). Only lines containing <c>"530 Login or password incorrect!"</c> match.
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
        if (responseIndex < 0 || responseIndex > MaxFileZillaPrefixChars)
        {
            return false;
        }

        string? user = null;
        string? rawIp;
        var match = FileZillaLoginRegex.Match(trimmed, 0, responseIndex);
        if (match.Success)
        {
            if (!string.IsNullOrWhiteSpace(trimmed[(match.Index + match.Length)..responseIndex]))
            {
                return false;
            }

            rawIp = match.Groups["ip"].Value;
            var parenUser = match.Groups["parenUser"].Success ? match.Groups["parenUser"].Value : null;
            var bareUser = match.Groups["bareUser"].Success ? match.Groups["bareUser"].Value : null;
            user = NormalizeFileZillaUser(parenUser) ?? NormalizeFileZillaUser(bareUser);
        }
        else
        {
            rawIp = FirstIpToken(trimmed[..responseIndex]);
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
            RawLog = DetectorUtil.LimitRawLog(trimmed),
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
                else if (_sources.Count > 0)
                {
                    // Disabled: forget positions so re-enabling starts at the end of each file
                    // instead of replaying what was logged in the meantime.
                    _sources.Clear();
                    _tailer.Prune([]);
                    _fieldsHeaders.Clear();
                    _headerPreReadDone.Clear();
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

    internal void PollOnce(WinGuardSettings settings, Channel<FailedLogin> sink)
    {
        var activeFiles = new List<string>();
        foreach (var source in settings.Ftp.Sources ?? [])
        {
            if (source is null || string.IsNullOrWhiteSpace(source.Path))
            {
                continue;
            }

            var sourceKey = $"{source.Kind}|{source.Path.Trim()}";
            var watched = _sources.Resolve(sourceKey, source.Path, source.Kind == FtpServerKind.FileZilla ? "*" : "*.log");
            if (watched.BecameUnavailable)
            {
                _logger.LogWarning("FTP source {Path} cannot be read right now; its files continue where they stopped once it can.", source.Path);
            }
            else if (watched.Returned)
            {
                _logger.LogInformation("FTP source {Path} can be read again.", source.Path);
            }

            foreach (var file in watched.Files)
            {
                activeFiles.Add(file);
                var lines = _tailer.ReadNewLines(file, readFromStartIfNew: watched.ReadNewFilesFromStart);

                // Only for a file that has new lines: a log folder can hold years of old logs.
                if (source.Kind != FtpServerKind.FileZilla && lines.Count > 0)
                {
                    EnsureFieldsHeaderPreRead(file);
                }

                foreach (var line in lines)
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

        // A source that cannot be listed keeps the positions of its files: see WatchedSources.
        _tailer.Prune(activeFiles.Concat(_sources.HeldFiles));
        _sources.EndCycle();
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
    /// <c>#Fields:</c> header IIS wrote earlier is never streamed to us. Search the file for
    /// the last one, once, to recover the active column order; without this, servers with
    /// a custom W3C field selection would be parsed with <see cref="DefaultW3cFields"/> and
    /// could silently mis-detect (integrator fix for the skip-to-end interaction).
    /// </summary>
    private void EnsureFieldsHeaderPreRead(string file)
    {
        // Attempt the search once per file, not on every poll cycle.
        if (_fieldsHeaders.ContainsKey(file) || !_headerPreReadDone.Add(file))
        {
            return;
        }

        try
        {
            using var stream = new FileStream(
                file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var header = FindLastFieldsHeader(stream);
            if (header is not null)
            {
                _fieldsHeaders[file] = header;
                _logger.LogDebug("Pre-read the W3C fields header for {File}.", file);
            }
        }
        catch (Exception ex)
        {
            _headerPreReadDone.Remove(file);
            _logger.LogDebug(ex, "Could not pre-read the W3C fields header for {File}; using the default column order.", file);
        }
    }

    /// <summary>
    /// Searches backwards from the end of the file. IIS writes the header when it opens a log, so in
    /// a busy file it can be far behind the tail. A very large file is searched up to
    /// <see cref="MaxFieldsHeaderScanBytes"/> back and then at its start, where the first header is.
    /// </summary>
    internal static string? FindLastFieldsHeader(Stream stream)
    {
        var length = stream.Length;
        var buffer = new byte[FieldsHeaderBlockBytes + MaxFieldsHeaderBytes];
        for (var end = length; end > 0 && length - end < MaxFieldsHeaderScanBytes; end -= FieldsHeaderBlockBytes)
        {
            var header = FindFieldsHeaderInBlock(stream, Math.Max(0, end - FieldsHeaderBlockBytes), end, buffer);
            if (header is not null)
            {
                return header;
            }
        }

        return length > MaxFieldsHeaderScanBytes
            ? FindFieldsHeaderInBlock(stream, 0, FieldsHeaderBlockBytes, buffer)
            : null;
    }

    /// <summary>The last header starting in a block; the read runs past its end to complete one that straddles it.</summary>
    private static string? FindFieldsHeaderInBlock(Stream stream, long start, long end, byte[] buffer)
    {
        stream.Seek(start, SeekOrigin.Begin);
        var count = stream.ReadAtLeast(
            buffer.AsSpan(0, (int)(end - start) + MaxFieldsHeaderBytes),
            (int)(end - start) + MaxFieldsHeaderBytes,
            throwOnEndOfStream: false);

        // Latin-1 maps bytes to chars one to one, so a stray byte cannot shift anything, and the
        // field names the parser needs are ASCII.
        var text = System.Text.Encoding.Latin1.GetString(buffer, 0, count);
        for (var index = text.LastIndexOf("#Fields:", StringComparison.OrdinalIgnoreCase);
            index >= 0;
            index = index == 0 ? -1 : text.LastIndexOf("#Fields:", index - 1, StringComparison.OrdinalIgnoreCase))
        {
            if (index == 0 ? start == 0 : text[index - 1] is '\n')
            {
                var lineEnd = text.IndexOf('\n', index);
                return (lineEnd < 0 ? text[index..] : text[index..lineEnd]).Trim();
            }
        }

        return null;
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