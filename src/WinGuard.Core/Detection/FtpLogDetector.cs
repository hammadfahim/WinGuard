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
/// on <c>"530 Login or password incorrect!"</c>. The failure timestamp is the poller's current UTC
/// time because the timestamps embedded in these heterogeneous log formats are unreliable.
/// </para>
/// </summary>
public sealed class FtpLogDetector : IDetector
{
    private static readonly string[] DefaultW3cFields =
    [
        "date", "time", "c-ip", "cs-username", "s-ip", "s-port", "cs-method", "cs-uri-stem",
        "sc-status", "sc-substatus", "sc-win32-status", "time-taken",
    ];

    private static readonly Regex FileZillaLoginRegex = new(
        @"\((?<user>[^()]+)\)\s*\((?<ip>[^()]+)\)>",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex ParenthesizedRegex = new(
        @"\((?<value>[^()]*)\)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private readonly Func<WinGuardSettings> _settingsAccessor;
    private readonly ILogger<FtpLogDetector> _logger;
    private readonly TimeProvider _timeProvider;
    private readonly LogFileTailer _tailer = new();
    private readonly Dictionary<string, string> _fieldsHeaders = new(StringComparer.OrdinalIgnoreCase);

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
    public Task StartAsync(Channel<FailedLogin> sink, CancellationToken ct)
    {
        if (!_settingsAccessor().Ftp.Enabled)
        {
            _logger.LogInformation("FTP detector is disabled by settings.");
            return Task.CompletedTask;
        }

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
            TimestampUtc = DateTime.UtcNow,
            RawLog = trimmed,
        };
        return true;
    }

    /// <summary>
    /// Parses one FileZilla Server log line, extracting the session IP from the last
    /// <c>(address)</c> token before <c>'&gt;'</c> and the user from the <c>(name (ip)&gt;</c> shape.
    /// Only lines containing <c>"530 Login or password incorrect!"</c> match.
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
        if (trimmed.IndexOf("530 Login or password incorrect!", StringComparison.OrdinalIgnoreCase) < 0)
        {
            return false;
        }

        string? user = null;
        string? rawIp;
        var match = FileZillaLoginRegex.Match(trimmed);
        if (match.Success)
        {
            rawIp = match.Groups["ip"].Value;
            user = NormalizeOptional(match.Groups["user"].Value);
        }
        else
        {
            rawIp = LastParenthesizedIp(trimmed);
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
            TimestampUtc = DateTime.UtcNow,
            RawLog = trimmed,
        };
        return true;
    }

    private async Task PollLoopAsync(Channel<FailedLogin> sink, CancellationToken ct)
    {
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

                var interval = settings.Ftp.PollInterval > TimeSpan.Zero ? settings.Ftp.PollInterval : Defaults.FtpPollInterval;
                try
                {
                    await Task.Delay(interval, _timeProvider, ct).ConfigureAwait(false);
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
    }

    private void PollOnce(WinGuardSettings settings, Channel<FailedLogin> sink)
    {
        var activeFiles = new List<string>();
        foreach (var source in settings.Ftp.Sources ?? [])
        {
            if (source is null || string.IsNullOrWhiteSpace(source.Path))
            {
                continue;
            }

            var files = source.Kind == FtpServerKind.FileZilla
                ? LogFileTailer.ResolveFiles(source.Path, "*")
                : LogFileTailer.ResolveFiles(source.Path, "*.log");

            foreach (var file in files)
            {
                activeFiles.Add(file);
                foreach (var line in _tailer.ReadNewLines(file))
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

        _tailer.Prune(activeFiles);

        var activeSet = new HashSet<string>(activeFiles, StringComparer.OrdinalIgnoreCase);
        foreach (var key in _fieldsHeaders.Keys.Where(k => !activeSet.Contains(k)).ToList())
        {
            _fieldsHeaders.Remove(key);
        }
    }

    private void Emit(Channel<FailedLogin> sink, FailedLogin failure)
    {
        failure.TimestampUtc = _timeProvider.GetUtcNow().UtcDateTime;
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

    private static string? NormalizeOptional(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var trimmed = value.Trim();
        return trimmed == "-" ? null : trimmed;
    }
}