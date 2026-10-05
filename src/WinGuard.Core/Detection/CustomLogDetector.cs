using System.Text.RegularExpressions;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using WinGuard.Core.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Engine;
using WinGuard.Core.Model;

namespace WinGuard.Core.Detection;

/// <summary>
/// Generic log detector (PLAN.md §4.5): tails each configured <see cref="CustomLogSource"/> file
/// (or folder + glob) and applies the source's regex. A regex match yields one
/// <see cref="FailedLogin"/>; the regex must capture a named group <c>ipaddress</c> and may capture
/// an optional named group <c>username</c>. Tailing uses the shared <see cref="LogFileTailer"/> so
/// only appended lines are evaluated. The failure timestamp is the poller's current UTC time
/// (the regex has no guaranteed timestamp capture). Each pattern is compiled once with a 2-second
/// match timeout; an invalid pattern is logged once and its source skipped, and a match timeout is
/// logged once per source and the line skipped.
/// </summary>
public sealed class CustomLogDetector : IDetector
{
    /// <summary>Fallback detector discriminator for a custom source without a configured name.</summary>
    public const string DefaultDetectorName = "custom";

    private static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(2);

    private readonly Func<WinGuardSettings> _settingsAccessor;
    private readonly ILogger<CustomLogDetector> _logger;
    private readonly TimeProvider _timeProvider;
    private readonly LogFileTailer _tailer = new();
    private readonly FileChangeSignal _signal = new();

    // Sources already polled at least once: a file appearing under one of them later is new.
    private HashSet<string> _knownSources = new(StringComparer.OrdinalIgnoreCase);
    private volatile bool _loopRunning;

    // A regex that keeps hitting the match timeout would stall the poll loop for seconds per line.
    private const int MaxTimeoutsPerCycle = 3;

    // Compiled pattern cache keyed by (source name, pattern); a null value marks a known-bad source.
    private readonly Dictionary<(string Source, string Pattern), Regex?> _regexCache = new();
    private readonly HashSet<string> _invalidWarnedSources = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _timeoutWarnedSources = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Creates the detector.</summary>
    /// <param name="settingsAccessor">Returns the current live settings.</param>
    /// <param name="logger">Logger for polling diagnostics.</param>
    /// <param name="timeProvider">Clock abstraction; defaults to <see cref="TimeProvider.System"/>.</param>
    public CustomLogDetector(
        Func<WinGuardSettings> settingsAccessor,
        ILogger<CustomLogDetector> logger,
        TimeProvider? timeProvider = null)
    {
        _settingsAccessor = settingsAccessor;
        _logger = logger;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public ProtocolSource Source => ProtocolSource.Custom;

    /// <inheritdoc />
    public string Name => "Custom log sources";

    /// <inheritdoc />
    public bool IsRunning => _loopRunning;

    /// <inheritdoc />
    public Task StartAsync(Channel<FailedLogin> sink, CancellationToken ct)
    {
        // The loop always runs so hot-added/edited custom sources take effect without a restart;
        // each source's own Enabled flag is re-checked every cycle.
        _ = Task.Run(() => PollLoopAsync(sink, ct), CancellationToken.None);
        var enabled = (_settingsAccessor().CustomSources ?? []).Count(source => source is { Enabled: true });
        _logger.LogInformation("Custom log detector started with {Count} enabled source(s).", enabled);
        return Task.CompletedTask;
    }

    /// <summary>
    /// Applies <paramref name="regexPattern"/> to one log line. The named group <c>ipaddress</c> is
    /// required and must normalize to a valid IP; the optional named group <c>username</c> becomes
    /// the user. At most one failure is produced per line. An invalid pattern or a match timeout
    /// returns <see langword="false"/> without throwing; <see cref="FailedLogin.Detector"/> defaults
    /// to <see cref="DefaultDetectorName"/> when the call is made outside a named source (the live
    /// loop overwrites it with the source's name).
    /// </summary>
    /// <param name="line">A single log line.</param>
    /// <param name="regexPattern">Regex with named groups <c>ipaddress</c> and optional <c>username</c>.</param>
    /// <param name="failed">The parsed failure when the method returns <see langword="true"/>.</param>
    public static bool TryParseLine(string line, string regexPattern, out FailedLogin? failed)
    {
        failed = null;
        if (string.IsNullOrEmpty(line) || string.IsNullOrWhiteSpace(regexPattern))
        {
            return false;
        }

        Regex regex;
        try
        {
            regex = new Regex(
                regexPattern,
                RegexOptions.Compiled | RegexOptions.CultureInvariant,
                RegexTimeout);
        }
        catch (ArgumentException)
        {
            return false;
        }

        try
        {
            return TryMatch(regex, line, out failed);
        }
        catch (RegexMatchTimeoutException)
        {
            failed = null;
            return false;
        }
    }

    private static bool TryMatch(Regex regex, string line, out FailedLogin? failed)
    {
        failed = null;
        if (string.IsNullOrEmpty(line))
        {
            return false;
        }

        var match = regex.Match(line);
        if (!match.Success)
        {
            return false;
        }

        var ipGroup = match.Groups["ipaddress"];
        if (!ipGroup.Success || !IpMatcher.TryNormalize(ipGroup.Value, out var ip))
        {
            return false;
        }

        var userGroup = match.Groups["username"];
        var user = userGroup.Success ? NormalizeOptional(userGroup.Value) : null;

        failed = new FailedLogin
        {
            IpAddress = ip,
            UserName = user,
            Source = ProtocolSource.Custom,
            Detector = DefaultDetectorName,
            TimestampUtc = DateTime.UtcNow,
            RawLog = line.Trim(),
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
                try
                {
                    PollOnce(settings, sink);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Custom log detector poll cycle failed.");
                }

                // Custom sources share the FTP poll interval (PLAN.md §4.5; phase-3 topic #4
                // ruling): read it live each cycle so a settings change takes effect, falling
                // back to the default when it is not positive.
                var interval = settings.Ftp.PollInterval > TimeSpan.Zero
                    ? settings.Ftp.PollInterval
                    : Defaults.FtpPollInterval;
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
            _logger.LogError(ex, "Custom log detector poll loop terminated unexpectedly.");
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
        foreach (var source in settings.CustomSources ?? [])
        {
            if (source is null || !source.Enabled
                || string.IsNullOrWhiteSpace(source.PathGlob)
                || string.IsNullOrWhiteSpace(source.Regex))
            {
                continue;
            }

            // Invalid patterns are reported once and the whole source is skipped for this cycle.
            if (!TryGetSourceRegex(source, out var regex) || regex is null)
            {
                continue;
            }

            var detectorName = DisplayName(source);
            var sourceKey = $"{source.Name}|{source.PathGlob.Trim()}";
            var sourceKnown = _knownSources.Contains(sourceKey);
            seenSources.Add(sourceKey);
            var timeouts = 0;

            foreach (var file in LogFileTailer.ResolveFiles(source.PathGlob, "*"))
            {
                activeFiles.Add(file);
                foreach (var line in _tailer.ReadNewLines(file, readFromStartIfNew: sourceKnown))
                {
                    if (timeouts >= MaxTimeoutsPerCycle)
                    {
                        // Give up on this batch of lines; the next cycle starts after them.
                        break;
                    }

                    if (!TryParseForSource(line, source, regex, out var failure, out var timedOut))
                    {
                        if (timedOut)
                        {
                            timeouts++;
                        }

                        continue;
                    }

                    if (failure is not null)
                    {
                        failure.Detector = detectorName;
                        // Custom regexes have no guaranteed timestamp capture, so the ingest
                        // (poll) time is authoritative for this engine.
                        failure.TimestampUtc = _timeProvider.GetUtcNow().UtcDateTime;
                        if (!sink.Writer.TryWrite(failure))
                        {
                            _logger.LogWarning("Custom log detector could not write to the sink channel (closed).");
                        }
                    }
                }
            }
        }

        _knownSources = seenSources;
        _tailer.Prune(activeFiles);
        _signal.Watch(activeFiles);

        // Keep the compiled-pattern cache to the patterns still configured.
        var live = (settings.CustomSources ?? [])
            .Where(source => source is not null)
            .Select(source => (source.Name ?? string.Empty, source.Regex))
            .ToHashSet();
        foreach (var key in _regexCache.Keys.Where(k => !live.Contains(k)).ToList())
        {
            _regexCache.Remove(key);
        }
    }

    /// <summary>
    /// Returns the cached compiled regex for a source, compiling it on first use. An invalid
    /// pattern is remembered as null, logged once, and reported as unavailable so the source is
    /// skipped instead of silently swallowed.
    /// </summary>
    private bool TryGetSourceRegex(CustomLogSource source, out Regex? regex)
    {
        var key = (source.Name ?? string.Empty, source.Regex);
        if (_regexCache.TryGetValue(key, out regex))
        {
            return regex is not null;
        }

        try
        {
            regex = new Regex(
                source.Regex,
                RegexOptions.Compiled | RegexOptions.CultureInvariant,
                RegexTimeout);
            _regexCache[key] = regex;
            return true;
        }
        catch (ArgumentException ex)
        {
            _regexCache[key] = null;
            if (_invalidWarnedSources.Add(DisplayName(source)))
            {
                _logger.LogWarning(ex, "Custom log source {Source} has an invalid regex; skipping it.", DisplayName(source));
            }

            regex = null;
            return false;
        }
    }

    /// <summary>
    /// Runs a cached regex against one line, converting a match timeout into a skipped line and a
    /// rate-limited (once per source) warning instead of propagating the exception.
    /// </summary>
    private bool TryParseForSource(string line, CustomLogSource source, Regex regex, out FailedLogin? failure, out bool timedOut)
    {
        timedOut = false;
        try
        {
            return TryMatch(regex, line, out failure);
        }
        catch (RegexMatchTimeoutException)
        {
            failure = null;
            timedOut = true;
            if (_timeoutWarnedSources.Add(DisplayName(source)))
            {
                _logger.LogWarning(
                    "Custom log source {Source} regex exceeded the {Timeout}s match timeout; skipping the line.",
                    DisplayName(source),
                    RegexTimeout.TotalSeconds);
            }

            return false;
        }
    }

    private static string DisplayName(CustomLogSource source) =>
        string.IsNullOrWhiteSpace(source.Name) ? DefaultDetectorName : source.Name;

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