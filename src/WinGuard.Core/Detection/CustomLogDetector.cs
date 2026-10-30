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
/// only appended lines are evaluated, and a file watched by several sources is read once with every
/// line offered to each of them. The failure timestamp is the poller's current UTC time (the regex
/// has no guaranteed timestamp capture).
/// <para>
/// Log lines can be attacker-controlled, so patterns run on the linear-time
/// <see cref="RegexOptions.NonBacktracking"/> engine whenever they allow it. A pattern that needs
/// backtracking is logged once and runs with a 2-second match timeout; a line that times out is
/// skipped and reported, and every other line is still evaluated. An invalid pattern is logged once
/// and its source skipped.
/// </para>
/// </summary>
public sealed class CustomLogDetector : IDetector
{
    /// <summary>Fallback detector discriminator for a custom source without a configured name.</summary>
    public const string DefaultDetectorName = "custom";

    private static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(2);

    // Timed-out lines keep being reported, but not more often than this.
    private static readonly TimeSpan SkippedLinesWarningInterval = TimeSpan.FromMinutes(5);

    private readonly Func<WinGuardSettings> _settingsAccessor;
    private readonly ILogger<CustomLogDetector> _logger;
    private readonly TimeProvider _timeProvider;
    private readonly LogFileTailer _tailer = new();
    private readonly FileChangeSignal _signal = new();

    // Sources already polled at least once: a file appearing under one of them later is new.
    private HashSet<string> _knownSources = new(StringComparer.OrdinalIgnoreCase);
    private volatile bool _loopRunning;

    // After this many full timeouts in a cycle a source's remaining lines get HurriedMatchTimeout,
    // so a burst of crafted lines stalls the poll loop briefly instead of for seconds per line.
    private const int MaxTimeoutsPerCycle = 3;

    // Compiled pattern cache keyed by (source name, pattern); a null value marks a known-bad source.
    private readonly Dictionary<(string Source, string Pattern), SourceMatcher?> _regexCache = new();
    private readonly HashSet<string> _invalidWarnedSources = new(StringComparer.OrdinalIgnoreCase);

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

    /// <summary>Per-line regex budget.</summary>
    internal TimeSpan MatchTimeout { get; init; } = RegexTimeout;

    /// <summary>Per-line regex budget once a source has used up <see cref="MaxTimeoutsPerCycle"/>.</summary>
    internal TimeSpan HurriedMatchTimeout { get; init; } = TimeSpan.FromMilliseconds(50);

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
            regex = CompileRegex(regexPattern, RegexTimeout, out _);
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

    /// <summary>
    /// Compiles a source pattern on the linear-time engine, or on the backtracking engine when the
    /// pattern needs it (lookaround, backreferences, atomic groups).
    /// </summary>
    /// <exception cref="ArgumentException">The pattern is invalid.</exception>
    private static Regex CompileRegex(string pattern, TimeSpan timeout, out bool linearTime)
    {
        try
        {
            linearTime = true;
            return new Regex(pattern, RegexOptions.NonBacktracking | RegexOptions.CultureInvariant, timeout);
        }
        catch (NotSupportedException)
        {
            linearTime = false;
            return new Regex(pattern, RegexOptions.Compiled | RegexOptions.CultureInvariant, timeout);
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
            RawLog = DetectorUtil.LimitRawLog(line.Trim()),
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

    internal void PollOnce(WinGuardSettings settings, Channel<FailedLogin> sink)
    {
        // The tailer keeps one cursor per file, so a file is read once here and each line handed to
        // every source on it; reading it per source would leave the second one nothing to see.
        var files = new Dictionary<string, WatchedFile>(StringComparer.OrdinalIgnoreCase);
        var activeSources = new List<ActiveSource>();
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
            if (!TryGetSourceRegex(source, out var matcher) || matcher is null)
            {
                continue;
            }

            var sourceKey = $"{source.Name}|{source.PathGlob.Trim()}";
            var sourceKnown = _knownSources.Contains(sourceKey);
            seenSources.Add(sourceKey);

            var active = new ActiveSource(matcher, DisplayName(source));
            activeSources.Add(active);
            var pathGlob = CustomSourceRecipes.UpgradePathGlob(source.PathGlob, source.Regex);
            foreach (var file in LogFileTailer.ResolveFiles(pathGlob, "*"))
            {
                if (!files.TryGetValue(file, out var watched))
                {
                    files[file] = watched = new WatchedFile();
                }

                // A file new to the tailer but under a known source appeared since the last poll,
                // so all of it is recent for a source added at the same moment too.
                watched.ReadFromStartIfNew |= sourceKnown;
                watched.CrLfRecords |= CustomSourceRecipes.UsesCrLfRecords(source.Regex);
                watched.Sources.Add(active);
            }
        }

        foreach (var (file, watched) in files)
        {
            foreach (var line in _tailer.ReadNewLines(file, watched.ReadFromStartIfNew, watched.CrLfRecords))
            {
                foreach (var active in watched.Sources)
                {
                    Evaluate(line, active, sink);
                }
            }
        }

        foreach (var active in activeSources)
        {
            ReportSkippedLines(active);
        }

        _knownSources = seenSources;
        _tailer.Prune(files.Keys);
        _signal.Watch(files.Keys);

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
    /// Runs one source's regex against one line. A timeout costs only that line, counted for
    /// <see cref="ReportSkippedLines"/>: later lines and other sources are still evaluated, so a
    /// crafted line cannot hide what comes after it.
    /// </summary>
    private void Evaluate(string line, ActiveSource active, Channel<FailedLogin> sink)
    {
        var regex = active.TimeoutsThisCycle < MaxTimeoutsPerCycle ? active.Matcher.Regex : active.Matcher.HurriedRegex;
        FailedLogin? failure;
        try
        {
            if (!TryMatch(regex, line, out failure) || failure is null)
            {
                return;
            }
        }
        catch (RegexMatchTimeoutException)
        {
            active.TimeoutsThisCycle++;
            active.Matcher.SkippedLines++;
            return;
        }

        failure.Detector = active.DetectorName;
        // Custom regexes have no guaranteed timestamp capture, so the ingest
        // (poll) time is authoritative for this engine.
        failure.TimestampUtc = _timeProvider.GetUtcNow().UtcDateTime;
        if (!sink.Writer.TryWrite(failure))
        {
            _logger.LogWarning("Custom log detector could not write to the sink channel (closed).");
        }
    }

    /// <summary>A skipped line may have been a failed login, so it is always reported, in rate-limited totals.</summary>
    private void ReportSkippedLines(ActiveSource active)
    {
        var matcher = active.Matcher;
        var now = _timeProvider.GetUtcNow();
        if (matcher.SkippedLines == 0 || now - matcher.LastSkipWarning < SkippedLinesWarningInterval)
        {
            return;
        }

        _logger.LogWarning(
            "Custom log source {Source}: {Count} line(s) were not checked because the regex exceeded its match timeout; a failed login on such a line is not counted. Simplify the regex.",
            active.DetectorName,
            matcher.SkippedLines);
        matcher.SkippedLines = 0;
        matcher.LastSkipWarning = now;
    }

    /// <summary>
    /// Returns the cached compiled regex for a source, compiling it on first use. An invalid
    /// pattern is remembered as null, logged once, and reported as unavailable so the source is
    /// skipped instead of silently swallowed.
    /// </summary>
    private bool TryGetSourceRegex(CustomLogSource source, out SourceMatcher? matcher)
    {
        var key = (source.Name ?? string.Empty, source.Regex);
        if (_regexCache.TryGetValue(key, out matcher))
        {
            return matcher is not null;
        }

        try
        {
            var regex = CompileRegex(source.Regex, MatchTimeout, out var linearTime);
            if (!linearTime)
            {
                _logger.LogWarning(
                    "Custom log source {Source}: the regex uses lookaround, a backreference or another construct that needs backtracking, so a crafted log line can cost it up to {Timeout}s. Rewrite it without them if you can.",
                    DisplayName(source),
                    MatchTimeout.TotalSeconds);
            }

            matcher = new SourceMatcher(
                regex,
                linearTime ? regex : new Regex(source.Regex, RegexOptions.CultureInvariant, HurriedMatchTimeout));
            _regexCache[key] = matcher;
            return true;
        }
        catch (ArgumentException ex)
        {
            _regexCache[key] = null;
            if (_invalidWarnedSources.Add(DisplayName(source)))
            {
                _logger.LogWarning(ex, "Custom log source {Source} has an invalid regex; skipping it.", DisplayName(source));
            }

            matcher = null;
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

    /// <summary>A source's compiled regex; lives as long as the pattern stays configured.</summary>
    private sealed class SourceMatcher(Regex regex, Regex hurriedRegex)
    {
        public Regex Regex { get; } = regex;

        public Regex HurriedRegex { get; } = hurriedRegex;

        public long SkippedLines { get; set; }

        public DateTimeOffset LastSkipWarning { get; set; } = DateTimeOffset.MinValue;
    }

    /// <summary>One enabled source during one poll cycle.</summary>
    private sealed class ActiveSource(SourceMatcher matcher, string detectorName)
    {
        public SourceMatcher Matcher { get; } = matcher;

        public string DetectorName { get; } = detectorName;

        public int TimeoutsThisCycle { get; set; }
    }

    /// <summary>One file during one poll cycle, with every source that wants its lines.</summary>
    private sealed class WatchedFile
    {
        public List<ActiveSource> Sources { get; } = [];

        public bool ReadFromStartIfNew { get; set; }

        public bool CrLfRecords { get; set; }
    }
}
