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
/// Log lines can be attacker-controlled, so each pattern has a 2-second match timeout per line. A
/// line that exceeds it is checked again on the linear-time
/// <see cref="RegexOptions.NonBacktracking"/> engine, which cannot time out on a crafted line. That
/// engine is the rescue and not the default because it can pick a later match than the
/// documented regex semantics on the same line, and later text is more likely to be the client's.
/// A pattern it does not support (lookaround, backreferences) is logged once, and a line that times
/// out on such a pattern is skipped and reported; every other line is still evaluated. An invalid
/// pattern is logged once and its source skipped.
/// </para>
/// </summary>
public sealed class CustomLogDetector : IDetector
{
    /// <summary>Fallback detector discriminator for a custom source without a configured name.</summary>
    public const string DefaultDetectorName = "custom";

    private static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(2);

    // Slow lines keep being reported, but not more often than this.
    private static readonly TimeSpan SlowLinesWarningInterval = TimeSpan.FromMinutes(5);

    private readonly Func<WinGuardSettings> _settingsAccessor;
    private readonly ILogger<CustomLogDetector> _logger;
    private readonly TimeProvider _timeProvider;
    private readonly LogFileTailer _tailer = new();
    private readonly FileChangeSignal _signal = new();

    // Sources already polled at least once: a file appearing under one of them later is new.
    private readonly WatchedSources _sources = new();
    private volatile bool _loopRunning;

    // After this many full timeouts in a cycle a source stops spending seconds per line: its
    // remaining lines go straight to the linear engine, or get HurriedMatchTimeout without one.
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

    /// <summary>Per-line regex budget once a source without a linear engine has used up <see cref="MaxTimeoutsPerCycle"/>.</summary>
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
            regex = new Regex(regexPattern, RegexOptions.Compiled | RegexOptions.CultureInvariant, RegexTimeout);
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
            var linear = CompileLinear(regexPattern, RegexTimeout);
            try
            {
                return linear is not null && TryMatch(linear, line, out failed);
            }
            catch (RegexMatchTimeoutException)
            {
                failed = null;
                return false;
            }
        }
    }

    /// <summary>The pattern on the linear-time engine, or null when it uses something that engine lacks.</summary>
    private static Regex? CompileLinear(string pattern, TimeSpan timeout)
    {
        try
        {
            return new Regex(pattern, RegexOptions.NonBacktracking | RegexOptions.CultureInvariant, timeout);
        }
        catch (NotSupportedException)
        {
            return null;
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
            var active = new ActiveSource(matcher, DisplayName(source));
            activeSources.Add(active);
            var pathGlob = CustomSourceRecipes.UpgradePathGlob(source.PathGlob, source.Regex);
            var resolved = _sources.Resolve(sourceKey, pathGlob, "*");
            if (resolved.BecameUnavailable)
            {
                _logger.LogWarning("Custom source '{Source}' cannot read {Path} right now; its files continue where they stopped once it can.", active.DetectorName, pathGlob);
            }
            else if (resolved.Returned)
            {
                _logger.LogInformation("Custom source '{Source}' can read {Path} again.", active.DetectorName, pathGlob);
            }

            foreach (var file in resolved.Files)
            {
                if (!files.TryGetValue(file, out var watched))
                {
                    files[file] = watched = new WatchedFile();
                }

                // A file new to the tailer but under a known source appeared since the last poll,
                // so all of it is recent for a source added at the same moment too.
                watched.ReadFromStartIfNew |= resolved.ReadNewFilesFromStart;
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
            ReportSlowLines(active);
        }

        // A source that cannot be listed keeps the positions of its files: see WatchedSources.
        _tailer.Prune(files.Keys.Concat(_sources.HeldFiles));
        _sources.EndCycle();
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
    /// Runs one source's regex against one line. A timeout costs at most that line, counted for
    /// <see cref="ReportSlowLines"/>: later lines and other sources are still evaluated, so a
    /// crafted line cannot hide what comes after it.
    /// </summary>
    private void Evaluate(string line, ActiveSource active, Channel<FailedLogin> sink)
    {
        if (!TryMatchWithinBudget(line, active, out var failure) || failure is null)
        {
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

    private static bool TryMatchWithinBudget(string line, ActiveSource active, out FailedLogin? failure)
    {
        var matcher = active.Matcher;
        var withinBudget = active.TimeoutsThisCycle < MaxTimeoutsPerCycle;
        try
        {
            return TryMatch(withinBudget ? matcher.Regex : matcher.LinearRegex ?? matcher.HurriedRegex, line, out failure);
        }
        catch (RegexMatchTimeoutException)
        {
            active.TimeoutsThisCycle++;
            matcher.SlowLines++;
        }

        if (withinBudget && matcher.LinearRegex is not null)
        {
            try
            {
                return TryMatch(matcher.LinearRegex, line, out failure);
            }
            catch (RegexMatchTimeoutException)
            {
                // Linear in the length of the line, but a very long one can still run out of time.
            }
        }

        matcher.SkippedLines++;
        failure = null;
        return false;
    }

    /// <summary>A skipped line may have been a failed login, so it is always reported, in rate-limited totals.</summary>
    private void ReportSlowLines(ActiveSource active)
    {
        var matcher = active.Matcher;
        var now = _timeProvider.GetUtcNow();
        if (matcher.SlowLines == 0 || now - matcher.LastSlowLinesWarning < SlowLinesWarningInterval)
        {
            return;
        }

        _logger.LogWarning(
            "Custom log source {Source}: {Slow} line(s) exceeded the regex match timeout, which a crafted line can cause; {Skipped} could not be checked, so a failed login on those is not counted. Simplify the regex.",
            active.DetectorName,
            matcher.SlowLines,
            matcher.SkippedLines);
        matcher.SlowLines = 0;
        matcher.SkippedLines = 0;
        matcher.LastSlowLinesWarning = now;
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
            var regex = new Regex(source.Regex, RegexOptions.Compiled | RegexOptions.CultureInvariant, MatchTimeout);
            var linear = CompileLinear(source.Regex, MatchTimeout);
            if (linear is null)
            {
                _logger.LogWarning(
                    "Custom log source {Source}: the regex uses lookaround, a backreference or another construct that needs backtracking, so a line that runs past the {Timeout}s match timeout is skipped, and a crafted line can make that happen. Rewrite it without them if you can.",
                    DisplayName(source),
                    MatchTimeout.TotalSeconds);
            }

            matcher = new SourceMatcher(
                regex,
                linear,
                linear is null ? new Regex(source.Regex, RegexOptions.CultureInvariant, HurriedMatchTimeout) : regex);
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

    /// <summary>Longest user name kept from a custom log; the client chooses it, so it can be any length.</summary>
    internal const int MaxUserNameLength = 256;

    private static string? NormalizeOptional(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var trimmed = value.Trim();
        if (trimmed == "-")
        {
            return null;
        }

        return trimmed.Length > MaxUserNameLength ? trimmed[..MaxUserNameLength] : trimmed;
    }

    /// <summary>A source's compiled regex; lives as long as the pattern stays configured.</summary>
    private sealed class SourceMatcher(Regex regex, Regex? linearRegex, Regex hurriedRegex)
    {
        public Regex Regex { get; } = regex;

        public Regex? LinearRegex { get; } = linearRegex;

        public Regex HurriedRegex { get; } = hurriedRegex;

        public long SlowLines { get; set; }

        public long SkippedLines { get; set; }

        public DateTimeOffset LastSlowLinesWarning { get; set; } = DateTimeOffset.MinValue;
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
