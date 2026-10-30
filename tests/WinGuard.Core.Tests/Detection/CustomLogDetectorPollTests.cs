using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Detection;
using WinGuard.Core.Model;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>Poll-cycle behavior of the custom detector: shared files and slow regexes.</summary>
public sealed class CustomLogDetectorPollTests : IDisposable
{
    private const string FailedRegex = @"FAILED ip=(?<ipaddress>\S+)";

    // A backreference forces the backtracking engine; (a+)+ makes it exponential on "aaaa...!".
    private const string CatastrophicRegex = @"^(a+)+\1$|FAILED ip=(?<ipaddress>\S+)";

    private static readonly string CraftedLine = new string('a', 40) + "!\n";

    private readonly string _dir = Directory.CreateTempSubdirectory("winguard-custom-").FullName;

    public void Dispose() => Directory.Delete(_dir, true);

    // Short enough to keep the crafted-line tests quick, long enough that a JIT or GC pause on an
    // ordinary line does not look like a timeout.
    internal static CustomLogDetector NewDetector(ILogger<CustomLogDetector>? logger = null) =>
        new(() => new WinGuardSettings(), logger ?? NullLogger<CustomLogDetector>.Instance)
        {
            MatchTimeout = TimeSpan.FromMilliseconds(250),
            HurriedMatchTimeout = TimeSpan.FromMilliseconds(100),
        };

    internal static Channel<FailedLogin> NewSink() => Channel.CreateUnbounded<FailedLogin>();

    internal static List<FailedLogin> Drain(Channel<FailedLogin> sink)
    {
        var items = new List<FailedLogin>();
        while (sink.Reader.TryRead(out var item))
        {
            items.Add(item);
        }

        return items;
    }

    // ---------- several sources on one file ----------

    [Fact]
    public void Two_sources_on_one_file_both_see_every_line()
    {
        var path = NewFile("shared.log");
        var settings = Settings(
            Source("first", path, @"FIRST ip=(?<ipaddress>\S+)"),
            Source("second", path, @"SECOND ip=(?<ipaddress>\S+)"));
        var detector = NewDetector();
        var sink = NewSink();
        detector.PollOnce(settings, sink);

        File.AppendAllText(path, "FIRST ip=203.0.113.1\nSECOND ip=203.0.113.2\n");
        detector.PollOnce(settings, sink);
        File.AppendAllText(path, "SECOND ip=203.0.113.3\nFIRST ip=203.0.113.4\n");
        detector.PollOnce(settings, sink);

        var failures = Drain(sink);
        Assert.Equal(
            new[] { "203.0.113.1", "203.0.113.4" },
            failures.Where(f => f.Detector == "first").Select(f => f.IpAddress));
        Assert.Equal(
            new[] { "203.0.113.2", "203.0.113.3" },
            failures.Where(f => f.Detector == "second").Select(f => f.IpAddress));
    }

    [Fact]
    public void A_shared_file_is_read_once_per_cycle()
    {
        var path = NewFile("once.log");
        var pattern = @"ip=(?<ipaddress>\S+)";
        var settings = Settings(Source("a", path, pattern), Source("b", path, pattern), Source("c", path, pattern));
        var detector = NewDetector();
        var sink = NewSink();
        detector.PollOnce(settings, sink);

        File.AppendAllText(path, "ip=203.0.113.1\n");
        detector.PollOnce(settings, sink);

        Assert.Equal(new[] { "a", "b", "c" }, Drain(sink).Select(f => f.Detector));
    }

    [Fact]
    public void A_source_added_later_starts_at_the_current_end_of_a_shared_file()
    {
        var path = NewFile("late.log", "ip=203.0.113.9\n");
        var pattern = @"ip=(?<ipaddress>\S+)";
        var first = Source("first", path, pattern);
        var detector = NewDetector();
        var sink = NewSink();
        detector.PollOnce(Settings(first), sink);

        var both = Settings(first, Source("second", path, pattern));
        detector.PollOnce(both, sink);
        File.AppendAllText(path, "ip=203.0.113.1\n");
        detector.PollOnce(both, sink);

        Assert.Equal(new[] { "first", "second" }, Drain(sink).Select(f => f.Detector));
    }

    [Fact]
    public void A_file_new_under_a_known_source_is_read_from_its_start_by_every_source_on_it()
    {
        var folder = Directory.CreateDirectory(Path.Combine(_dir, "daily")).FullName;
        var pattern = @"ip=(?<ipaddress>\S+)";
        var settings = Settings(Source("a", Path.Combine(folder, "*.log"), pattern), Source("b", Path.Combine(folder, "*.log"), pattern));
        var detector = NewDetector();
        var sink = NewSink();
        detector.PollOnce(settings, sink);

        File.WriteAllText(Path.Combine(folder, "today.log"), "ip=203.0.113.1\n");
        detector.PollOnce(settings, sink);

        Assert.Equal(new[] { "a", "b" }, Drain(sink).Select(f => f.Detector));
    }

    // ---------- slow regexes ----------

    [Fact]
    public void A_line_that_times_out_is_checked_again_on_the_linear_engine()
    {
        var path = NewFile("rescued.log");
        var logger = new RecordingLogger();

        // The first alternative is what blows up; the failure on the same line must still be found.
        var settings = Settings(Source("rescued", path, @"^(a+)+$|^(a+)+!(?<ipaddress>\S+)$"));
        var detector = NewDetector(logger);
        var sink = NewSink();
        detector.PollOnce(settings, sink);

        var line = new string('a', 40) + "?203.0.113.9\n";
        File.AppendAllText(path, string.Concat(Enumerable.Repeat(line, 8)) + new string('a', 40) + "!203.0.113.1\n");
        detector.PollOnce(settings, sink);

        Assert.Equal("203.0.113.1", Assert.Single(Drain(sink)).IpAddress);
        var warning = Assert.Single(logger.Warnings);
        Assert.Contains("rescued", warning);
        Assert.Contains("0 could not be checked", warning);
    }

    [Fact]
    public void Ordinary_lines_keep_the_first_match_of_the_regular_engine()
    {
        // On this shape NonBacktracking returns the second marker, which a client could have typed.
        var path = NewFile("first-match.log");
        var settings = Settings(Source("first", path, @"(?:\((?<user>[^()]*)\)\s*)?(?<bare>[^\s()]+)?\s*\((?<ipaddress>[^()]+)\)>"));

        // The production timeout: a pause during a short test budget would hand the line to the
        // linear engine, which is the one case where that engine's answer applies.
        var detector = new CustomLogDetector(() => settings, NullLogger<CustomLogDetector>.Instance);
        var sink = NewSink();
        detector.PollOnce(settings, sink);

        File.AppendAllText(path, "(1) 2026-10-04 09:05:20 - (not logged in) (203.0.113.44)> USER x (198.51.100.9)> rest\n");
        detector.PollOnce(settings, sink);

        Assert.Equal("203.0.113.44", Assert.Single(Drain(sink)).IpAddress);
    }

    [Fact]
    public void A_pattern_that_needs_backtracking_is_reported_once()
    {
        var path = NewFile("lookahead.log");
        var logger = new RecordingLogger();
        var settings = Settings(Source("lookahead", path, @"(?!x)FAILED ip=(?<ipaddress>\S+)"));
        var detector = NewDetector(logger);
        var sink = NewSink();

        detector.PollOnce(settings, sink);
        File.AppendAllText(path, "FAILED ip=203.0.113.1\n");
        detector.PollOnce(settings, sink);

        Assert.Equal("203.0.113.1", Assert.Single(Drain(sink)).IpAddress);
        Assert.Contains("lookahead", Assert.Single(logger.Warnings));
    }

    [Fact]
    public void Crafted_lines_cannot_hide_failures_after_them_on_the_same_file()
    {
        var path = NewFile("crafted.log");
        var logger = new RecordingLogger();
        var settings = Settings(Source("slow", path, CatastrophicRegex));
        var detector = NewDetector(logger);
        var sink = NewSink();
        detector.PollOnce(settings, sink);

        File.AppendAllText(
            path,
            "FAILED ip=203.0.113.1\n" + string.Concat(Enumerable.Repeat(CraftedLine, 6)) + "FAILED ip=203.0.113.2\n");
        detector.PollOnce(settings, sink);

        Assert.Equal(new[] { "203.0.113.1", "203.0.113.2" }, Drain(sink).Select(f => f.IpAddress));
        Assert.Contains(logger.Warnings, w => w.Contains("slow") && w.Contains("6 line(s)") && w.Contains("6 could not be checked"));
    }

    [Fact]
    public void A_crafted_line_that_times_out_with_no_linear_engine_is_skipped_on_its_own()
    {
        Assert.False(CustomLogDetector.TryParseLine(CraftedLine.TrimEnd(), CatastrophicRegex, out var failed));
        Assert.Null(failed);
    }

    [Fact]
    public void A_slow_regex_on_one_file_cannot_cost_other_files_or_other_sources_their_lines()
    {
        var crafted = NewFile("a-crafted.log");
        var quiet = NewFile("b-quiet.log");
        var settings = Settings(
            Source("slow", Path.Combine(_dir, "*.log"), CatastrophicRegex),
            Source("other", crafted, FailedRegex));
        var detector = NewDetector();
        var sink = NewSink();
        detector.PollOnce(settings, sink);

        File.AppendAllText(crafted, string.Concat(Enumerable.Repeat(CraftedLine, 6)) + "FAILED ip=203.0.113.1\n");
        File.AppendAllText(quiet, "FAILED ip=203.0.113.2\n");
        detector.PollOnce(settings, sink);

        var failures = Drain(sink);
        Assert.Contains(failures, f => f.Detector == "slow" && f.IpAddress == "203.0.113.1");
        Assert.Contains(failures, f => f.Detector == "slow" && f.IpAddress == "203.0.113.2");
        Assert.Contains(failures, f => f.Detector == "other" && f.IpAddress == "203.0.113.1");
    }

    [Fact]
    public void The_timeout_budget_starts_over_every_cycle()
    {
        var path = NewFile("budget.log");
        var logger = new RecordingLogger();
        var settings = Settings(Source("slow", path, CatastrophicRegex));
        var detector = NewDetector(logger);
        var sink = NewSink();
        detector.PollOnce(settings, sink);

        for (var cycle = 0; cycle < 3; cycle++)
        {
            File.AppendAllText(path, string.Concat(Enumerable.Repeat(CraftedLine, 5)) + $"FAILED ip=203.0.113.{cycle + 1}\n");
            detector.PollOnce(settings, sink);
        }

        Assert.Equal(new[] { "203.0.113.1", "203.0.113.2", "203.0.113.3" }, Drain(sink).Select(f => f.IpAddress));
    }

    // ---------- upgraded recipes ----------

    [Fact]
    public void A_source_saved_with_the_awstats_path_reads_the_session_logs_after_the_upgrade()
    {
        var logs = Directory.CreateDirectory(Path.Combine(_dir, "Logs")).FullName;
        File.WriteAllText(Path.Combine(logs, "hmailserver_awstats.log"), string.Empty);
        var today = Path.Combine(logs, "hmailserver_2026-10-04.log");
        File.WriteAllText(today, string.Empty);
        var settings = Settings(Source("mail", Path.Combine(logs, "hmailserver_awstats.log"), CustomSourceRecipes.HMailServer.Regex));
        var detector = NewDetector();
        var sink = NewSink();
        detector.PollOnce(settings, sink);

        File.AppendAllText(today, "\"SMTPD\"\t1\t2\t\"2026-10-04 09:00:00.000\"\t\"203.0.113.1\"\t\"SENT: 535 Authentication failed. Restarting authentication process.\"\r\n");
        detector.PollOnce(settings, sink);

        Assert.Equal("203.0.113.1", Assert.Single(Drain(sink)).IpAddress);
    }

    // ---------- RawLog ----------

    [Fact]
    public void A_very_long_matching_line_is_capped_in_the_raw_log()
    {
        var line = "FAILED ip=203.0.113.1 " + new string('x', 10_000);

        Assert.True(CustomLogDetector.TryParseLine(line, FailedRegex, out var failed));
        Assert.True(failed!.RawLog.Length <= 2048);
    }

    private static WinGuardSettings Settings(params CustomLogSource[] sources)
    {
        var settings = new WinGuardSettings();
        settings.CustomSources.AddRange(sources);
        return settings;
    }

    private static CustomLogSource Source(string name, string path, string regex) =>
        new() { Name = name, PathGlob = path, Regex = regex };

    private string NewFile(string name, string content = "")
    {
        var path = Path.Combine(_dir, name);
        File.WriteAllText(path, content);
        return path;
    }

    private sealed class RecordingLogger : ILogger<CustomLogDetector>
    {
        public List<string> Warnings { get; } = [];

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (logLevel == LogLevel.Warning)
            {
                Warnings.Add(formatter(state, exception));
            }
        }
    }
}
