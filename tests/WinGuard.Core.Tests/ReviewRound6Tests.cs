using System.Net;
using System.Runtime.Versioning;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Detection;
using WinGuard.Core.Model;
using WinGuard.Core.Notifications;
using WinGuard.Core.Tests.Fakes;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>
/// The findings of the sixth review: rotated archives read again from the start, a log folder that
/// is away for a moment coming back as history, one slow notification channel holding up the
/// others, and mail to the SMTPS port.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ReviewRound6Tests : IDisposable
{
    private const string FailedRegex = @"FAILED ip=(?<ipaddress>\S+)";
    private const string FileZillaFailure = "(000001) 2026-10-04 09:05:20 - (not logged in) ({0})> 530 Login or password incorrect!\n";

    private static readonly DateTimeOffset T0 = new(2026, 3, 1, 12, 0, 0, TimeSpan.Zero);

    private readonly string _dir = Directory.CreateTempSubdirectory("winguard-round6-").FullName;

    public void Dispose() => Directory.Delete(_dir, true);

    // ---------- numbered archives ----------

    [Fact]
    public void Numbered_archives_moving_up_one_place_are_not_read_again()
    {
        var current = NewFile("app.log", "history 0\n");
        var first = NewFile("app.log.1", "history 1\n");
        var second = NewFile("app.log.2", "history 2\n");
        var tailer = new LogFileTailer();
        Assert.Empty(tailer.ReadNewLines(current));
        Assert.Empty(tailer.ReadNewLines(first));
        Assert.Empty(tailer.ReadNewLines(second));

        File.AppendAllText(current, "last line\n");
        Rotate(current, first, second);

        // In sort order, as the detectors poll. Every name now holds another file than before.
        Assert.Equal(new[] { "fresh" }, tailer.ReadNewLines(current, readFromStartIfNew: true));
        Assert.Equal(new[] { "last line" }, tailer.ReadNewLines(first, readFromStartIfNew: true));
        Assert.Empty(tailer.ReadNewLines(second, readFromStartIfNew: true));
    }

    [Fact]
    public void Archives_that_sort_before_the_live_file_are_not_read_again_either()
    {
        var first = NewFile("app.1.log", "history 1\n");
        var second = NewFile("app.2.log", "history 2\n");
        var current = NewFile("app.log", "history 0\n");
        var tailer = new LogFileTailer();
        Assert.Empty(tailer.ReadNewLines(first));
        Assert.Empty(tailer.ReadNewLines(second));
        Assert.Empty(tailer.ReadNewLines(current));

        File.AppendAllText(current, "last line\n");
        Rotate(current, first, second);

        Assert.Equal(new[] { "last line" }, tailer.ReadNewLines(first, readFromStartIfNew: true));
        Assert.Empty(tailer.ReadNewLines(second, readFromStartIfNew: true));
        Assert.Equal(new[] { "fresh" }, tailer.ReadNewLines(current, readFromStartIfNew: true));
    }

    [Fact]
    public void A_rotation_of_numbered_archives_bans_nobody_from_the_archives()
    {
        var current = NewFile("app.log", "FAILED ip=203.0.113.10\n");
        var first = NewFile("app.log.1", "FAILED ip=203.0.113.11\n");
        var second = NewFile("app.log.2", "FAILED ip=203.0.113.12\n");
        var settings = CustomSettings(Path.Combine(_dir, "app.log*"));
        var detector = CustomLogDetectorPollTests.NewDetector();
        var sink = CustomLogDetectorPollTests.NewSink();
        detector.PollOnce(settings, sink);

        Rotate(current, first, second, fresh: "FAILED ip=203.0.113.1\n");
        detector.PollOnce(settings, sink);

        Assert.Equal(new[] { "203.0.113.1" }, CustomLogDetectorPollTests.Drain(sink).Select(f => f.IpAddress));
    }

    // ---------- a source that is away for a moment ----------

    [Fact]
    public void A_folder_that_is_away_for_a_cycle_does_not_come_back_as_history()
    {
        var folder = Directory.CreateDirectory(Path.Combine(_dir, "logs")).FullName;
        var away = Path.Combine(_dir, "logs.away");
        File.WriteAllText(Path.Combine(folder, "a.log"), "FAILED ip=203.0.113.20\n");
        File.WriteAllText(Path.Combine(folder, "b.log"), "FAILED ip=203.0.113.21\n");
        var log = new WarningLog<CustomLogDetector>();
        var settings = CustomSettings(Path.Combine(folder, "*.log"));
        var detector = CustomLogDetectorPollTests.NewDetector(log);
        var sink = CustomLogDetectorPollTests.NewSink();
        detector.PollOnce(settings, sink);

        Directory.Move(folder, away);
        detector.PollOnce(settings, sink);
        detector.PollOnce(settings, sink);
        Directory.Move(away, folder);
        detector.PollOnce(settings, sink);
        Assert.Empty(CustomLogDetectorPollTests.Drain(sink));

        // The files continue where they stopped, and the source is an ordinary one again.
        File.AppendAllText(Path.Combine(folder, "a.log"), "FAILED ip=203.0.113.1\n");
        File.WriteAllText(Path.Combine(folder, "c.log"), "FAILED ip=203.0.113.2\n");
        detector.PollOnce(settings, sink);

        Assert.Equal(new[] { "203.0.113.1", "203.0.113.2" }, CustomLogDetectorPollTests.Drain(sink).Select(f => f.IpAddress));
        Assert.Single(log.Warnings, warning => warning.Contains("cannot read", StringComparison.Ordinal));
    }

    [Fact]
    public void Files_that_turn_up_with_a_returning_folder_are_history()
    {
        var folder = Directory.CreateDirectory(Path.Combine(_dir, "logs")).FullName;
        var away = Path.Combine(_dir, "logs.away");
        File.WriteAllText(Path.Combine(folder, "a.log"), "FAILED ip=203.0.113.20\n");
        var settings = CustomSettings(Path.Combine(folder, "*.log"));
        var detector = CustomLogDetectorPollTests.NewDetector();
        var sink = CustomLogDetectorPollTests.NewSink();
        detector.PollOnce(settings, sink);

        // Nothing says whether this was written or restored while the folder could not be seen.
        Directory.Move(folder, away);
        detector.PollOnce(settings, sink);
        File.WriteAllText(Path.Combine(away, "restored.log"), "FAILED ip=203.0.113.30\n");
        Directory.Move(away, folder);
        detector.PollOnce(settings, sink);

        Assert.Empty(CustomLogDetectorPollTests.Drain(sink));
    }

    [Fact]
    public void A_log_that_does_not_exist_yet_is_still_read_from_its_first_line()
    {
        var path = Path.Combine(_dir, "later.log");
        var settings = CustomSettings(path);
        var detector = CustomLogDetectorPollTests.NewDetector();
        var sink = CustomLogDetectorPollTests.NewSink();
        detector.PollOnce(settings, sink);
        detector.PollOnce(settings, sink);

        File.WriteAllText(path, "FAILED ip=203.0.113.1\n");
        detector.PollOnce(settings, sink);

        Assert.Equal(new[] { "203.0.113.1" }, CustomLogDetectorPollTests.Drain(sink).Select(f => f.IpAddress));
    }

    [Fact]
    public void A_single_log_that_is_deleted_and_written_anew_is_read_from_its_first_line()
    {
        var path = NewFile("single.log", "FAILED ip=203.0.113.20\n");
        var settings = CustomSettings(path);
        var detector = CustomLogDetectorPollTests.NewDetector();
        var sink = CustomLogDetectorPollTests.NewSink();
        detector.PollOnce(settings, sink);

        File.Delete(path);
        detector.PollOnce(settings, sink);
        File.WriteAllText(path, "FAILED ip=203.0.113.1\n");
        detector.PollOnce(settings, sink);

        Assert.Equal(new[] { "203.0.113.1" }, CustomLogDetectorPollTests.Drain(sink).Select(f => f.IpAddress));
    }

    [Fact]
    public void An_ftp_folder_that_is_away_for_a_cycle_does_not_come_back_as_history()
    {
        var folder = Directory.CreateDirectory(Path.Combine(_dir, "ftp")).FullName;
        var away = Path.Combine(_dir, "ftp.away");
        var file = Path.Combine(folder, "fzs.log");
        File.WriteAllText(file, string.Format(FileZillaFailure, "203.0.113.20"));
        var settings = new WinGuardSettings();
        settings.Ftp.Sources.Add(new FtpLogSource { Kind = FtpServerKind.FileZilla, Path = folder });
        var detector = new FtpLogDetector(() => settings, NullLogger<FtpLogDetector>.Instance);
        var sink = Channel.CreateUnbounded<FailedLogin>();
        detector.PollOnce(settings, sink);

        Directory.Move(folder, away);
        detector.PollOnce(settings, sink);
        Directory.Move(away, folder);
        detector.PollOnce(settings, sink);
        Assert.Empty(CustomLogDetectorPollTests.Drain(sink));

        File.AppendAllText(file, string.Format(FileZillaFailure, "203.0.113.1"));
        detector.PollOnce(settings, sink);

        Assert.Equal(new[] { "203.0.113.1" }, CustomLogDetectorPollTests.Drain(sink).Select(f => f.IpAddress));
    }

    [Fact]
    public void A_folder_that_is_missing_cannot_be_told_from_one_that_is_empty_by_its_files_alone()
    {
        var folder = Directory.CreateDirectory(Path.Combine(_dir, "empty")).FullName;

        Assert.True(LogFileTailer.TryResolveFiles(Path.Combine(folder, "*.log"), "*", out var none));
        Assert.Empty(none);
        Assert.False(LogFileTailer.TryResolveFiles(Path.Combine(_dir, "missing", "*.log"), "*", out var unknown));
        Assert.Empty(unknown);
        Assert.False(LogFileTailer.TryResolveFiles(Path.Combine(_dir, "missing.log"), "*", out _));

        // Never read at all, so there is nothing to wait for.
        Assert.True(LogFileTailer.TryResolveFiles(@"\\server\share\app.log", "*", out _));
    }

    // ---------- one slow channel ----------

    [Fact]
    public async Task A_receiver_that_hangs_delays_no_later_event_on_the_other_channels()
    {
        var http = new GatedHandler(uri => uri.Host.Contains("hooks", StringComparison.Ordinal));
        using var client = new HttpClient(http);
        using var dispatcher = new NotificationDispatcher(() => ChannelSettings(), NullLogger<NotificationDispatcher>.Instance, null, client);
        dispatcher.Start();

        for (var i = 1; i <= 5; i++)
        {
            dispatcher.Publish(Blocked($"203.0.113.{i}"));
        }

        // The webhook never answers. Waiting for it, event by event, would take its timeout each time.
        await WaitUntilAsync(() => http.Count("api.telegram.org") == 5, "all five Telegram messages");
        Assert.Equal(1, http.Count("hooks.example.invalid"));

        http.Open();
        await WaitUntilAsync(() => http.Count("hooks.example.invalid") == 5, "the webhook catching up, in its own time");
        await dispatcher.StopAsync();

        Assert.Equal(0, dispatcher.SuppressedCount);
    }

    [Fact]
    public async Task A_notification_that_waited_too_long_behind_a_dead_receiver_is_dropped_and_counted()
    {
        var time = new FakeTimeProvider(T0);
        var http = new GatedHandler(uri => uri.Host.Contains("hooks", StringComparison.Ordinal));
        using var client = new HttpClient(http);
        using var dispatcher = new NotificationDispatcher(() => ChannelSettings(), NullLogger<NotificationDispatcher>.Instance, null, client, time)
        {
            MaxQueueAge = TimeSpan.FromMinutes(1),
        };
        dispatcher.Start();

        dispatcher.Publish(Blocked("203.0.113.1"));
        dispatcher.Publish(Blocked("203.0.113.2"));

        // The webhook is handed an event before Telegram is, so by now it has both.
        await WaitUntilAsync(() => http.Count("api.telegram.org") == 2, "both events on their way");
        time.Advance(TimeSpan.FromMinutes(2));
        http.Open();

        await WaitUntilAsync(() => dispatcher.SuppressedCount == 1, "the stale notification");
        await dispatcher.StopAsync();

        Assert.Equal(1, http.Count("hooks.example.invalid"));
    }

    [Fact]
    public async Task The_switch_on_with_nowhere_to_send_suppresses_nothing()
    {
        var settings = ChannelSettings(rateLimit: 1);
        var webhookUrl = settings.Notifications.WebhookUrl;
        settings.Notifications.WebhookUrl = string.Empty;
        settings.Notifications.TelegramBotToken = string.Empty;
        var http = new GatedHandler(_ => false);
        var reads = 0;
        using var client = new HttpClient(http);
        using var dispatcher = new NotificationDispatcher(
            () =>
            {
                Interlocked.Increment(ref reads);
                return settings;
            },
            NullLogger<NotificationDispatcher>.Instance,
            null,
            client);
        dispatcher.Start();

        dispatcher.Publish(Blocked("203.0.113.1"));
        dispatcher.Publish(Blocked("203.0.113.2"));
        dispatcher.Publish(Blocked("203.0.113.3"));

        // Each event reads the settings when it is published, in the SIEM loop and in the channel
        // loop: after nine reads all three have been through the channel loop.
        await WaitUntilAsync(() => Volatile.Read(ref reads) >= 9, "the three events without a destination");

        // Had those three used up the limit of one, this one could not be sent.
        settings.Notifications.WebhookUrl = webhookUrl;
        dispatcher.Publish(Blocked("203.0.113.4"));
        await WaitUntilAsync(() => http.Count("hooks.example.invalid") == 1, "the first event with a destination");
        await dispatcher.StopAsync();

        Assert.Equal(0, dispatcher.SuppressedCount);
    }

    // ---------- mail to the SMTPS port ----------

    [Fact]
    public async Task Mail_to_the_smtps_port_is_given_up_at_once_and_said_so_once()
    {
        var log = new WarningLog<NotificationDispatcher>();
        var settings = ChannelSettings();
        settings.Notifications.Smtp = new SmtpSettings { Host = "smtp.example.invalid", Port = 465, EnableSsl = true, From = "a@example.invalid", To = "b@example.invalid" };
        var http = new GatedHandler(_ => false);
        using var client = new HttpClient(http);
        using var dispatcher = new NotificationDispatcher(() => settings, log, null, client);
        dispatcher.Start();

        for (var i = 1; i <= 3; i++)
        {
            dispatcher.Publish(Blocked($"203.0.113.{i}"));
        }

        await WaitUntilAsync(() => http.Count("hooks.example.invalid") == 3, "the webhook");
        await WaitUntilAsync(() => log.Warnings.Count > 0, "the reason no mail goes out");
        await dispatcher.StopAsync();

        var warning = Assert.Single(log.Warnings);
        Assert.Contains("port 465", warning);
        Assert.Contains("587", warning);
    }

    [Theory]
    [InlineData("smtp.example.invalid", 465, true)]
    [InlineData("smtp.example.invalid", 587, false)]
    [InlineData("smtp.example.invalid", 25, false)]
    [InlineData("", 465, false)]
    public void The_smtps_port_is_refused_when_a_relay_is_set(string host, int port, bool refused)
    {
        var settings = new WinGuardSettings();
        settings.Notifications.Smtp = new SmtpSettings { Host = host, Port = port };
        settings.Normalize();

        var problems = SettingsValidator.Validate(settings);

        Assert.Equal(refused, problems.Any(problem => problem.StartsWith("SMTP:", StringComparison.Ordinal) && problem.Contains("587", StringComparison.Ordinal)));
    }

    // ---------- helpers ----------

    private string NewFile(string name, string content)
    {
        var path = Path.Combine(_dir, name);
        File.WriteAllText(path, content);
        return path;
    }

    /// <summary>What a size-based roller does: the oldest archive goes, every file moves up one name.</summary>
    private static void Rotate(string current, string first, string second, string fresh = "fresh\n")
    {
        File.Delete(second);
        File.Move(first, second);
        File.Move(current, first);
        File.WriteAllText(current, fresh);
    }

    private static WinGuardSettings CustomSettings(string pathGlob)
    {
        var settings = new WinGuardSettings();
        settings.CustomSources.Add(new CustomLogSource { Name = "app", PathGlob = pathGlob, Regex = FailedRegex });
        return settings;
    }

    private static WinGuardSettings ChannelSettings(int rateLimit = 100) => new()
    {
        Notifications = new NotificationSettings
        {
            Enabled = true,
            WebhookUrl = "https://hooks.example.invalid/services/s3cr3t",
            RateLimitPerMinute = rateLimit,
            TelegramBotToken = "123456:s3cr3ttoken",
            TelegramChatId = "42",
        },
    };

    private static LogEvent Blocked(string ip) => new()
    {
        TimestampUtc = T0.UtcDateTime,
        Level = LogEventLevel.Warning,
        Source = ProtocolSource.Rdp,
        IpAddress = ip,
        Message = $"BLOCKED {ip} for 1d (offense #1)",
    };

    private static async Task WaitUntilAsync(Func<bool> condition, string what)
    {
        var waited = System.Diagnostics.Stopwatch.StartNew();
        while (!condition())
        {
            Assert.True(waited.Elapsed < TimeSpan.FromSeconds(8), "timed out waiting for: " + what);
            await Task.Delay(5);
        }
    }

    /// <summary>Records every request; those the gate picks do not get an answer until it is opened.</summary>
    private sealed class GatedHandler(Func<Uri, bool> gated) : HttpMessageHandler
    {
        private readonly TaskCompletionSource _open = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly List<string> _hosts = [];

        public void Open() => _open.TrySetResult();

        public int Count(string host)
        {
            lock (_hosts)
            {
                return _hosts.Count(seen => seen == host);
            }
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            lock (_hosts)
            {
                _hosts.Add(request.RequestUri!.Host);
            }

            if (gated(request.RequestUri!))
            {
                await _open.Task.WaitAsync(cancellationToken);
            }

            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }

    private sealed class WarningLog<T> : ILogger<T>
    {
        private readonly List<string> _warnings = [];

        public List<string> Warnings
        {
            get
            {
                lock (_warnings)
                {
                    return _warnings.ToList();
                }
            }
        }

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (logLevel >= LogLevel.Warning)
            {
                lock (_warnings)
                {
                    _warnings.Add(formatter(state, exception));
                }
            }
        }
    }
}
