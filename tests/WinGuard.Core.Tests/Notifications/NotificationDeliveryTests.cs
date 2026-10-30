using System.Diagnostics;
using System.Net;
using System.Runtime.Versioning;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using WinGuard.Core.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Engine;
using WinGuard.Core.Model;
using WinGuard.Core.Notifications;
using WinGuard.Core.Tests.Fakes;
using WinGuard.Service;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>
/// Delivery end to end, against a recording HTTP handler and, where it matters, the real ban engine:
/// what a receiver gets, which events reach it, what the log may show, and what happens when a
/// channel fails or the rate limit bites.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class NotificationDeliveryTests
{
    private const string WebhookUrl = "https://hooks.example.invalid/services/T000/B000/s3cr3tpath?token=s3cr3tquery";
    private const string PlainHttpUrl = "http://hooks.example.invalid/services/s3cr3tpath";
    private const string TelegramToken = "123456:s3cr3ttoken";

    private static readonly DateTimeOffset T0 = new(2026, 3, 1, 12, 0, 0, TimeSpan.Zero);

    private static WinGuardSettings Settings(string webhookUrl = WebhookUrl, int rateLimit = 100, string telegramToken = "", SmtpSettings? smtp = null) => new()
    {
        Notifications = new NotificationSettings
        {
            Enabled = true,
            WebhookUrl = webhookUrl,
            RateLimitPerMinute = rateLimit,
            TelegramBotToken = telegramToken,
            TelegramChatId = telegramToken.Length > 0 ? "42" : string.Empty,
            Smtp = smtp,
        },
    };

    private static LogEvent Blocked(string ip = "203.0.113.7") => new()
    {
        TimestampUtc = T0.UtcDateTime,
        Level = LogEventLevel.Warning,
        Source = ProtocolSource.Rdp,
        IpAddress = ip,
        Message = $"BLOCKED {ip} for 1d (offense #1)",
    };

    private static async Task WaitUntilAsync(Func<bool> condition, string what)
    {
        var waited = Stopwatch.StartNew();
        while (!condition())
        {
            Assert.True(waited.Elapsed < TimeSpan.FromSeconds(10), "timed out waiting for: " + what);
            await Task.Delay(5);
        }
    }

    // ---- what the receiver gets ----

    [Fact]
    public async Task The_webhook_body_satisfies_every_kind_of_receiver()
    {
        var http = new RecordingHandler();
        using var client = new HttpClient(http);
        using var dispatcher = new NotificationDispatcher(() => Settings(), NullLogger<NotificationDispatcher>.Instance, null, client);
        dispatcher.Start();

        dispatcher.Publish(Blocked());
        await WaitUntilAsync(() => http.Requests.Count > 0, "the webhook");
        await dispatcher.StopAsync();

        var (uri, body) = Assert.Single(http.Requests);
        Assert.Equal(WebhookUrl, uri.ToString());
        using var json = JsonDocument.Parse(body);
        var root = json.RootElement;

        var text = root.GetProperty("text").GetString();
        Assert.Contains("BLOCKED 203.0.113.7", text);          // Slack, Mattermost, Teams
        Assert.Equal(text, root.GetProperty("content").GetString()); // Discord refuses a body without it
        Assert.Equal(text, root.GetProperty("summary").GetString()); // Teams cards
        Assert.Equal("WinGuard", root.GetProperty("title").GetString());
        Assert.Equal("203.0.113.7", root.GetProperty("ip").GetString());
        Assert.Equal("Warning", root.GetProperty("level").GetString());
        Assert.Equal("Rdp", root.GetProperty("source").GetString());
    }

    [Fact]
    public void Discord_content_stays_within_its_limit()
    {
        var text = new string('x', 2500);

        using var json = JsonDocument.Parse(NotificationDispatcher.BuildWebhookPayload(text, Blocked()));

        Assert.Equal(2000, json.RootElement.GetProperty("content").GetString()!.Length);
        Assert.Equal(2500, json.RootElement.GetProperty("text").GetString()!.Length);
    }

    // ---- which events get out ----

    /// <summary>Runs the real engine through everything that reports, into <paramref name="publisher"/>.</summary>
    private static async Task RunEngineThroughEveryEventAsync(IEventPublisher publisher)
    {
        var store = new FakeStore();
        var firewall = new FakeFirewall();
        var time = new FakeTimeProvider(T0);
        var settings = new WinGuardSettings { HousekeepingInterval = TimeSpan.FromHours(6), FailedLoginThreshold = 2 };
        var engine = new BanEngine(store, firewall, () => settings, NullLogger<BanEngine>.Instance, time, publisher);
        await engine.StartAsync(CancellationToken.None);

        try
        {
            // BLOCKED, then SKIPPED (Info) for the next failure of the banned address.
            for (var i = 0; i < 3; i++)
            {
                await engine.ProcessAsync(new FailedLogin { IpAddress = "203.0.113.1", Source = ProtocolSource.Rdp, TimestampUtc = time.GetUtcNow().UtcDateTime });
            }

            // MANUAL BLOCK and MANUAL UNBLOCK.
            await engine.BanNowAsync("203.0.113.2", TimeSpan.FromHours(1), false, null);
            await engine.UnbanAsync("203.0.113.2");

            // UNBANNED: a ban that runs out.
            await engine.BanNowAsync("203.0.113.3", TimeSpan.FromMinutes(1), false, null);
            time.Advance(TimeSpan.FromMinutes(2));
            await engine.HousekeepOnceAsync();

            // UNBLOCKED: a range ban that comes to overlap the whitelist.
            await store.UpsertBanAsync(new BanEntry
            {
                IpAddress = "2001:db8:1:2::/64",
                BannedAtUtc = time.GetUtcNow().UtcDateTime,
                ExpiresUtc = time.GetUtcNow().UtcDateTime.AddDays(1),
                OffenseCount = 1,
            });
            await store.AddToListAsync(ListKind.Whitelist, "2001:db8:1:2::5");
            await engine.HousekeepOnceAsync();
        }
        finally
        {
            await engine.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task An_expired_ban_reaches_the_channels_and_the_event_log()
    {
        var http = new RecordingHandler();
        var written = new List<(string Message, EventLogEntryType Type, int Id)>();
        var writer = new WindowsEventLogWriter(NullLogger.Instance, (message, type, id) => written.Add((message, type, id)));
        using var client = new HttpClient(http);
        using var dispatcher = new NotificationDispatcher(() => Settings(), NullLogger<NotificationDispatcher>.Instance, writer, client);
        dispatcher.Start();

        await RunEngineThroughEveryEventAsync(dispatcher);

        await WaitUntilAsync(() => http.Requests.Any(r => r.Body.Contains("UNBANNED 203.0.113.3")), "the expiry notification");
        await dispatcher.StopAsync();

        var entry = Assert.Single(written, e => e.Message.StartsWith("UNBANNED", StringComparison.Ordinal));
        Assert.Equal(EventLogEntryType.Information, entry.Type);
        Assert.Equal(WinGuardEventIds.BanExpired, entry.Id);
    }

    [Fact]
    public async Task The_rest_of_the_info_stream_stays_quiet()
    {
        var recorder = new RecordingPublisher();

        await RunEngineThroughEveryEventAsync(recorder);

        var quiet = recorder.Events.Where(e => !WinGuardEventIds.IsNotifiable(e)).Select(e => e.Message).ToList();
        Assert.Contains(quiet, message => message.StartsWith("SKIPPED", StringComparison.Ordinal));
        Assert.All(quiet, message => Assert.StartsWith("SKIPPED", message));
    }

    [Fact]
    public async Task Every_kind_of_engine_event_gets_its_own_id()
    {
        var recorder = new RecordingPublisher();

        await RunEngineThroughEveryEventAsync(recorder);

        var ids = recorder.Events.Where(WinGuardEventIds.IsNotifiable).Select(WinGuardEventIds.For).ToHashSet();
        Assert.Equal(
            new HashSet<int>
            {
                WinGuardEventIds.Blocked,
                WinGuardEventIds.ManualBlock,
                WinGuardEventIds.ManualUnblock,
                WinGuardEventIds.BanExpired,
                WinGuardEventIds.RangeUnblocked,
            },
            ids);
    }

    [Fact]
    public void The_ids_are_a_contract_siems_rely_on()
    {
        Assert.Equal(1001, WinGuardEventIds.Blocked);
        Assert.Equal(1002, WinGuardEventIds.ManualBlock);
        Assert.Equal(1003, WinGuardEventIds.BanExpired);
        Assert.Equal(1004, WinGuardEventIds.ManualUnblock);
        Assert.Equal(1005, WinGuardEventIds.RangeUnblocked);
        Assert.Equal(1006, WinGuardEventIds.NotificationsSuppressed);
        Assert.Equal(1900, WinGuardEventIds.OtherWarning);
        Assert.Equal(1901, WinGuardEventIds.Error);
        Assert.Equal(1902, WinGuardEventIds.OtherInformation);
    }

    [Theory]
    [InlineData(LogEventLevel.Error, "ERROR processing failed login: x", WinGuardEventIds.Error)]
    [InlineData(LogEventLevel.Error, "BLOCKED 203.0.113.7", WinGuardEventIds.Error)]
    [InlineData(LogEventLevel.Warning, "Something else", WinGuardEventIds.OtherWarning)]
    [InlineData(LogEventLevel.Info, "Cleared bans on startup", WinGuardEventIds.OtherInformation)]
    public void Events_without_a_type_of_their_own_get_a_catch_all(LogEventLevel level, string message, int expected)
    {
        Assert.Equal(expected, WinGuardEventIds.For(new LogEvent { Level = level, Message = message }));
    }

    [Fact]
    public void The_event_log_entry_carries_the_id_and_the_address()
    {
        var written = new List<(string Message, EventLogEntryType Type, int Id)>();
        var writer = new WindowsEventLogWriter(NullLogger.Instance, (message, type, id) => written.Add((message, type, id)));

        writer.Write(Blocked(), new NotificationSettings());
        writer.Write(new LogEvent { Level = LogEventLevel.Error, Message = "ERROR x" }, null);
        writer.Write(new LogEvent { Level = LogEventLevel.Info, Message = "SKIPPED 203.0.113.7 (whitelist)" }, null);

        Assert.Equal(2, written.Count);
        Assert.Equal(("BLOCKED 203.0.113.7 for 1d (offense #1) [203.0.113.7]", EventLogEntryType.Warning, WinGuardEventIds.Blocked), written[0]);
        Assert.Equal(("ERROR x", EventLogEntryType.Error, WinGuardEventIds.Error), written[1]);
    }

    // ---- what the log may show ----

    [Theory]
    [InlineData("https://hooks.slack.com/services/T000/B000/XXXX", "https://hooks.slack.com/***")]
    [InlineData("https://discord.com/api/webhooks/123/abc?wait=true", "https://discord.com/***")]
    [InlineData("https://user:password@example.com:8443/hook", "https://example.com:8443/***")]
    [InlineData("not a url at all", "(webhook URL hidden)")]
    public void Urls_are_redacted_down_to_the_host(string url, string expected)
    {
        Assert.Equal(expected, NotificationDispatcher.RedactUrl(url));
    }

    [Fact]
    public async Task A_refused_webhook_is_logged_without_its_secret()
    {
        var log = new CapturingLogger();
        var http = new RecordingHandler { Status = HttpStatusCode.Forbidden };
        using var client = new HttpClient(http);
        using var dispatcher = new NotificationDispatcher(() => Settings(), log, null, client);
        dispatcher.Start();

        dispatcher.Publish(Blocked());
        await WaitUntilAsync(() => log.Contains("answered 403"), "the warning");
        await dispatcher.StopAsync();

        Assert.Contains("https://hooks.example.invalid/***", log.Text);
        Assert.DoesNotContain("s3cr3t", log.Text);
    }

    [Fact]
    public async Task A_failing_send_is_logged_without_its_secret_even_when_the_exception_quotes_it()
    {
        var log = new CapturingLogger();
        var http = new RecordingHandler { Failure = uri => new HttpRequestException("could not reach " + uri) };
        using var client = new HttpClient(http);
        using var dispatcher = new NotificationDispatcher(() => Settings(telegramToken: TelegramToken), log, null, client);
        dispatcher.Start();

        dispatcher.Publish(Blocked());
        await WaitUntilAsync(() => log.Contains("Webhook delivery") && log.Contains("Telegram delivery"), "both failures");
        await dispatcher.StopAsync();

        Assert.DoesNotContain("s3cr3t", log.Text);
    }

    [Fact]
    public async Task A_plain_http_webhook_is_warned_about_once_and_still_delivered()
    {
        var log = new CapturingLogger();
        var http = new RecordingHandler();
        using var client = new HttpClient(http);
        using var dispatcher = new NotificationDispatcher(() => Settings(PlainHttpUrl), log, null, client);
        dispatcher.Start();

        dispatcher.Publish(Blocked("203.0.113.1"));
        dispatcher.Publish(Blocked("203.0.113.2"));
        await WaitUntilAsync(() => http.Requests.Count == 2, "both webhooks");
        await dispatcher.StopAsync();

        Assert.Single(log.Messages, message => message.Contains("plain HTTP"));
        Assert.DoesNotContain("s3cr3t", log.Text);
    }

    [Fact]
    public async Task An_https_webhook_gets_no_such_warning()
    {
        var log = new CapturingLogger();
        var http = new RecordingHandler();
        using var client = new HttpClient(http);
        using var dispatcher = new NotificationDispatcher(() => Settings(), log, null, client);
        dispatcher.Start();

        dispatcher.Publish(Blocked());
        await WaitUntilAsync(() => http.Requests.Count == 1, "the webhook");
        await dispatcher.StopAsync();

        Assert.DoesNotContain(log.Messages, message => message.Contains("plain HTTP"));
    }

    // ---- when channels fail ----

    [Fact]
    public async Task One_failing_channel_does_not_stop_the_others()
    {
        var log = new CapturingLogger();
        var http = new RecordingHandler { Failure = uri => uri.Host.Contains("hooks", StringComparison.Ordinal) ? new HttpRequestException("webhook is down") : null };
        using var client = new HttpClient(http);

        // An unusable address fails while the mail is built, on top of the failing webhook.
        var smtp = new SmtpSettings { Host = "smtp.example.invalid", To = "not an address" };
        using var dispatcher = new NotificationDispatcher(() => Settings(telegramToken: TelegramToken, smtp: smtp), log, null, client);
        dispatcher.Start();

        dispatcher.Publish(Blocked());
        await WaitUntilAsync(() => http.Requests.Any(r => r.Uri.Host == "api.telegram.org"), "the Telegram message");
        await WaitUntilAsync(() => log.Contains("E-mail delivery"), "the e-mail failure");
        await dispatcher.StopAsync();

        Assert.Contains("webhook is down", log.Text);
    }

    [Fact]
    public async Task A_mail_relay_that_cannot_be_reached_is_logged()
    {
        var log = new CapturingLogger();
        var http = new RecordingHandler();
        using var client = new HttpClient(http);

        // Nothing listens on this port, so the connection is refused at once.
        var smtp = new SmtpSettings { Host = "127.0.0.1", Port = 1, EnableSsl = false, From = "a@example.invalid", To = "b@example.invalid" };
        using var dispatcher = new NotificationDispatcher(() => Settings(smtp: smtp), log, null, client);
        dispatcher.Start();

        dispatcher.Publish(Blocked());
        await WaitUntilAsync(() => log.Contains("E-mail delivery through 127.0.0.1 failed"), "the e-mail failure");
        await dispatcher.StopAsync();

        Assert.Single(http.Requests);
    }

    [Fact]
    public async Task A_dead_channel_does_not_hold_the_others_back()
    {
        var http = new RecordingHandler { Hang = uri => uri.Host.Contains("hooks", StringComparison.Ordinal) };
        using var client = new HttpClient(http);
        using var dispatcher = new NotificationDispatcher(() => Settings(telegramToken: TelegramToken), NullLogger<NotificationDispatcher>.Instance, null, client);
        dispatcher.Start();

        dispatcher.Publish(Blocked());

        // Far inside the webhook's own 10 second timeout.
        await WaitUntilAsync(() => http.Requests.Any(r => r.Uri.Host == "api.telegram.org"), "the Telegram message");
        await dispatcher.StopAsync();
    }

    [Fact]
    public async Task A_caller_owned_http_client_survives_the_dispatcher()
    {
        var http = new RecordingHandler();
        using var client = new HttpClient(http);
        new NotificationDispatcher(() => Settings(), NullLogger<NotificationDispatcher>.Instance, null, client).Dispose();

        using var response = await client.GetAsync("https://example.invalid/");

        Assert.True(response.IsSuccessStatusCode);
    }

    // ---- when the rate limit bites ----

    [Fact]
    public async Task Rate_limited_events_are_summed_up_once_the_interval_has_passed()
    {
        var time = new FakeTimeProvider(T0);
        var http = new RecordingHandler();
        var log = new CapturingLogger();
        using var client = new HttpClient(http);
        using var dispatcher = new NotificationDispatcher(() => Settings(rateLimit: 1), log, null, client, time)
        {
            SummaryPollInterval = TimeSpan.FromMilliseconds(10),
        };
        dispatcher.Start();

        dispatcher.Publish(Blocked("203.0.113.1"));
        dispatcher.Publish(Blocked("203.0.113.2"));
        dispatcher.Publish(Blocked("203.0.113.3"));
        await WaitUntilAsync(() => dispatcher.SuppressedCount == 2, "the rate limit");
        Assert.Single(http.Requests);

        // Not due yet: nothing but the one event that got through.
        await Task.Delay(50);
        Assert.Single(http.Requests);

        // No further event arrives: the summary must not depend on one.
        time.Advance(NotificationDispatcher.SuppressionSummaryInterval);
        await WaitUntilAsync(() => http.Requests.Count == 2, "the summary");
        await dispatcher.StopAsync();

        Assert.Contains("SUPPRESSED 2 notification(s)", http.Requests[1].Body);
        Assert.Equal(0, dispatcher.SuppressedCount);
        Assert.Contains("SUPPRESSED 2 notification(s)", log.Text);
    }

    [Fact]
    public async Task A_quiet_period_sends_no_summary()
    {
        var time = new FakeTimeProvider(T0);
        var http = new RecordingHandler();
        using var client = new HttpClient(http);
        using var dispatcher = new NotificationDispatcher(() => Settings(rateLimit: 1), NullLogger<NotificationDispatcher>.Instance, null, client, time);

        time.Advance(TimeSpan.FromHours(1));
        await dispatcher.FlushSuppressedAsync(CancellationToken.None);

        Assert.Empty(http.Requests);
    }

    [Fact]
    public async Task A_summary_goes_to_the_event_log_with_its_id_even_with_the_channels_off()
    {
        var time = new FakeTimeProvider(T0);
        var written = new List<(string Message, EventLogEntryType Type, int Id)>();
        var writer = new WindowsEventLogWriter(NullLogger.Instance, (message, type, id) => written.Add((message, type, id)));
        var settings = new WinGuardSettings();
        using var dispatcher = new NotificationDispatcher(() => settings, NullLogger<NotificationDispatcher>.Instance, writer, null, time);

        // More than the queue holds, with nothing reading it.
        for (var i = 0; i < 503; i++)
        {
            dispatcher.Publish(Blocked());
        }

        Assert.Equal(3, dispatcher.SuppressedCount);

        time.Advance(NotificationDispatcher.SuppressionSummaryInterval);
        await dispatcher.FlushSuppressedAsync(CancellationToken.None);

        var entry = Assert.Single(written);
        Assert.Equal(WinGuardEventIds.NotificationsSuppressed, entry.Id);
        Assert.StartsWith("SUPPRESSED 3 notification(s)", entry.Message);
    }

    [Fact]
    public async Task Stopping_with_a_summary_still_owed_leaves_a_trace_in_the_log()
    {
        var log = new CapturingLogger();
        var http = new RecordingHandler();
        using var client = new HttpClient(http);
        using var dispatcher = new NotificationDispatcher(() => Settings(rateLimit: 1), log, null, client);
        dispatcher.Start();

        dispatcher.Publish(Blocked("203.0.113.1"));
        dispatcher.Publish(Blocked("203.0.113.2"));
        await WaitUntilAsync(() => dispatcher.SuppressedCount == 1, "the rate limit");
        await dispatcher.StopAsync();

        Assert.Contains("1 notification(s) were suppressed", log.Text);
    }

    // ---- shutdown ----

    [Fact]
    public async Task A_delivery_stuck_in_a_blocking_call_cannot_hold_up_the_shutdown()
    {
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var writer = new WindowsEventLogWriter(NullLogger.Instance, (_, _, _) =>
        {
            entered.Set();
            release.Wait();
        });
        var settings = new WinGuardSettings();
        using var dispatcher = new NotificationDispatcher(() => settings, NullLogger<NotificationDispatcher>.Instance, writer);
        using var hosted = new NotificationHostedService(dispatcher);
        await hosted.StartAsync(CancellationToken.None);

        dispatcher.Publish(Blocked());
        Assert.True(entered.Wait(TimeSpan.FromSeconds(10)));

        using var hostGivesUp = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        await hosted.StopAsync(hostGivesUp.Token).WaitAsync(TimeSpan.FromSeconds(10));

        release.Set();
    }

    private sealed class RecordingPublisher : IEventPublisher
    {
        private readonly List<LogEvent> _events = [];

        public List<LogEvent> Events
        {
            get
            {
                lock (_events)
                {
                    return _events.ToList();
                }
            }
        }

        public void Publish(LogEvent logEvent)
        {
            lock (_events)
            {
                _events.Add(logEvent);
            }
        }
    }

    private sealed class RecordingHandler : HttpMessageHandler
    {
        private readonly List<(Uri Uri, string Body)> _requests = [];

        public HttpStatusCode Status { get; init; } = HttpStatusCode.OK;

        public Func<Uri, Exception?>? Failure { get; init; }

        public Func<Uri, bool>? Hang { get; init; }

        public List<(Uri Uri, string Body)> Requests
        {
            get
            {
                lock (_requests)
                {
                    return _requests.ToList();
                }
            }
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
            lock (_requests)
            {
                _requests.Add((request.RequestUri!, body));
            }

            if (Hang?.Invoke(request.RequestUri!) == true)
            {
                await Task.Delay(Timeout.Infinite, cancellationToken);
            }

            if (Failure?.Invoke(request.RequestUri!) is { } failure)
            {
                throw failure;
            }

            return new HttpResponseMessage(Status);
        }
    }

    private sealed class CapturingLogger : ILogger<NotificationDispatcher>
    {
        private readonly List<string> _messages = [];

        public List<string> Messages
        {
            get
            {
                lock (_messages)
                {
                    return _messages.ToList();
                }
            }
        }

        public string Text => string.Join(Environment.NewLine, Messages);

        public bool Contains(string text) => Text.Contains(text, StringComparison.Ordinal);

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            lock (_messages)
            {
                _messages.Add(formatter(state, exception) + (exception is null ? string.Empty : " " + exception));
            }
        }
    }
}
