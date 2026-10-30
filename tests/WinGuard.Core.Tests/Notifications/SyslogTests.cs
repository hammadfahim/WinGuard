using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Model;
using WinGuard.Core.Notifications;
using WinGuard.Core.Tests.Fakes;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>
/// The syslog channel: messages held against the RFC 5424 grammar, delivery through the dispatcher
/// with a recording transport, and the real sockets over loopback.
/// </summary>
public sealed class SyslogTests
{
    private const string WebhookUrl = "https://hooks.example.invalid/services/s3cr3t";

    private static readonly DateTime When = new(2026, 3, 1, 12, 0, 0, 250, DateTimeKind.Utc);

    // RFC 5424 §6, the whole message, field by field.
    private static readonly Regex Rfc5424 = new(
        @"^<(?<prival>0|[1-9][0-9]{0,2})>1 " +
        @"(?<timestamp>-|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})) " +
        @"(?<host>-|[!-~]{1,255}) " +
        @"(?<app>-|[!-~]{1,48}) " +
        @"(?<proc>-|[!-~]{1,128}) " +
        @"(?<msgid>-|[!-~]{1,32}) " +
        @"(?<sd>-|\[.*\])" +
        @"( (?<msg>.*))?$",
        RegexOptions.Singleline | RegexOptions.CultureInvariant);

    private static SyslogSettings Syslog(SyslogFormat format = SyslogFormat.Rfc5424, int facility = SyslogSettings.DefaultFacility) => new()
    {
        Enabled = true,
        Host = "siem.example.invalid",
        Format = format,
        Facility = facility,
    };

    private static LogEvent Blocked(string ip = "203.0.113.7") => new()
    {
        TimestampUtc = When,
        Level = LogEventLevel.Warning,
        Source = ProtocolSource.Rdp,
        IpAddress = ip,
        Message = $"BLOCKED {ip} for 1.00:00:00 (offense #1)",
    };

    private static byte[] Bytes(LogEvent logEvent, SyslogSettings? settings = null, string host = "web1.example.com") =>
        SyslogFormatter.Format(logEvent, settings ?? Syslog(), host, 4242, "0.2.0");

    private static string Text(LogEvent logEvent, SyslogSettings? settings = null, string host = "web1.example.com") =>
        Encoding.UTF8.GetString(Bytes(logEvent, settings, host));

    private static Match Parse(string message)
    {
        var match = Rfc5424.Match(message);
        Assert.True(match.Success, "not RFC 5424: " + message);
        return match;
    }

    // ---- the format ----

    [Fact]
    public void A_message_is_exactly_what_the_rfc_describes()
    {
        Assert.Equal(
            "<36>1 2026-03-01T12:00:00.250Z web1.example.com WinGuard 4242 1001 - BLOCKED 203.0.113.7 for 1.00:00:00 (offense #1) ip=203.0.113.7 source=rdp",
            Text(Blocked()));
    }

    [Theory]
    [InlineData(LogEventLevel.Error, 4, 35)]
    [InlineData(LogEventLevel.Warning, 4, 36)]
    [InlineData(LogEventLevel.Info, 4, 38)]
    [InlineData(LogEventLevel.Warning, 0, 4)]
    [InlineData(LogEventLevel.Warning, 16, 132)]
    [InlineData(LogEventLevel.Error, 23, 187)]
    public void The_priority_is_facility_times_eight_plus_severity(LogEventLevel level, int facility, int priority)
    {
        var logEvent = new LogEvent { TimestampUtc = When, Level = level, Message = "UNBANNED 203.0.113.7" };

        Assert.Equal(priority.ToString(), Parse(Text(logEvent, Syslog(facility: facility))).Groups["prival"].Value);
    }

    [Theory]
    [InlineData("web 1 . example", "web1.example")]
    [InlineData("höst", "hst")]
    [InlineData("", "-")]
    [InlineData("   ", "-")]
    [InlineData("öä", "-")]
    public void The_host_name_keeps_to_printable_ascii_or_is_nil(string host, string expected)
    {
        Assert.Equal(expected, Parse(Text(Blocked(), host: host)).Groups["host"].Value);
    }

    [Fact]
    public void A_very_long_host_name_is_cut_to_what_the_header_allows()
    {
        Assert.Equal(255, Parse(Text(Blocked(), host: new string('h', 400))).Groups["host"].Length);
    }

    [Fact]
    public void An_event_without_a_time_says_so()
    {
        var logEvent = new LogEvent { Level = LogEventLevel.Warning, Message = "whatever" };

        Assert.Equal("-", Parse(Text(logEvent)).Groups["timestamp"].Value);
    }

    [Fact]
    public void The_message_id_is_the_stable_event_id()
    {
        var disarmed = new LogEvent { TimestampUtc = When, Level = LogEventLevel.Warning, Message = "DISARMED until tomorrow" };

        Assert.Equal("1020", Parse(Text(disarmed)).Groups["msgid"].Value);
    }

    [Fact]
    public void No_structured_data_is_claimed_without_an_enterprise_number()
    {
        Assert.Equal("-", Parse(Text(Blocked())).Groups["sd"].Value);
    }

    [Theory]
    [InlineData("line one\r\n<36>1 2026-03-01T12:00:00Z forged WinGuard 1 1001 - BLOCKED 1.2.3.4")]
    [InlineData("nul\0byte")]
    [InlineData("bell\u0007 and esc\u001B[31m")]
    [InlineData("del\u007F and c1\u0085\u009B")]
    [InlineData("line\u2028separator\u2029paragraph")]
    public void Control_characters_cannot_forge_a_message(string message)
    {
        var bytes = Bytes(new LogEvent { TimestampUtc = When, Level = LogEventLevel.Warning, Message = message });

        Assert.DoesNotContain(bytes, b => b < 0x20 || b == 0x7F);
        var text = Encoding.UTF8.GetString(bytes);
        Assert.DoesNotContain('\u0085', text);
        Assert.DoesNotContain('\u2028', text);
        Assert.DoesNotContain('\u2029', text);
    }

    [Fact]
    public void A_line_break_stays_readable()
    {
        var text = Text(new LogEvent { TimestampUtc = When, Level = LogEventLevel.Warning, Message = "one\r\ntwo\tthree\u0001" });

        Assert.EndsWith(@"one\r\ntwo\tthree\x01", text);
    }

    [Fact]
    public void Control_characters_in_the_host_field_of_an_event_are_escaped_too()
    {
        var logEvent = new LogEvent { TimestampUtc = When, Level = LogEventLevel.Warning, Message = "x", IpAddress = "1.2.3.4\nforged" };

        Assert.DoesNotContain(Bytes(logEvent), b => b < 0x20);
    }

    [Fact]
    public void Ascii_text_goes_without_a_bom()
    {
        Assert.Equal(-1, IndexOf(Bytes(Blocked()), [0xEF, 0xBB, 0xBF]));
    }

    [Fact]
    public void Unicode_text_starts_with_the_bom_the_rfc_requires()
    {
        var logEvent = new LogEvent { TimestampUtc = When, Level = LogEventLevel.Warning, Message = "Benutzer Müller" };

        var bytes = Bytes(logEvent);
        var header = Encoding.ASCII.GetByteCount("<36>1 2026-03-01T12:00:00.250Z web1.example.com WinGuard 4242 1900 - ");

        Assert.Equal(header, IndexOf(bytes, [0xEF, 0xBB, 0xBF]));
        Assert.EndsWith("Benutzer Müller", Encoding.UTF8.GetString(bytes));
    }

    [Fact]
    public void A_long_message_is_cut_to_the_limit()
    {
        var bytes = Bytes(new LogEvent { TimestampUtc = When, Level = LogEventLevel.Error, Message = new string('x', 10_000) });

        Assert.Equal(SyslogFormatter.MaxMessageBytes, bytes.Length);
        Parse(Encoding.ASCII.GetString(bytes));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void A_cut_never_lands_inside_a_character(int offset)
    {
        var message = new string('x', offset) + string.Concat(Enumerable.Repeat("\U0001F512", 2000));

        var bytes = Bytes(new LogEvent { TimestampUtc = When, Level = LogEventLevel.Warning, Message = message });

        Assert.True(bytes.Length <= SyslogFormatter.MaxMessageBytes);
        new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(bytes); // throws on a broken sequence
    }

    [Fact]
    public void The_message_stays_inside_the_limit_with_a_bom_too()
    {
        var bytes = Bytes(new LogEvent { TimestampUtc = When, Level = LogEventLevel.Warning, Message = "ü" + new string('x', 10_000) });

        Assert.Equal(SyslogFormatter.MaxMessageBytes, bytes.Length);
    }

    // ---- CEF ----

    [Fact]
    public void A_cef_event_goes_in_the_message_of_a_valid_syslog_line()
    {
        var text = Text(Blocked(), Syslog(SyslogFormat.Cef));

        Assert.Equal(
            "CEF:0|WinGuard|WinGuard|0.2.0|1001|Address banned|6|rt=1772366400250 src=203.0.113.7 cs2Label=engine cs2=rdp msg=BLOCKED 203.0.113.7 for 1.00:00:00 (offense #1)",
            Parse(text).Groups["msg"].Value);
    }

    [Theory]
    [InlineData(LogEventLevel.Error, "8")]
    [InlineData(LogEventLevel.Warning, "6")]
    [InlineData(LogEventLevel.Info, "3")]
    public void Cef_severity_follows_the_level(LogEventLevel level, string severity)
    {
        var cef = Parse(Text(new LogEvent { TimestampUtc = When, Level = level, Message = "UNBANNED 203.0.113.7" }, Syslog(SyslogFormat.Cef))).Groups["msg"].Value;

        Assert.Equal(severity, cef.Split('|')[6]);
    }

    [Fact]
    public void Cef_extension_values_escape_what_would_end_them()
    {
        var logEvent = new LogEvent { TimestampUtc = When, Level = LogEventLevel.Warning, Message = @"a=b c\d" + "\r\nforged=1" };

        var cef = Parse(Text(logEvent, Syslog(SyslogFormat.Cef))).Groups["msg"].Value;

        Assert.EndsWith(@"msg=a\=b c\\d\nforged\=1", cef);
    }

    [Fact]
    public void Cef_header_fields_escape_the_pipe_and_the_backslash()
    {
        var cef = SyslogFormatter.Format(Blocked(), Syslog(SyslogFormat.Cef), "h", 1, @"1|2\3");

        Assert.Contains(@"|WinGuard|1\|2\\3|1001|", Encoding.UTF8.GetString(cef));
    }

    [Fact]
    public void An_ipv6_source_or_prefix_does_not_go_in_the_ipv4_field()
    {
        foreach (var ip in new[] { "2001:db8::1", "2001:db8:1:2::/64" })
        {
            var cef = Parse(Text(Blocked(ip), Syslog(SyslogFormat.Cef))).Groups["msg"].Value;

            Assert.DoesNotContain(" src=", cef);
            Assert.Contains("cs1Label=sourceAddress cs1=" + ip, cef);
        }
    }

    // ---- through the dispatcher ----

    private sealed class RecordingTransport : ISyslogTransport
    {
        private readonly List<SyslogMessage> _sent = [];

        public List<SyslogMessage> Sent
        {
            get
            {
                lock (_sent)
                {
                    return _sent.ToList();
                }
            }
        }

        /// <summary>Set: every send waits for its token, as a receiver that never answers.</summary>
        public bool Hang { get; set; }

        public Exception? Failure { get; set; }

        public async Task SendAsync(SyslogMessage message, CancellationToken ct)
        {
            if (Hang)
            {
                await Task.Delay(Timeout.Infinite, ct);
            }

            if (Failure is not null)
            {
                throw Failure;
            }

            lock (_sent)
            {
                _sent.Add(message);
            }
        }

        public void Dispose()
        {
        }
    }

    private sealed class CountingHandler : HttpMessageHandler
    {
        private int _requests;

        public int Requests => Volatile.Read(ref _requests);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _requests);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }

    private sealed class RecordingLogger : ILogger<NotificationDispatcher>
    {
        private readonly List<(LogLevel Level, string Message)> _entries = [];

        public List<(LogLevel Level, string Message)> Entries
        {
            get
            {
                lock (_entries)
                {
                    return _entries.ToList();
                }
            }
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            lock (_entries)
            {
                _entries.Add((logLevel, formatter(state, exception)));
            }
        }
    }

    private static NotificationDispatcher Dispatcher(WinGuardSettings settings, ISyslogTransport transport, HttpClient? http = null, TimeProvider? time = null) =>
        new(() => settings, NullLogger<NotificationDispatcher>.Instance, null, http, time, transport);

    private static async Task WaitUntilAsync(Func<bool> condition, string what)
    {
        var waited = Stopwatch.StartNew();
        while (!condition())
        {
            Assert.True(waited.Elapsed < TimeSpan.FromSeconds(10), "timed out waiting for: " + what);
            await Task.Delay(5);
        }
    }

    [Fact]
    public async Task An_event_reaches_syslog_with_the_notification_master_switch_off()
    {
        var transport = new RecordingTransport();
        var settings = new WinGuardSettings();
        settings.Notifications.Syslog = Syslog();
        using var dispatcher = Dispatcher(settings, transport);
        dispatcher.Start();

        dispatcher.Publish(Blocked());
        await WaitUntilAsync(() => transport.Sent.Count > 0, "the syslog message");
        await dispatcher.StopAsync();

        var message = Assert.Single(transport.Sent);
        Assert.Equal("siem.example.invalid", message.Host);
        Assert.Equal(514, message.Port);
        Assert.Equal(SyslogProtocol.Udp, message.Protocol);
        Assert.Contains("BLOCKED 203.0.113.7", Encoding.UTF8.GetString(message.Payload));
    }

    [Fact]
    public async Task Syslog_is_off_unless_it_is_switched_on()
    {
        var transport = new RecordingTransport();
        var settings = new WinGuardSettings();
        settings.Notifications.Syslog.Host = "siem.example.invalid";
        using var dispatcher = Dispatcher(settings, transport);
        dispatcher.Start();

        dispatcher.Publish(Blocked());
        await Task.Delay(50);
        await dispatcher.StopAsync();

        Assert.Empty(transport.Sent);
    }

    [Fact]
    public async Task Syslog_without_a_host_sends_nothing()
    {
        var transport = new RecordingTransport();
        var settings = new WinGuardSettings();
        settings.Notifications.Syslog.Enabled = true;
        using var dispatcher = Dispatcher(settings, transport);
        dispatcher.Start();

        dispatcher.Publish(Blocked());
        await Task.Delay(50);
        await dispatcher.StopAsync();

        Assert.Empty(transport.Sent);
    }

    [Fact]
    public async Task Syslog_gets_the_events_the_other_channels_get_and_no_more()
    {
        var transport = new RecordingTransport();
        var settings = new WinGuardSettings();
        settings.Notifications.Syslog = Syslog();
        using var dispatcher = Dispatcher(settings, transport);
        dispatcher.Start();

        dispatcher.Publish(new LogEvent { TimestampUtc = When, Level = LogEventLevel.Info, Message = "SKIPPED 203.0.113.7 (whitelist)" });
        dispatcher.Publish(new LogEvent { TimestampUtc = When, Level = LogEventLevel.Info, Message = "UNBANNED 203.0.113.7" });
        await WaitUntilAsync(() => transport.Sent.Count > 0, "the syslog message");
        await dispatcher.StopAsync();

        Assert.Contains("UNBANNED", Encoding.UTF8.GetString(Assert.Single(transport.Sent).Payload));
    }

    [Fact]
    public async Task The_chat_rate_limit_does_not_thin_out_syslog()
    {
        var transport = new RecordingTransport();
        using var handler = new CountingHandler();
        using var http = new HttpClient(handler);
        var settings = new WinGuardSettings();
        settings.Notifications.Enabled = true;
        settings.Notifications.WebhookUrl = WebhookUrl;
        settings.Notifications.RateLimitPerMinute = 2;
        settings.Notifications.Syslog = Syslog();
        using var dispatcher = Dispatcher(settings, transport, http);
        dispatcher.Start();

        for (var i = 0; i < 10; i++)
        {
            dispatcher.Publish(Blocked($"203.0.113.{i + 1}"));
        }

        await WaitUntilAsync(() => transport.Sent.Count == 10, "all ten syslog messages");
        await dispatcher.StopAsync();

        Assert.Equal(2, handler.Requests);
    }

    [Fact]
    public async Task The_summary_of_suppressed_notifications_reaches_syslog_too()
    {
        var transport = new RecordingTransport();
        var time = new FakeTimeProvider(new DateTimeOffset(When));
        using var handler = new CountingHandler();
        using var http = new HttpClient(handler);
        var settings = new WinGuardSettings();
        settings.Notifications.Enabled = true;
        settings.Notifications.WebhookUrl = WebhookUrl;
        settings.Notifications.RateLimitPerMinute = 1;
        settings.Notifications.Syslog = Syslog();
        using var dispatcher = Dispatcher(settings, transport, http, time);
        dispatcher.Start();

        dispatcher.Publish(Blocked("203.0.113.1"));
        dispatcher.Publish(Blocked("203.0.113.2"));
        await WaitUntilAsync(() => dispatcher.SuppressedCount == 1, "the suppression");

        time.Advance(NotificationDispatcher.SuppressionSummaryInterval);
        await dispatcher.FlushSuppressedAsync(CancellationToken.None);
        await WaitUntilAsync(() => transport.Sent.Count == 3, "the summary");
        await dispatcher.StopAsync();

        Assert.Contains(transport.Sent, message => Encoding.UTF8.GetString(message.Payload).Contains(" 1006 - SUPPRESSED "));
    }

    [Fact]
    public async Task A_receiver_that_hangs_holds_up_no_other_channel()
    {
        var transport = new RecordingTransport { Hang = true };
        using var handler = new CountingHandler();
        using var http = new HttpClient(handler);
        var settings = new WinGuardSettings();
        settings.Notifications.Enabled = true;
        settings.Notifications.WebhookUrl = WebhookUrl;
        settings.Notifications.Syslog = Syslog();
        using var dispatcher = Dispatcher(settings, transport, http);
        dispatcher.Start();
        var watch = Stopwatch.StartNew();

        for (var i = 0; i < 5; i++)
        {
            dispatcher.Publish(Blocked($"203.0.113.{i + 1}"));
        }

        await WaitUntilAsync(() => handler.Requests == 5, "all five webhooks");

        // One syslog timeout is five seconds; one per event would be twenty-five.
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(4), $"took {watch.Elapsed}");

        var stopping = Stopwatch.StartNew();
        await dispatcher.StopAsync();
        Assert.True(stopping.Elapsed < TimeSpan.FromSeconds(4), $"stopping took {stopping.Elapsed}");
    }

    // ---- the sender ----

    [Fact]
    public async Task A_send_that_times_out_lets_the_next_one_through()
    {
        var transport = new RecordingTransport { Hang = true };
        using var sender = new SyslogSender(NullLogger.Instance, transport) { SendTimeout = TimeSpan.FromMilliseconds(30) };
        sender.Start();

        sender.Enqueue(Blocked("203.0.113.1"), Syslog());
        await Task.Delay(100);
        transport.Hang = false;
        sender.Enqueue(Blocked("203.0.113.2"), Syslog());
        await WaitUntilAsync(() => transport.Sent.Count > 0, "the second message");
        await sender.StopAsync();

        Assert.Contains("203.0.113.2", Encoding.UTF8.GetString(Assert.Single(transport.Sent).Payload));
    }

    [Fact]
    public async Task An_outage_is_logged_when_it_starts_and_when_it_ends_not_per_message()
    {
        var logger = new RecordingLogger();
        var transport = new RecordingTransport { Failure = new SocketException((int)SocketError.ConnectionRefused) };
        using var sender = new SyslogSender(logger, transport);
        sender.Start();

        for (var i = 0; i < 20; i++)
        {
            sender.Enqueue(Blocked(), Syslog());
        }

        await WaitUntilAsync(() => logger.Entries.Count > 0, "the outage warning");
        await Task.Delay(50);
        Assert.Single(logger.Entries, entry => entry.Level == LogLevel.Warning);

        transport.Failure = null;
        sender.Enqueue(Blocked(), Syslog());
        await WaitUntilAsync(() => logger.Entries.Any(entry => entry.Level == LogLevel.Information), "the recovery");
        await sender.StopAsync();

        Assert.Contains("works again", logger.Entries.Last().Message);
    }

    [Fact]
    public void A_full_queue_drops_rather_than_blocks_and_counts_what_it_dropped()
    {
        using var sender = new SyslogSender(NullLogger.Instance, new RecordingTransport());

        for (var i = 0; i < 1005; i++)
        {
            sender.Enqueue(Blocked(), Syslog());
        }

        Assert.Equal(5, sender.Dropped);
    }

    [Fact]
    public async Task The_settings_of_the_moment_decide_each_message()
    {
        var transport = new RecordingTransport();
        using var sender = new SyslogSender(NullLogger.Instance, transport);
        sender.Start();
        var settings = Syslog();

        sender.Enqueue(Blocked(), settings);
        settings.Host = "other.example.invalid";
        settings.Port = 1514;
        settings.Protocol = SyslogProtocol.Tcp;
        sender.Enqueue(Blocked(), settings);
        await WaitUntilAsync(() => transport.Sent.Count == 2, "both messages");
        await sender.StopAsync();

        Assert.Equal("siem.example.invalid", transport.Sent[0].Host);
        Assert.Equal(("other.example.invalid", 1514, SyslogProtocol.Tcp), (transport.Sent[1].Host, transport.Sent[1].Port, transport.Sent[1].Protocol));
    }

    // ---- the real sockets, over loopback ----

    private static SyslogMessage Message(int port, SyslogProtocol protocol, string text) =>
        new(IPAddress.Loopback.ToString(), port, protocol, Encoding.ASCII.GetBytes(text));

    private static CancellationToken FiveSeconds() => new CancellationTokenSource(TimeSpan.FromSeconds(5)).Token;

    [Fact]
    public async Task A_udp_message_is_one_datagram_without_framing()
    {
        using var receiver = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)receiver.Client.LocalEndPoint!).Port;
        using var transport = new SocketSyslogTransport();

        await transport.SendAsync(Message(port, SyslogProtocol.Udp, "<36>1 - - - - - - hello"), FiveSeconds());

        var received = await receiver.ReceiveAsync(FiveSeconds());
        Assert.Equal("<36>1 - - - - - - hello", Encoding.ASCII.GetString(received.Buffer));
    }

    [Fact]
    public async Task Tcp_messages_share_a_connection_one_per_line()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            using var transport = new SocketSyslogTransport();

            await transport.SendAsync(Message(port, SyslogProtocol.Tcp, "first"), FiveSeconds());
            using var accepted = await listener.AcceptTcpClientAsync(FiveSeconds());
            await transport.SendAsync(Message(port, SyslogProtocol.Tcp, "second"), FiveSeconds());

            using var reader = new StreamReader(accepted.GetStream(), Encoding.ASCII);
            Assert.Equal("first", await reader.ReadLineAsync(FiveSeconds()));
            Assert.Equal("second", await reader.ReadLineAsync(FiveSeconds()));
            Assert.False(listener.Pending());
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task A_receiver_that_went_away_gets_a_new_connection_and_no_message_is_lost()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            using var transport = new SocketSyslogTransport();

            await transport.SendAsync(Message(port, SyslogProtocol.Tcp, "before"), FiveSeconds());
            using (var first = await listener.AcceptTcpClientAsync(FiveSeconds()))
            {
                using var reader = new StreamReader(first.GetStream(), Encoding.ASCII);
                Assert.Equal("before", await reader.ReadLineAsync(FiveSeconds()));
            }

            await Task.Delay(100); // long enough for the close to reach the sender

            await transport.SendAsync(Message(port, SyslogProtocol.Tcp, "after"), FiveSeconds());
            using var second = await listener.AcceptTcpClientAsync(FiveSeconds());
            using var again = new StreamReader(second.GetStream(), Encoding.ASCII);
            Assert.Equal("after", await again.ReadLineAsync(FiveSeconds()));
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task A_closed_port_fails_the_send_with_an_exception_the_sender_handles()
    {
        int port;
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        using var transport = new SocketSyslogTransport();

        await Assert.ThrowsAnyAsync<Exception>(() => transport.SendAsync(Message(port, SyslogProtocol.Tcp, "x"), FiveSeconds()));
    }

    [Fact]
    public async Task The_timeout_reaches_the_connection_attempt()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            using var transport = new SocketSyslogTransport();
            using var expired = new CancellationTokenSource();
            await expired.CancelAsync();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => transport.SendAsync(Message(port, SyslogProtocol.Tcp, "x"), expired.Token));
            Assert.False(listener.Pending());
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task A_failed_connection_is_not_kept_for_the_next_message()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            using var transport = new SocketSyslogTransport();
            using var expired = new CancellationTokenSource();
            await expired.CancelAsync();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => transport.SendAsync(Message(port, SyslogProtocol.Tcp, "lost"), expired.Token));

            await transport.SendAsync(Message(port, SyslogProtocol.Tcp, "next"), FiveSeconds());

            using var accepted = await listener.AcceptTcpClientAsync(FiveSeconds());
            using var reader = new StreamReader(accepted.GetStream(), Encoding.ASCII);
            Assert.Equal("next", await reader.ReadLineAsync(FiveSeconds()));
        }
        finally
        {
            listener.Stop();
        }
    }

    // ---- the settings ----

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(70000)]
    public void A_port_out_of_range_falls_back_to_the_default(int port)
    {
        var settings = new WinGuardSettings();
        settings.Notifications.Syslog.Port = port;

        settings.Normalize();

        Assert.Equal(SyslogSettings.DefaultPort, settings.Notifications.Syslog.Port);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(24)]
    public void A_facility_out_of_range_falls_back_to_the_default(int facility)
    {
        var settings = new WinGuardSettings();
        settings.Notifications.Syslog.Facility = facility;

        settings.Normalize();

        Assert.Equal(SyslogSettings.DefaultFacility, settings.Notifications.Syslog.Facility);
    }

    [Fact]
    public void Enum_values_from_a_bad_request_fall_back_too()
    {
        var settings = new WinGuardSettings();
        settings.Notifications.Syslog.Protocol = (SyslogProtocol)99;
        settings.Notifications.Syslog.Format = (SyslogFormat)99;

        settings.Normalize();

        Assert.Equal(SyslogProtocol.Udp, settings.Notifications.Syslog.Protocol);
        Assert.Equal(SyslogFormat.Rfc5424, settings.Notifications.Syslog.Format);
    }

    [Fact]
    public void The_host_is_trimmed()
    {
        var settings = new WinGuardSettings();
        settings.Notifications.Syslog.Host = "  siem.example.invalid ";

        settings.Normalize();

        Assert.Equal("siem.example.invalid", settings.Notifications.Syslog.Host);
    }

    [Theory]
    [InlineData("", "a host is required")]
    [InlineData("two words", "host name or an address")]
    [InlineData("bad\nhost", "host name or an address")]
    public void The_validator_refuses_an_enabled_channel_without_a_usable_host(string host, string reason)
    {
        var settings = new WinGuardSettings();
        settings.Notifications.Syslog = new SyslogSettings { Enabled = true, Host = host };

        Assert.Contains(reason, Assert.Single(SettingsValidator.Validate(settings)));
    }

    [Theory]
    [InlineData("siem.example.com")]
    [InlineData("192.0.2.10")]
    [InlineData("2001:db8::10")]
    public void The_validator_takes_names_and_addresses(string host)
    {
        var settings = new WinGuardSettings();
        settings.Notifications.Syslog = new SyslogSettings { Enabled = true, Host = host };

        Assert.Empty(SettingsValidator.Validate(settings));
    }

    [Fact]
    public void A_channel_that_is_off_may_have_no_host()
    {
        Assert.Empty(SettingsValidator.Validate(new WinGuardSettings()));
    }

    private static int IndexOf(byte[] haystack, byte[] needle) =>
        Convert.ToHexString(haystack).IndexOf(Convert.ToHexString(needle), StringComparison.Ordinal) is var index and >= 0 ? index / 2 : -1;
}
