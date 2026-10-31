using System.Net.Http.Headers;
using System.Net.Mail;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using WinGuard.Core.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Ipc;
using WinGuard.Core.Model;

namespace WinGuard.Core.Notifications;

/// <summary>
/// The event types WinGuard reports, and the stable ids they carry in the Windows Application log
/// (source <c>WinGuard</c>) so a SIEM can filter on them. The ids are a public contract, listed in
/// SECURITY.md: never renumber one, only add.
/// <para>
/// Events are told apart by their message, which the engine writes: <see cref="LogEvent"/> has no
/// type field. The notification tests run the real engine, so a reworded message fails there.
/// </para>
/// </summary>
public static class WinGuardEventIds
{
    /// <summary>The engine banned an address after repeated failures, or a blacklisted one.</summary>
    public const int Blocked = 1001;

    /// <summary>An administrator blocked an address.</summary>
    public const int ManualBlock = 1002;

    /// <summary>A ban ran out and the address was unblocked.</summary>
    public const int BanExpired = 1003;

    /// <summary>An administrator unblocked an address.</summary>
    public const int ManualUnblock = 1004;

    /// <summary>The engine lifted a range ban because it came to overlap the whitelist.</summary>
    public const int RangeUnblocked = 1005;

    /// <summary>Notifications were dropped by the rate limit or a full queue.</summary>
    public const int NotificationsSuppressed = 1006;

    /// <summary>A logon succeeded from an address with recent failures or an active ban.</summary>
    public const int PossibleCompromise = 1007;

    /// <summary>Break-glass: enforcement was disarmed and the firewall rules removed.</summary>
    public const int Disarmed = 1020;

    /// <summary>Break-glass: a disarm ended and enforcement resumed.</summary>
    public const int Rearmed = 1021;

    /// <summary>Break-glass: a disarm file was expired, corrupt or untrusted and was ignored.</summary>
    public const int DisarmRefused = 1022;

    /// <summary>Any other warning.</summary>
    public const int OtherWarning = 1900;

    /// <summary>Any error.</summary>
    public const int Error = 1901;

    /// <summary>Any other informational event (written only if it ever becomes notifiable).</summary>
    public const int OtherInformation = 1902;

    internal const string SuppressedPrefix = "SUPPRESSED ";
    internal const string CompromisePrefix = "POSSIBLE COMPROMISE: ";
    internal const string DisarmedPrefix = "DISARMED ";
    internal const string RearmedPrefix = "REARMED ";
    internal const string DisarmRefusedPrefix = "DISARM REFUSED ";

    // The engine logs an expired ban at Info level; it is the one Info event worth reporting.
    private const string ExpiredPrefix = "UNBANNED ";

    /// <summary>The id of an event; see <see cref="WinGuardEventIds"/>.</summary>
    public static int For(LogEvent logEvent)
    {
        ArgumentNullException.ThrowIfNull(logEvent);

        var message = logEvent.Message;
        if (logEvent.Level == LogEventLevel.Error)
        {
            return Error;
        }

        if (message.StartsWith("BLOCKED ", StringComparison.Ordinal))
        {
            return Blocked;
        }

        if (message.StartsWith("MANUAL BLOCK ", StringComparison.Ordinal))
        {
            return ManualBlock;
        }

        if (message.StartsWith(ExpiredPrefix, StringComparison.Ordinal))
        {
            return BanExpired;
        }

        if (message.StartsWith("MANUAL UNBLOCK ", StringComparison.Ordinal))
        {
            return ManualUnblock;
        }

        if (message.StartsWith("UNBLOCKED ", StringComparison.Ordinal))
        {
            return RangeUnblocked;
        }

        if (message.StartsWith(SuppressedPrefix, StringComparison.Ordinal))
        {
            return NotificationsSuppressed;
        }

        if (message.StartsWith(CompromisePrefix, StringComparison.Ordinal))
        {
            return PossibleCompromise;
        }

        if (message.StartsWith(DisarmedPrefix, StringComparison.Ordinal))
        {
            return Disarmed;
        }

        if (message.StartsWith(RearmedPrefix, StringComparison.Ordinal))
        {
            return Rearmed;
        }

        if (message.StartsWith(DisarmRefusedPrefix, StringComparison.Ordinal))
        {
            return DisarmRefused;
        }

        return logEvent.Level == LogEventLevel.Warning ? OtherWarning : OtherInformation;
    }

    /// <summary>
    /// Whether an event is worth an out-of-band ping: blocks, unblocks and errors, which includes
    /// expired bans although they are logged at Info; the rest of the Info stream (SKIPPED,
    /// housekeeping) is not.
    /// </summary>
    public static bool IsNotifiable(LogEvent logEvent) =>
        logEvent.Level >= LogEventLevel.Warning || For(logEvent) == BanExpired;
}

/// <summary>
/// Publishes WinGuard events to external channels: an HTTPS webhook, a Telegram chat and/or SMTP
/// e-mail, behind a shared rate limit. Opt-in (see <see cref="NotificationSettings"/>): nothing is
/// sent unless the administrator configured a destination. WinGuard never contacts anything else.
/// <para>
/// <see cref="Publish"/> enqueues into bounded channels and returns immediately, so the engine's
/// hot path is never blocked by a slow receiver; overflow events are dropped (a notification is
/// best-effort — the events table remains the source of truth). Whatever the rate limit or a queue
/// dropped is counted and reported as one summary per <see cref="SuppressionSummaryInterval"/>.
/// </para>
/// <para>
/// Delivery runs on two background loops started by the service host, each with its own queue. The
/// Windows Application log and syslog are the record a SIEM relies on, and neither waits for the
/// network here; webhook, Telegram and SMTP can each take many seconds to fail. With one loop a
/// dead receiver held every later event back from the SIEM and filled the shared queue, so a
/// webhook that hangs now costs chat notifications and nothing else.
/// </para>
/// <para>
/// A webhook URL and a Telegram token are secrets (whoever holds one can post to the channel), so
/// neither reaches the log.
/// </para>
/// </summary>
public sealed class NotificationDispatcher : IEventPublisher, IDisposable
{
    /// <summary>At most one "N notifications suppressed" summary is sent per this interval.</summary>
    internal static readonly TimeSpan SuppressionSummaryInterval = TimeSpan.FromMinutes(5);

    private const int DiscordContentLimit = 2000;

    private static readonly TimeSpan SendTimeout = TimeSpan.FromSeconds(10);

    // SmtpClient.Timeout only applies to synchronous sends; this limit is the one that counts, and
    // a TLS handshake with a slow relay needs more time than an HTTP POST.
    private static readonly TimeSpan MailSendTimeout = TimeSpan.FromSeconds(30);

    private readonly Func<WinGuardSettings> _settingsAccessor;
    private readonly ILogger<NotificationDispatcher> _logger;
    private readonly WindowsEventLogWriter? _windowsEventLog;
    private readonly SyslogSender _syslog;
    private readonly TimeProvider _timeProvider;
    private readonly Channel<LogEvent> _siemQueue;
    private readonly Channel<LogEvent> _channelQueue;
    private readonly object _rateLock = new();
    private readonly Queue<DateTime> _recentSends = new();

    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;
    private CancellationTokenSource? _cts;
    private Task? _loops;
    private bool _disposed;

    // Guarded by _rateLock.
    private long _suppressed;
    private DateTime _suppressedSinceUtc;

    // The summary on its way to the channels. It waits here rather than in the queue, so a full
    // queue cannot swallow the news of its own overflow.
    private LogEvent? _pendingSummary;

    // The channel loop is the only writer; a change of URL warns again.
    private string? _warnedPlainHttpUrl;

    /// <summary>Creates the dispatcher.</summary>
    /// <param name="settingsAccessor">Live settings (channels are re-read per event).</param>
    /// <param name="logger">Diagnostic logger.</param>
    /// <param name="windowsEventLog">
    /// Optional Windows Application-log writer, delivered on the dispatcher's SIEM loop so the
    /// engine's hot path never performs event-log I/O. Honors its own settings toggle,
    /// independent of the notification master switch.
    /// </param>
    /// <param name="httpClient">Optional HTTP client (tests inject one and keep ownership); created when null.</param>
    /// <param name="timeProvider">Clock for the rate limit and the summaries; the system clock when null.</param>
    public NotificationDispatcher(
        Func<WinGuardSettings> settingsAccessor,
        ILogger<NotificationDispatcher> logger,
        WindowsEventLogWriter? windowsEventLog = null,
        HttpClient? httpClient = null,
        TimeProvider? timeProvider = null)
        : this(settingsAccessor, logger, windowsEventLog, httpClient, timeProvider, new SocketSyslogTransport())
    {
    }

    /// <summary>For the tests: a syslog transport that needs no network.</summary>
    internal NotificationDispatcher(
        Func<WinGuardSettings> settingsAccessor,
        ILogger<NotificationDispatcher> logger,
        WindowsEventLogWriter? windowsEventLog,
        HttpClient? httpClient,
        TimeProvider? timeProvider,
        ISyslogTransport syslogTransport)
    {
        _settingsAccessor = settingsAccessor ?? throw new ArgumentNullException(nameof(settingsAccessor));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _windowsEventLog = windowsEventLog;
        _syslog = new SyslogSender(logger, syslogTransport);
        _ownsHttpClient = httpClient is null;
        _httpClient = httpClient ?? new HttpClient();
        _timeProvider = timeProvider ?? TimeProvider.System;

        _siemQueue = CreateQueue();
        _channelQueue = CreateQueue();
    }

    /// <summary>How often an idle loop checks for a summary that is due.</summary>
    internal TimeSpan SummaryPollInterval { get; init; } = TimeSpan.FromSeconds(15);

    /// <summary>Notifications dropped since the last summary.</summary>
    internal long SuppressedCount
    {
        get
        {
            lock (_rateLock)
            {
                return _suppressed;
            }
        }
    }

    private DateTime UtcNow => _timeProvider.GetUtcNow().UtcDateTime;

    // TryWrite reports success even when DropWrite discards the item; only the callback knows.
    private Channel<LogEvent> CreateQueue() => Channel.CreateBounded<LogEvent>(
        new BoundedChannelOptions(500)
        {
            SingleReader = true,
            FullMode = BoundedChannelFullMode.DropWrite,
        },
        _ => NoteSuppressed());

    /// <summary>Starts the delivery loops.</summary>
    public void Start()
    {
        if (_loops is not null)
        {
            return;
        }

        _cts = new CancellationTokenSource();
        var token = _cts.Token;
        _syslog.Start();
        _loops = Task.WhenAll(
            Task.Run(() => SiemLoopAsync(token), CancellationToken.None),
            Task.Run(() => ChannelLoopAsync(token), CancellationToken.None));
        _logger.LogInformation("Notification dispatcher started.");
    }

    /// <summary>Stops the delivery loops and waits for them to finish (drops pending events).</summary>
    public async Task StopAsync()
    {
        _cts?.Cancel();
        if (_loops is not null)
        {
            try
            {
                await _loops.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Notification dispatcher loop ended with an error.");
            }
        }

        _loops = null;
        await _syslog.StopAsync().ConfigureAwait(false);

        // The summary that was not due yet, so the count is not lost with the process.
        var unreported = SuppressedCount;
        if (unreported > 0)
        {
            _logger.LogWarning("{Count} notification(s) were suppressed and never reported to the channels before the stop.", unreported);
        }

        _cts?.Dispose();
        _cts = null;
    }

    /// <inheritdoc />
    public void Publish(LogEvent logEvent)
    {
        if (logEvent is null || !WinGuardEventIds.IsNotifiable(logEvent))
        {
            return;
        }

        try
        {
            _siemQueue.Writer.TryWrite(logEvent);

            // Read here, not at delivery: with the channels off the queue would only fill up.
            if (_settingsAccessor()?.Notifications is { Enabled: true })
            {
                _channelQueue.Writer.TryWrite(logEvent);
            }
        }
        catch (Exception)
        {
            // Channel completed/disposed: no-op.
        }
    }

    /// <summary>The Windows Application log and syslog. Nothing here waits for a remote receiver.</summary>
    private async Task SiemLoopAsync(CancellationToken ct)
    {
        var reader = _siemQueue.Reader;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await WaitForWorkAsync(reader, ct).ConfigureAwait(false);

                while (reader.TryRead(out var logEvent))
                {
                    try
                    {
                        DeliverToSiem(logEvent);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Notification delivery failed for '{Message}'.", logEvent.Message);
                    }
                }

                // Also on an idle loop: the storm that filled the counter may be over, and then
                // nothing else would ever wake this up.
                try
                {
                    FlushSuppressed();
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Could not report suppressed notifications.");
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Normal stop.
        }
    }

    /// <summary>Webhook, Telegram and SMTP, one event at a time, however long each takes.</summary>
    private async Task ChannelLoopAsync(CancellationToken ct)
    {
        var reader = _channelQueue.Reader;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await WaitForWorkAsync(reader, ct).ConfigureAwait(false);
                await SendPendingSummaryAsync(ct).ConfigureAwait(false);

                while (reader.TryRead(out var logEvent))
                {
                    try
                    {
                        await DeliverToChannelsAsync(logEvent, ct).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (ct.IsCancellationRequested)
                    {
                        throw;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Notification delivery failed for '{Message}'.", logEvent.Message);
                    }

                    await SendPendingSummaryAsync(ct).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Normal stop.
        }
    }

    /// <summary>Returns when an event is waiting or a poll interval has passed.</summary>
    private async Task WaitForWorkAsync(ChannelReader<LogEvent> reader, CancellationToken ct)
    {
        using var poll = CancellationTokenSource.CreateLinkedTokenSource(ct);
        poll.CancelAfter(SummaryPollInterval);
        try
        {
            await reader.WaitToReadAsync(poll.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            // The poll interval passed.
        }
    }

    /// <summary>
    /// The Windows Application log and syslog are delivered regardless of the notification master
    /// switch (they have their own toggles) and are not rate limited: SIEM consumers want full
    /// fidelity. Syslog only queues here, so a hanging receiver holds nothing back.
    /// </summary>
    private void DeliverToSiem(LogEvent logEvent)
    {
        var settings = _settingsAccessor();
        if (settings is not null)
        {
            _windowsEventLog?.Write(logEvent, settings.Notifications);
            _syslog.Enqueue(logEvent, settings.Notifications?.Syslog);
        }
    }

    private async Task DeliverToChannelsAsync(LogEvent logEvent, CancellationToken ct)
    {
        if (_settingsAccessor()?.Notifications is not { Enabled: true } notifications)
        {
            return;
        }

        if (!AcquireRateSlot(notifications.RateLimitPerMinute))
        {
            // Dropping is the correct behavior under a brute-force storm: the events feed keeps
            // the full record, and the periodic summary says how much the channels missed.
            _logger.LogDebug("Notification rate limit reached; dropping '{Message}'.", logEvent.Message);
            NoteSuppressed();
            return;
        }

        await SendToChannelsAsync(notifications, logEvent, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Sends to every configured channel at once. Each send handles its own failures and timeout,
    /// so a dead channel neither stops the others nor delays them.
    /// </summary>
    private async Task SendToChannelsAsync(NotificationSettings notifications, LogEvent logEvent, CancellationToken ct)
    {
        var text = FormatEvent(logEvent);
        var sends = new List<Task>(3);

        if (!string.IsNullOrWhiteSpace(notifications.WebhookUrl))
        {
            sends.Add(SendWebhookAsync(notifications.WebhookUrl.Trim(), text, logEvent, ct));
        }

        if (!string.IsNullOrWhiteSpace(notifications.TelegramBotToken) && !string.IsNullOrWhiteSpace(notifications.TelegramChatId))
        {
            sends.Add(SendTelegramAsync(notifications.TelegramBotToken.Trim(), notifications.TelegramChatId.Trim(), text, ct));
        }

        var smtp = notifications.Smtp;
        if (smtp is { } && !string.IsNullOrWhiteSpace(smtp.Host) && !string.IsNullOrWhiteSpace(smtp.To))
        {
            sends.Add(SendMailAsync(smtp, text, ct));
        }

        await Task.WhenAll(sends).ConfigureAwait(false);
    }

    private void NoteSuppressed()
    {
        lock (_rateLock)
        {
            if (_suppressed++ == 0)
            {
                _suppressedSinceUtc = UtcNow;
            }
        }
    }

    /// <summary>
    /// Reports what was dropped once the summary is due: to the SIEM outputs here and now, and to the
    /// channels through their loop, so a dead receiver cannot delay it. The summary skips the rate
    /// limit, or a sustained storm would suppress the news of its own suppression; at one per
    /// <see cref="SuppressionSummaryInterval"/> it cannot flood anything.
    /// </summary>
    internal void FlushSuppressed()
    {
        long count;
        TimeSpan period;
        lock (_rateLock)
        {
            period = UtcNow - _suppressedSinceUtc;
            if (_suppressed == 0 || period < SuppressionSummaryInterval)
            {
                return;
            }

            count = _suppressed;
            _suppressed = 0;
        }

        var summary = new LogEvent
        {
            TimestampUtc = UtcNow,
            Level = LogEventLevel.Warning,
            Message = $"{WinGuardEventIds.SuppressedPrefix}{count} notification(s) in the last {Math.Ceiling(period.TotalMinutes):0} minute(s) "
                + "(rate limit or full queue); the WinGuard event feed holds the full record.",
        };
        _logger.LogWarning("{Message}", summary.Message);

        DeliverToSiem(summary);
        Volatile.Write(ref _pendingSummary, summary);
    }

    private async Task SendPendingSummaryAsync(CancellationToken ct)
    {
        var summary = Interlocked.Exchange(ref _pendingSummary, null);
        if (summary is null)
        {
            return;
        }

        try
        {
            if (_settingsAccessor()?.Notifications is { Enabled: true } notifications)
            {
                await SendToChannelsAsync(notifications, summary, ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not report suppressed notifications.");
        }
    }

    /// <summary>Simple sliding-window rate limiter shared by all channels.</summary>
    internal bool AcquireRateSlot(int limitPerMinute)
    {
        lock (_rateLock)
        {
            var now = UtcNow;
            while (_recentSends.Count > 0 && now - _recentSends.Peek() > TimeSpan.FromMinutes(1))
            {
                _recentSends.Dequeue();
            }

            if (_recentSends.Count >= limitPerMinute)
            {
                return false;
            }

            _recentSends.Enqueue(now);
            return true;
        }
    }

    private static string FormatEvent(LogEvent logEvent) =>
        $"WinGuard: {logEvent.Message}" + (logEvent.IpAddress is null ? string.Empty : $" [{logEvent.IpAddress}]")
        + $" ({logEvent.TimestampUtc:yyyy-MM-dd HH:mm:ss} UTC)";

    /// <summary>
    /// The webhook body. Incoming webhooks disagree on the field that carries the message: Discord
    /// requires <c>content</c> (at most 2000 characters) and rejects a body without it, Slack and
    /// Mattermost read <c>text</c>, Teams connector cards read <c>text</c> plus <c>title</c> and
    /// <c>summary</c>. All of them ignore fields they do not know, so one body serves them all, and
    /// the structured fields are there for automation receivers.
    /// </summary>
    internal static string BuildWebhookPayload(string text, LogEvent logEvent) => JsonSerializer.Serialize(new
    {
        content = text.Length > DiscordContentLimit ? text[..DiscordContentLimit] : text,
        text,
        title = "WinGuard",
        summary = text,
        timestampUtc = logEvent.TimestampUtc,
        level = logEvent.Level.ToString(),
        source = logEvent.Source?.ToString(),
        ip = logEvent.IpAddress,
        message = logEvent.Message,
    }, IpcJson.Options);

    /// <summary>A webhook URL as it may appear in a log: which host, without the secret path, query or credentials.</summary>
    internal static string RedactUrl(string url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var uri) && uri.Authority.Length > 0
            ? $"{uri.Scheme}://{uri.Authority}/***"
            : "(webhook URL hidden)";

    /// <summary>The reason a send failed, for the log, with any secret it quotes taken out.</summary>
    private static string FailureReason(Exception ex, string? secret)
    {
        if (ex is OperationCanceledException)
        {
            return "timed out";
        }

        var reason = ex.GetBaseException().Message;
        return string.IsNullOrEmpty(secret) ? reason : reason.Replace(secret, "***", StringComparison.OrdinalIgnoreCase);
    }

    private async Task SendWebhookAsync(string url, string text, LogEvent logEvent, CancellationToken ct)
    {
        var redacted = RedactUrl(url);
        try
        {
            if (!url.StartsWith("https://", StringComparison.OrdinalIgnoreCase) && !url.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("Webhook URL is not HTTP(S); no webhook was sent.");
                return;
            }

            if (url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) && !string.Equals(_warnedPlainHttpUrl, url, StringComparison.Ordinal))
            {
                _warnedPlainHttpUrl = url;
                _logger.LogWarning("Webhook URL {Url} is plain HTTP: the URL, which is a secret, and every notification travel unencrypted. Use an HTTPS URL.", redacted);
            }

            var payload = BuildWebhookPayload(text, logEvent);
            using var content = new StringContent(payload, Encoding.UTF8, new MediaTypeHeaderValue("application/json"));
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(SendTimeout);
            using var response = await _httpClient.PostAsync(url, content, timeout.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Webhook {Url} answered {Status}.", redacted, (int)response.StatusCode);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _logger.LogWarning("Webhook delivery to {Url} failed: {Reason}", redacted, FailureReason(ex, url));
        }
    }

    private async Task SendTelegramAsync(string botToken, string chatId, string text, CancellationToken ct)
    {
        try
        {
            var payload = JsonSerializer.Serialize(new { chat_id = chatId, text });
            using var content = new StringContent(payload, Encoding.UTF8, new MediaTypeHeaderValue("application/json"));
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(SendTimeout);
            using var response = await _httpClient
                .PostAsync($"https://api.telegram.org/bot{botToken}/sendMessage", content, timeout.Token)
                .ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Telegram answered {Status} for chat {Chat}.", (int)response.StatusCode, chatId);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _logger.LogWarning("Telegram delivery failed: {Reason}", FailureReason(ex, botToken));
        }
    }

    private async Task SendMailAsync(SmtpSettings smtp, string text, CancellationToken ct)
    {
        try
        {
            // System.Net.Mail lives in the base class library; no package needed.
            using var message = new MailMessage(
                string.IsNullOrWhiteSpace(smtp.From) ? "winguard@localhost" : smtp.From.Trim(),
                smtp.To.Trim(),
                "WinGuard notification",
                text)
            {
                BodyEncoding = Encoding.UTF8,
            };

            using var client = new SmtpClient(smtp.Host.Trim(), smtp.Port > 0 ? smtp.Port : 25)
            {
                EnableSsl = smtp.EnableSsl,
            };

            if (!string.IsNullOrWhiteSpace(smtp.Username))
            {
                client.UseDefaultCredentials = false;
                client.Credentials = new System.Net.NetworkCredential(smtp.Username.Trim(), smtp.Password);
            }

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(MailSendTimeout);
            await client.SendMailAsync(message, timeout.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            // Bad settings land here too: an invalid address throws while the message is built.
            _logger.LogWarning("E-mail delivery through {Host} failed: {Reason}", smtp.Host, FailureReason(ex, smtp.Password));
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _cts?.Cancel();
        _cts?.Dispose();
        _syslog.Dispose();
        if (_ownsHttpClient)
        {
            _httpClient.Dispose();
        }
    }
}

/// <summary>
/// Writes notifiable engine events into the Windows <c>Application</c> event log under the
/// <c>WinGuard</c> source, so Windows Event Forwarding, Splunk, Wazuh and friends can consume
/// WinGuard activity without polling the GUI pipe. Every entry carries the stable id of its type
/// (<see cref="WinGuardEventIds"/>). Opt-in via
/// <see cref="NotificationSettings.WriteToWindowsEventLog"/> (default on).
/// <para>
/// <see cref="Publish"/> stays on the calling (engine) path only to enqueue; the actual event-log
/// I/O is expected to run on the notification dispatcher's SIEM loop via <see cref="Write"/>,
/// which is also safe to call directly.
/// </para>
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsEventLogWriter : IEventPublisher
{
    /// <summary>Event-log source WinGuard writes under (created on first use; needs one elevation).</summary>
    public const string SourceName = "WinGuard";

    private readonly ILogger _logger;
    private readonly Action<string, System.Diagnostics.EventLogEntryType, int>? _sink;

    // Source-existence probing enumerates the event log registry and is slow; the result is
    // cached for the process lifetime (0 = unknown, 1 = ready, 2 = failed).
    private int _sourceState;

    // 1 while writes fail. An outage is reported when it starts and when it ends.
    private int _writesFailing;

    /// <summary>Creates the writer.</summary>
    /// <param name="logger">Diagnostic logger.</param>
    public WindowsEventLogWriter(ILogger logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>For the tests: writing to the real log needs administrator rights the first time.</summary>
    internal WindowsEventLogWriter(ILogger logger, Action<string, System.Diagnostics.EventLogEntryType, int> sink)
        : this(logger)
    {
        _sink = sink;
    }

    /// <summary>
    /// Direct sink entry: writes one event, honoring the
    /// <see cref="NotificationSettings.WriteToWindowsEventLog"/> toggle. Never throws.
    /// </summary>
    public void Write(LogEvent logEvent, NotificationSettings? settings)
    {
        if (!OperatingSystem.IsWindows() || logEvent is null || !WinGuardEventIds.IsNotifiable(logEvent))
        {
            return;
        }

        if (settings is not null && !settings.WriteToWindowsEventLog)
        {
            return;
        }

        if (_sink is null && !EnsureSource())
        {
            return;
        }

        try
        {
            var entryType = logEvent.Level switch
            {
                LogEventLevel.Error => System.Diagnostics.EventLogEntryType.Error,
                LogEventLevel.Warning => System.Diagnostics.EventLogEntryType.Warning,
                _ => System.Diagnostics.EventLogEntryType.Information,
            };

            var message = logEvent.Message + (logEvent.IpAddress is null ? string.Empty : $" [{logEvent.IpAddress}]");
            var eventId = WinGuardEventIds.For(logEvent);
            if (_sink is not null)
            {
                _sink(message, entryType, eventId);
            }
            else
            {
                System.Diagnostics.EventLog.WriteEntry(SourceName, message, entryType, eventId);
            }

            if (Interlocked.Exchange(ref _writesFailing, 0) == 1)
            {
                _logger.LogInformation("Writing to the Windows Application event log works again.");
            }
        }
        catch (Exception ex)
        {
            // A full log says nothing about the next event: a SIEM depends on this output, so one
            // failed write must not end it. Each event simply tries again.
            if (Interlocked.Exchange(ref _writesFailing, 1) == 0)
            {
                _logger.LogWarning(ex, "Could not write to the Windows Application event log. Not reported again until it works.");
            }
        }
    }

    /// <summary>True when the source is there. Without one nothing can be written, so that ends the output for this run.</summary>
    private bool EnsureSource()
    {
        var state = Volatile.Read(ref _sourceState);
        if (state != 0)
        {
            return state == 1;
        }

        try
        {
            if (!System.Diagnostics.EventLog.SourceExists(SourceName))
            {
                System.Diagnostics.EventLog.CreateEventSource(SourceName, "Application");
                _logger.LogInformation("Created the '{Source}' event source in the Application log.", SourceName);
            }

            Volatile.Write(ref _sourceState, 1);
            return true;
        }
        catch (Exception ex)
        {
            // A locked-down Application log must never break delivery; complain once and stop.
            Volatile.Write(ref _sourceState, 2);
            _logger.LogWarning(ex, "Could not set up the Windows Application event log source; Windows Event Log output is disabled for this run.");
            return false;
        }
    }

    /// <inheritdoc />
    public void Publish(LogEvent logEvent)
    {
        // Compatibility path for direct use as an IEventPublisher: no settings toggle available.
        Write(logEvent, null);
    }
}

/// <summary>Fans every event out to all registered publishers.</summary>
public sealed class CompositeEventPublisher : IEventPublisher
{
    private readonly IEventPublisher[] _publishers;

    /// <summary>Creates the composite.</summary>
    /// <param name="publishers">Publishers invoked in order; each failure is isolated.</param>
    public CompositeEventPublisher(params IEventPublisher[] publishers)
    {
        _publishers = publishers ?? [];
    }

    /// <inheritdoc />
    public void Publish(LogEvent logEvent)
    {
        foreach (var publisher in _publishers)
        {
            try
            {
                publisher.Publish(logEvent);
            }
            catch (Exception)
            {
                // One broken sink must not stop the others.
            }
        }
    }
}
