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
/// Publishes WinGuard events to external channels: an HTTPS webhook, a Telegram chat and/or SMTP
/// e-mail, behind a shared rate limit. Opt-in (see <see cref="NotificationSettings"/>): nothing is
/// sent unless the administrator configured a destination. WinGuard never contacts anything else.
/// <para>
/// <see cref="Publish"/> enqueues into a bounded channel and returns immediately, so the engine's
/// hot path is never blocked by a slow receiver; overflow events are dropped (a notification is
/// best-effort — the events table remains the source of truth). Delivery runs on one background
/// loop started by the service host.
/// </para>
/// </summary>
public sealed class NotificationDispatcher : IEventPublisher, IDisposable
{
    private static readonly TimeSpan SendTimeout = TimeSpan.FromSeconds(10);

    private readonly Func<WinGuardSettings> _settingsAccessor;
    private readonly ILogger<NotificationDispatcher> _logger;
    private readonly Channel<LogEvent> _queue;
    private readonly object _rateLock = new();
    private readonly Queue<DateTime> _recentSends = new();

    private readonly HttpClient _httpClient;
    private CancellationTokenSource? _cts;
    private Task? _loop;
    private bool _disposed;

    /// <summary>Creates the dispatcher.</summary>
    /// <param name="settingsAccessor">Live settings (channels are re-read per event).</param>
    /// <param name="logger">Diagnostic logger.</param>
    /// <param name="httpClient">Optional HTTP client (tests inject one); created when null.</param>
    public NotificationDispatcher(
        Func<WinGuardSettings> settingsAccessor,
        ILogger<NotificationDispatcher> logger,
        HttpClient? httpClient = null)
    {
        _settingsAccessor = settingsAccessor ?? throw new ArgumentNullException(nameof(settingsAccessor));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _httpClient = httpClient ?? new HttpClient();
        _queue = Channel.CreateBounded<LogEvent>(new BoundedChannelOptions(500)
        {
            SingleReader = true,
            FullMode = BoundedChannelFullMode.DropWrite,
        });
    }

    /// <summary>Starts the delivery loop.</summary>
    public void Start()
    {
        if (_loop is not null)
        {
            return;
        }

        _cts = new CancellationTokenSource();
        var token = _cts.Token;
        _loop = Task.Run(() => DeliverLoopAsync(token), CancellationToken.None);
        _logger.LogInformation("Notification dispatcher started.");
    }

    /// <summary>Stops the delivery loop and waits for it to finish (drops pending events).</summary>
    public async Task StopAsync()
    {
        _cts?.Cancel();
        if (_loop is not null)
        {
            try
            {
                await _loop.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Notification dispatcher loop ended with an error.");
            }
        }

        _loop = null;
    }

    /// <inheritdoc />
    public void Publish(LogEvent logEvent)
    {
        if (logEvent is null)
        {
            return;
        }

        // Only meaningful engine actions are worth an out-of-band ping: blocks, unblocks and
        // errors are Warning/Error; the Info-level stream (SKIPPED, housekeeping) is not.
        if (logEvent.Level < LogEventLevel.Warning)
        {
            return;
        }

        try
        {
            _queue.Writer.TryWrite(logEvent);
        }
        catch (Exception)
        {
            // Channel completed/disposed: no-op.
        }
    }

    private async Task DeliverLoopAsync(CancellationToken ct)
    {
        try
        {
            await foreach (var logEvent in _queue.Reader.ReadAllAsync(ct).ConfigureAwait(false))
            {
                try
                {
                    await DeliverOnceAsync(logEvent, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Notification delivery failed for '{Message}'.", logEvent.Message);
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Normal stop.
        }
    }

    private async Task DeliverOnceAsync(LogEvent logEvent, CancellationToken ct)
    {
        var settings = _settingsAccessor();
        var notifications = settings?.Notifications;
        if (notifications is not { Enabled: true })
        {
            return;
        }

        if (!AcquireRateSlot(notifications.RateLimitPerMinute))
        {
            // Dropping is the correct behavior under a brute-force storm: the events feed keeps
            // the full record, and the next successful send carries fresh state.
            _logger.LogDebug("Notification rate limit reached; dropping '{Message}'.", logEvent.Message);
            return;
        }

        var text = FormatEvent(logEvent);

        if (!string.IsNullOrWhiteSpace(notifications.WebhookUrl))
        {
            await SendWebhookAsync(notifications.WebhookUrl.Trim(), text, logEvent, ct).ConfigureAwait(false);
        }

        if (!string.IsNullOrWhiteSpace(notifications.TelegramBotToken) && !string.IsNullOrWhiteSpace(notifications.TelegramChatId))
        {
            await SendTelegramAsync(notifications.TelegramBotToken.Trim(), notifications.TelegramChatId.Trim(), text, ct).ConfigureAwait(false);
        }

        var smtp = notifications.Smtp;
        if (smtp is { } && !string.IsNullOrWhiteSpace(smtp.Host) && !string.IsNullOrWhiteSpace(smtp.To))
        {
            await SendMailAsync(smtp, text, ct).ConfigureAwait(false);
        }
    }

    /// <summary>Simple sliding-window rate limiter shared by all channels.</summary>
    internal bool AcquireRateSlot(int limitPerMinute)
    {
        lock (_rateLock)
        {
            var now = DateTime.UtcNow;
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

    private async Task SendWebhookAsync(string url, string text, LogEvent logEvent, CancellationToken ct)
    {
        try
        {
            if (!url.StartsWith("https://", StringComparison.OrdinalIgnoreCase) && !url.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("Webhook URL is not HTTP(S); no webhook was sent.");
                return;
            }

            var payload = JsonSerializer.Serialize(new
            {
                timestampUtc = logEvent.TimestampUtc,
                level = logEvent.Level.ToString(),
                source = logEvent.Source?.ToString(),
                ip = logEvent.IpAddress,
                message = logEvent.Message,
                text,
            }, IpcJson.Options);

            using var content = new StringContent(payload, Encoding.UTF8, new MediaTypeHeaderValue("application/json"));
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(SendTimeout);
            using var response = await _httpClient.PostAsync(url, content, timeout.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Webhook {Url} answered {Status}.", url, (int)response.StatusCode);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _logger.LogWarning(ex, "Webhook delivery to {Url} failed.", url);
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
            _logger.LogWarning(ex, "Telegram delivery failed.");
        }
    }

    private static async Task SendMailAsync(SmtpSettings smtp, string text, CancellationToken ct)
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
            Timeout = (int)SendTimeout.TotalMilliseconds,
        };

        if (!string.IsNullOrWhiteSpace(smtp.Username))
        {
            client.UseDefaultCredentials = false;
            client.Credentials = new System.Net.NetworkCredential(smtp.Username.Trim(), smtp.Password);
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(SendTimeout);
        await client.SendMailAsync(message, timeout.Token).ConfigureAwait(false);
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
        _httpClient.Dispose();
    }
}

/// <summary>
/// Writes warning/error engine events into the Windows <c>Application</c> event log under the
/// <c>WinGuard</c> source, so Windows Event Forwarding, Splunk, Wazuh and friends can consume
/// WinGuard activity without polling the GUI pipe. Opt-in via
/// <see cref="NotificationSettings.WriteToWindowsEventLog"/> (default on).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsEventLogWriter : IEventPublisher
{
    /// <summary>Event-log source WinGuard writes under (created on first use; needs one elevation).</summary>
    public const string SourceName = "WinGuard";

    private readonly Func<WinGuardSettings>? _settingsAccessor;
    private readonly ILogger _logger;
    private readonly bool _available;
    private bool _warnedSourceFailure;

    /// <summary>Creates the writer.</summary>
    /// <param name="settingsAccessor">Live settings; when supplied the built-in toggle is honored.</param>
    /// <param name="logger">Diagnostic logger.</param>
    public WindowsEventLogWriter(Func<WinGuardSettings>? settingsAccessor, ILogger logger)
    {
        _settingsAccessor = settingsAccessor;
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _available = OperatingSystem.IsWindows();
    }

    /// <inheritdoc />
    public void Publish(LogEvent logEvent)
    {
        if (!_available || logEvent is null || logEvent.Level < LogEventLevel.Warning)
        {
            return;
        }

        try
        {
            var settings = _settingsAccessor?.Invoke();
            if (settings?.Notifications is { } notifications && !notifications.WriteToWindowsEventLog)
            {
                return;
            }

            if (!System.Diagnostics.EventLog.SourceExists(SourceName))
            {
                System.Diagnostics.EventLog.CreateEventSource(SourceName, "Application");
                _logger.LogInformation("Created the '{Source}' event source in the Application log.", SourceName);
            }

            var entryType = logEvent.Level switch
            {
                LogEventLevel.Error => System.Diagnostics.EventLogEntryType.Error,
                _ => System.Diagnostics.EventLogEntryType.Warning,
            };

            var message = logEvent.Message + (logEvent.IpAddress is null ? string.Empty : $" [{logEvent.IpAddress}]");
            System.Diagnostics.EventLog.WriteEntry(SourceName, message, entryType);
        }
        catch (Exception ex)
        {
            // A locked-down Application log must never break the engine; complain once.
            if (!_warnedSourceFailure)
            {
                _warnedSourceFailure = true;
                _logger.LogWarning(ex, "Could not write to the Windows Application event log; Windows Event Log output is disabled for this run.");
            }
        }
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
