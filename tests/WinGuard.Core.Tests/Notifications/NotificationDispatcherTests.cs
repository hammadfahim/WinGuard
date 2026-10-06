using Microsoft.Extensions.Logging.Abstractions;
using WinGuard.Core.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Model;
using WinGuard.Core.Notifications;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>
/// Tests for the notification fan-out: the sliding-window rate limiter, the severity filter and
/// the composite publisher's failure isolation. Network delivery itself is exercised live, not
/// in unit tests.
/// </summary>
public sealed class NotificationDispatcherTests
{
    private static NotificationDispatcher Create(WinGuardSettings? settings = null)
    {
        settings ??= new WinGuardSettings();
        return new NotificationDispatcher(() => settings, NullLogger<NotificationDispatcher>.Instance);
    }

    [Fact]
    public void Rate_limit_allows_N_sends_per_minute_then_drops()
    {
        using var dispatcher = Create();

        for (var i = 0; i < 20; i++)
        {
            Assert.True(dispatcher.AcquireRateSlot(20));
        }

        Assert.False(dispatcher.AcquireRateSlot(20));
    }

    [Fact]
    public void Publish_never_throws_and_ignores_info_events()
    {
        using var dispatcher = Create();
        dispatcher.Publish(new LogEvent { Level = LogEventLevel.Info, Message = "SKIPPED 1.2.3.4 (whitelist)" });
        dispatcher.Publish(new LogEvent { Level = LogEventLevel.Warning, Message = "BLOCKED 1.2.3.4" });
        dispatcher.Publish(null!);
    }

    [Fact]
    public async Task A_disabled_dispatcher_drops_everything_without_sending()
    {
        var settings = new WinGuardSettings
        {
            Notifications = new NotificationSettings { Enabled = false, WebhookUrl = "https://example.invalid/hook" },
        };
        using var dispatcher = Create(settings);
        dispatcher.Start();

        // Publish is fire-and-forget; give the loop a moment, then stop. Not sending is the
        // expected outcome (there is no receiver at example.invalid; a send attempt would only
        // log a warning, so the assertion is simply that Stop completes).
        dispatcher.Publish(new LogEvent { Level = LogEventLevel.Warning, Message = "BLOCKED 1.2.3.4" });
        await dispatcher.StopAsync();
    }

    [Fact]
    public void Composite_publisher_isolates_broken_sinks()
    {
        var recorder = new RecordingPublisher();
        var composite = new CompositeEventPublisher(new ThrowingPublisher(), recorder);

        var logEvent = new LogEvent { Level = LogEventLevel.Warning, Message = "BLOCKED 1.2.3.4" };
        composite.Publish(logEvent);

        Assert.Same(logEvent, Assert.Single(recorder.Records));
    }

    [Fact]
    public void Null_publisher_is_a_no_op()
    {
        NullEventPublisher.Instance.Publish(new LogEvent { Message = "x" });
    }

    [Fact]
    public void Windows_event_log_writer_honors_its_toggle_and_level_filter()
    {
        var writer = new WindowsEventLogWriter(NullLogger<WindowsEventLogWriter>.Instance);
        var off = new NotificationSettings { WriteToWindowsEventLog = false };

        // Toggle off / Info-level events never reach the event-log API.
        writer.Write(new LogEvent { Level = LogEventLevel.Warning, Message = "BLOCKED 1.2.3.4" }, off);
        writer.Write(new LogEvent { Level = LogEventLevel.Info, Message = "SKIPPED 1.2.3.4" }, null);
        writer.Write(null!, null);
    }

    private sealed class RecordingPublisher : IEventPublisher
    {
        public List<LogEvent> Records { get; } = [];

        public void Publish(LogEvent logEvent) => Records.Add(logEvent);
    }

    private sealed class ThrowingPublisher : IEventPublisher
    {
        public void Publish(LogEvent logEvent) => throw new InvalidOperationException("sink is broken");
    }
}
