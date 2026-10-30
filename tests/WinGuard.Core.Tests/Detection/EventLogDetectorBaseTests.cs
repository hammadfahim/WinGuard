using System.Diagnostics.Eventing.Reader;
using System.Threading.Channels;
using Microsoft.Extensions.Logging.Abstractions;
using WinGuard.Core.Detection;
using WinGuard.Core.Model;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>
/// Replay and re-subscription logic of the event-log detectors, run through the base class's seams
/// so no real event log is read or subscribed to.
/// </summary>
public sealed class EventLogDetectorBaseTests
{
    private static readonly TimeSpan WaitLimit = TimeSpan.FromSeconds(15);

    [Fact]
    public async Task Failures_from_the_startup_replay_are_flagged_as_replayed()
    {
        var detector = new FakeDetector { Backlog = [Failure("203.0.113.1"), null, Failure("203.0.113.2")] };
        var sink = Channel.CreateUnbounded<FailedLogin>();
        using var cts = new CancellationTokenSource();

        await detector.StartAsync(sink, cts.Token);
        var first = await sink.Reader.ReadAsync(cts.Token).AsTask().WaitAsync(WaitLimit);
        var second = await sink.Reader.ReadAsync(cts.Token).AsTask().WaitAsync(WaitLimit);
        await cts.CancelAsync();

        Assert.Equal(new[] { "203.0.113.1", "203.0.113.2" }, new[] { first.IpAddress, second.IpAddress });
        Assert.True(first.IsReplayed);
        Assert.True(second.IsReplayed);
    }

    [Fact]
    public async Task The_startup_replay_covers_the_backlog_window_up_to_now()
    {
        var detector = new FakeDetector { Window = TimeSpan.FromMinutes(30), Backlog = [Failure("203.0.113.1")] };
        var sink = Channel.CreateUnbounded<FailedLogin>();
        using var cts = new CancellationTokenSource();
        var before = DateTime.UtcNow;

        await detector.StartAsync(sink, cts.Token);
        await sink.Reader.ReadAsync(cts.Token).AsTask().WaitAsync(WaitLimit);
        await cts.CancelAsync();

        var (from, to) = Assert.Single(detector.Ranges);
        Assert.InRange(to, before, DateTime.UtcNow);
        Assert.Equal(TimeSpan.FromMinutes(30), to - from);
    }

    [Fact]
    public async Task A_detector_without_a_backlog_window_does_not_replay_at_startup()
    {
        var detector = new FakeDetector { Window = TimeSpan.Zero };
        var sink = Channel.CreateUnbounded<FailedLogin>();
        using var cts = new CancellationTokenSource();

        await detector.StartAsync(sink, cts.Token);
        await cts.CancelAsync();

        Assert.Empty(detector.Ranges);
        Assert.True(detector.OpenAttempts >= 1);
    }

    [Fact]
    public async Task Failures_logged_during_a_subscription_fault_are_replayed_after_resubscribing()
    {
        var detector = new FakeDetector();
        var sink = Channel.CreateUnbounded<FailedLogin>();
        using var cts = new CancellationTokenSource();
        await detector.StartAsync(sink, cts.Token);
        await detector.Opened.WaitAsync(WaitLimit);
        Assert.True(detector.IsRunning);
        var faulted = DateTime.UtcNow;
        detector.Backlog = [Failure("203.0.113.5")];

        detector.OnSubscriptionFault(null, new InvalidOperationException("channel cleared"));
        Assert.False(detector.IsRunning);

        // The quick retry subscribes again on its own and catches up.
        var replayed = await sink.Reader.ReadAsync(cts.Token).AsTask().WaitAsync(WaitLimit);
        var running = detector.IsRunning;
        await cts.CancelAsync();

        Assert.True(running);
        Assert.Equal("203.0.113.5", replayed.IpAddress);
        Assert.True(replayed.IsReplayed);
        var (from, to) = detector.Ranges[^1];
        Assert.InRange(from, faulted, to);
    }

    [Fact]
    public async Task A_subscription_that_only_opens_later_replays_since_the_first_failed_attempt()
    {
        var detector = new FakeDetector { CanOpen = false };
        var sink = Channel.CreateUnbounded<FailedLogin>();
        using var cts = new CancellationTokenSource();
        var started = DateTime.UtcNow;
        await detector.StartAsync(sink, cts.Token);
        await detector.Attempted.WaitAsync(WaitLimit);
        Assert.False(detector.IsRunning);

        detector.CanOpen = true;
        detector.Backlog = [Failure("203.0.113.6")];
        detector.TrySubscribe();
        var opened = DateTime.UtcNow;

        var replayed = await sink.Reader.ReadAsync(cts.Token).AsTask().WaitAsync(WaitLimit);
        await cts.CancelAsync();

        Assert.Equal("203.0.113.6", replayed.IpAddress);
        Assert.True(replayed.IsReplayed);
        var (from, to) = detector.Ranges[^1];
        Assert.InRange(from, started, to);
        Assert.InRange(to, started, opened);
    }

    [Fact]
    public void A_healthy_subscription_never_replays_a_gap()
    {
        var detector = new FakeDetector();

        detector.TrySubscribe();
        detector.TrySubscribe();

        Assert.True(detector.IsRunning);
        Assert.Equal(1, detector.OpenAttempts);
        Assert.Empty(detector.Ranges);
    }

    [Fact]
    public async Task The_gap_replay_is_capped_by_the_backlog_window()
    {
        var detector = new FakeDetector { Window = TimeSpan.FromMinutes(10) };
        var subscribed = new DateTime(2026, 10, 4, 12, 0, 0, DateTimeKind.Utc);

        await detector.ReplayGapAsync(subscribed.AddHours(-5), subscribed, CancellationToken.None);

        Assert.Equal((subscribed.AddMinutes(-10), subscribed), Assert.Single(detector.Ranges));
    }

    [Fact]
    public async Task A_short_gap_is_replayed_from_when_it_began()
    {
        var detector = new FakeDetector { Window = TimeSpan.FromMinutes(10) };
        var subscribed = new DateTime(2026, 10, 4, 12, 0, 0, DateTimeKind.Utc);

        await detector.ReplayGapAsync(subscribed.AddSeconds(-40), subscribed, CancellationToken.None);

        Assert.Equal((subscribed.AddSeconds(-40), subscribed), Assert.Single(detector.Ranges));
    }

    [Fact]
    public async Task With_replay_turned_off_a_gap_is_not_replayed()
    {
        var detector = new FakeDetector { Window = TimeSpan.Zero };
        var now = DateTime.UtcNow;

        await detector.ReplayGapAsync(now.AddMinutes(-1), now, CancellationToken.None);

        Assert.Empty(detector.Ranges);
    }

    [Fact]
    public async Task A_failing_gap_replay_is_contained()
    {
        var detector = new FakeDetector { ThrowOnRead = true };
        var now = DateTime.UtcNow;

        await detector.ReplayGapAsync(now.AddMinutes(-1), now, CancellationToken.None);

        Assert.Single(detector.Ranges);
    }

    [Fact]
    public void The_replay_query_is_a_half_open_utc_range()
    {
        var from = new DateTime(2026, 10, 4, 9, 0, 0, 5, DateTimeKind.Utc);
        var to = new DateTime(2026, 10, 4, 9, 30, 0, DateTimeKind.Utc);

        var xpath = EventLogDetectorBase.BuildReplayXPath("EventID=4625", from, to);

        Assert.Equal(
            "*[System[EventID=4625 and TimeCreated[@SystemTime>='2026-10-04T09:00:00.005Z' and @SystemTime<'2026-10-04T09:30:00.000Z']]]",
            xpath);
    }

    private static FailedLogin Failure(string ip) => new()
    {
        IpAddress = ip,
        Source = ProtocolSource.Rdp,
        Detector = "test",
        TimestampUtc = DateTime.UtcNow,
    };

    [Fact]
    public async Task A_detector_that_wants_no_events_does_not_subscribe_or_report_a_failure()
    {
        var detector = new FakeDetector { Wanted = false, Window = TimeSpan.Zero };
        var sink = Channel.CreateUnbounded<FailedLogin>();
        using var cts = new CancellationTokenSource();

        await detector.StartAsync(sink, cts.Token);
        detector.ReconcileSubscription();
        await cts.CancelAsync();

        Assert.Equal(0, detector.OpenAttempts);
        Assert.False(detector.IsRunning);
    }

    [Fact]
    public async Task A_subscription_follows_the_setting_and_replays_nothing_for_the_time_it_was_off()
    {
        var detector = new FakeDetector { Wanted = false, Window = TimeSpan.Zero };
        var sink = Channel.CreateUnbounded<FailedLogin>();
        using var cts = new CancellationTokenSource();
        await detector.StartAsync(sink, cts.Token);

        detector.Wanted = true;
        detector.Window = TimeSpan.FromMinutes(30);
        detector.ReconcileSubscription();
        Assert.True(detector.IsRunning);

        detector.Wanted = false;
        detector.ReconcileSubscription();
        Assert.False(detector.IsRunning);

        detector.Wanted = true;
        detector.ReconcileSubscription();
        Assert.True(detector.IsRunning);
        await cts.CancelAsync();

        Assert.Empty(detector.Ranges);
    }

    private sealed class FakeDetector : EventLogDetectorBase
    {
        private readonly TaskCompletionSource _opened = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _attempted = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public FakeDetector()
            : base(NullLogger.Instance)
        {
        }

        public List<FailedLogin?> Backlog { get; set; } = [];

        public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(30);

        public bool Wanted { get; set; } = true;

        public bool CanOpen { get; set; } = true;

        public bool ThrowOnRead { get; init; }

        public int OpenAttempts { get; private set; }

        public List<(DateTime From, DateTime To)> Ranges { get; } = [];

        public Task Opened => _opened.Task;

        public Task Attempted => _attempted.Task;

        public override ProtocolSource Source => ProtocolSource.Rdp;

        public override string Name => "fake";

        protected override string LogChannel => "WinGuard-Test-NoSuchChannel";

        protected override IReadOnlyList<(string Query, bool TolerateQueryErrors)> Queries => [];

        protected override string? BacklogEventXPath => "EventID=1";

        protected override TimeSpan BacklogWindow() => Window;

        protected override bool IsEnabled() => true;

        protected override FailedLogin? Parse(EventRecord record) => throw new NotSupportedException();

        private protected override bool WantsSubscription() => Wanted;

        private protected override IEnumerable<FailedLogin?> ReadBacklog(DateTime fromUtc, DateTime toUtc, CancellationToken ct)
        {
            lock (Ranges)
            {
                Ranges.Add((fromUtc, toUtc));
            }

            if (ThrowOnRead)
            {
                throw new InvalidOperationException("no such channel");
            }

            var backlog = Backlog;
            Backlog = [];
            return backlog;
        }

        private protected override bool OpenSubscription(out Exception? lastError)
        {
            OpenAttempts++;
            lastError = CanOpen ? null : new InvalidOperationException("channel not enabled");
            if (CanOpen)
            {
                _opened.TrySetResult();
            }

            _attempted.TrySetResult();
            return CanOpen;
        }
    }
}
