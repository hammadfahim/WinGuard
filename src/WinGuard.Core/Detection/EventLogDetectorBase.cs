using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Runtime.Versioning;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using WinGuard.Core.Abstractions;
using WinGuard.Core.Model;

namespace WinGuard.Core.Detection;

/// <summary>
/// Shared plumbing for the Windows event-log detectors: subscribes with an
/// <see cref="EventLogWatcher"/>, reports whether the subscription is actually alive through
/// <see cref="IsRunning"/>, and re-subscribes when it could not be created or later fails (channel
/// cleared, Event Log service restarted, channel enabled after start-up). Events logged while there
/// was no subscription are replayed once it is back, within the same limits as the start-up replay.
/// <para>
/// The subscription is created regardless of the enabled setting; <see cref="IsEnabled"/> is checked
/// per event, so toggling an engine in the GUI takes effect without a service restart.
/// </para>
/// </summary>
[SupportedOSPlatform("windows")]
public abstract class EventLogDetectorBase : IDetector
{
    private static readonly TimeSpan RetryInterval = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan QuickRetryDelay = TimeSpan.FromSeconds(2);

    private readonly object _lock = new();
    private EventLogWatcher? _watcher;
    private Channel<FailedLogin>? _sink;
    private CancellationToken _stopping;
    private DateTime _lastFaultUtc = DateTime.MinValue;

    // When the subscription was lost or first failed to open; null while there is no gap.
    private DateTime? _gapStartUtc;
    private bool _failureLogged;
    private volatile bool _running;
    private volatile bool _stopped;

    /// <summary>Creates the detector base.</summary>
    /// <param name="logger">Logger for subscription and parse diagnostics.</param>
    protected EventLogDetectorBase(ILogger logger)
    {
        Logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public abstract ProtocolSource Source { get; }

    /// <inheritdoc />
    public abstract string Name { get; }

    /// <inheritdoc />
    public bool IsRunning => _running;

    /// <summary>Logger shared with the derived detector.</summary>
    protected ILogger Logger { get; }

    /// <summary>Event-log channel to subscribe to.</summary>
    protected abstract string LogChannel { get; }

    /// <summary>Structured queries to try, in order; the first one the channel accepts is used.</summary>
    protected abstract IReadOnlyList<(string Query, bool TolerateQueryErrors)> Queries { get; }

    /// <summary>
    /// Raw XPath selecting the interesting events (no QueryList wrapper), used by the start-up
    /// backlog replay. Null (default) disables the replay for this detector.
    /// </summary>
    protected virtual string? BacklogEventXPath => null;

    /// <summary>
    /// Optional XPath on the event's payload, e.g. <c>EventData[...]</c>, for the replay query.
    /// <see cref="BacklogEventXPath"/> sits inside <c>System[...]</c> and cannot reach those fields.
    /// </summary>
    protected virtual string? BacklogDataXPath => null;

    /// <summary>
    /// How much history to replay at start-up (covers failures logged while the service was
    /// stopped). Derived classes read the live setting; zero disables the replay.
    /// </summary>
    protected virtual TimeSpan BacklogWindow() => TimeSpan.Zero;

    /// <summary>Whether the engine is currently enabled in the live settings.</summary>
    protected abstract bool IsEnabled();

    /// <summary>Turns one event record into a failure, or null when it is not one.</summary>
    protected abstract FailedLogin? Parse(EventRecord record);

    /// <summary>
    /// Whether the channel should be subscribed at all. A detector for a busy channel can stay
    /// unsubscribed while its feature is off, instead of ignoring every event. Checked by the monitor
    /// loop, so a change applies within <see cref="RetryInterval"/>. Nothing is replayed for the time
    /// it was off.
    /// </summary>
    private protected virtual bool WantsSubscription() => true;

    /// <summary>Whether a parsed record may enter the sink right now; a low-priority detector can give way under load.</summary>
    private protected virtual bool ShouldForward(Channel<FailedLogin> sink) => true;

    /// <summary>Upper bound on records examined per replay, so a huge backlog cannot stall startup.</summary>
    private const int MaxReplayRecords = 5000;

    /// <inheritdoc />
    public Task StartAsync(Channel<FailedLogin> sink, CancellationToken ct)
    {
        _sink = sink ?? throw new ArgumentNullException(nameof(sink));
        _stopping = ct;
        ct.Register(Stop);

        var backlog = BacklogWindow();
        if (backlog > TimeSpan.Zero && BacklogEventXPath is not null)
        {
            // Replay first, subscribe after: events between the replay read and the subscription
            // are missed (a tiny window, same as pre-replay behavior), never double-counted.
            _ = Task.Run(() => StartWithBacklogAsync(backlog, ct), CancellationToken.None);
        }
        else
        {
            TrySubscribe();
            _ = Task.Run(() => MonitorAsync(ct), CancellationToken.None);
        }

        return Task.CompletedTask;
    }

    private async Task StartWithBacklogAsync(TimeSpan backlog, CancellationToken ct)
    {
        try
        {
            var now = DateTime.UtcNow;
            await ReplayBacklogAsync(now - backlog, now, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return;
        }
        catch (Exception ex)
        {
            Logger.LogWarning(ex, "{Detector}: start-up backlog replay failed; live detection is unaffected.", Name);
        }

        TrySubscribe();
        _ = Task.Run(() => MonitorAsync(ct), CancellationToken.None);
    }

    /// <summary>
    /// Pushes the events logged in a time range through the normal <see cref="Parse"/> path, so
    /// failures logged while the service was stopped or unsubscribed still count towards a ban.
    /// The range can reach back into the previous run: the engine drops what that run already
    /// processed (see <see cref="FailedLogin.IsReplayed"/>).
    /// </summary>
    private async Task ReplayBacklogAsync(DateTime fromUtc, DateTime toUtc, CancellationToken ct)
    {
        var replayed = 0;
        var examined = 0;
        foreach (var failed in ReadBacklog(fromUtc, toUtc, ct))
        {
            examined++;
            if (failed is not null)
            {
                failed.IsReplayed = true;
                if (_sink is { } sink && ShouldForward(sink) && sink.Writer.TryWrite(failed))
                {
                    replayed++;
                }
            }

            // The reads are synchronous COM calls; yield so cancellation is observed promptly.
            if ((examined & 0x3F) == 0)
            {
                await Task.Yield();
            }
        }

        if (replayed > 0)
        {
            Logger.LogInformation(
                "{Detector}: replayed {Replayed} failure(s) logged in the {Channel} channel between {From:u} and {To:u}.",
                Name, replayed, LogChannel, fromUtc, toUtc);
        }
    }

    /// <summary>
    /// Reads and parses the events of a time range, newest first. Yields null for a record that is
    /// no failure, honors the live enabled setting per record and stops early once
    /// <see cref="MaxReplayRecords"/> records were seen. Tests replace it to run a replay without
    /// real event logs.
    /// </summary>
    private protected virtual IEnumerable<FailedLogin?> ReadBacklog(DateTime fromUtc, DateTime toUtc, CancellationToken ct)
    {
        var query = new EventLogQuery(LogChannel, PathType.LogName, BuildReplayXPath(BacklogEventXPath!, fromUtc, toUtc, BacklogDataXPath))
        {
            TolerateQueryErrors = true,
            ReverseDirection = true,
        };

        using var reader = new EventLogReader(query);
        for (var examined = 0; examined < MaxReplayRecords && !ct.IsCancellationRequested && !_stopped; examined++)
        {
            EventRecord? record;
            try
            {
                record = reader.ReadEvent();
            }
            catch (Exception ex)
            {
                Logger.LogDebug(ex, "{Detector}: backlog replay read failed (channel may not exist).", Name);
                yield break;
            }

            if (record is null)
            {
                yield break;
            }

            yield return ParseReplayRecord(record);
        }
    }

    private FailedLogin? ParseReplayRecord(EventRecord record)
    {
        try
        {
            return IsEnabled() ? Parse(record) : null;
        }
        catch (Exception ex)
        {
            Logger.LogDebug(ex, "{Detector}: backlog replay parse failed for one record.", Name);
            return null;
        }
        finally
        {
            record.Dispose();
        }
    }

    /// <summary>The replay query: <paramref name="eventXPath"/> within a half-open UTC time range, plus an optional payload filter.</summary>
    internal static string BuildReplayXPath(string eventXPath, DateTime fromUtc, DateTime toUtc, string? dataXPath = null)
    {
        static string Stamp(DateTime utc) => utc.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture);

        var data = dataXPath is null ? string.Empty : " and " + dataXPath;
        return $"*[System[{eventXPath.Trim('/', ' ')} and TimeCreated[@SystemTime>='{Stamp(fromUtc)}' and @SystemTime<'{Stamp(toUtc)}']]{data}]";
    }

    /// <summary>
    /// Catches up on what was logged while there was no subscription. The range ends where the new
    /// subscription begins, so an event is never seen by both, and it is limited like the start-up
    /// replay: <see cref="BacklogWindow"/> caps it, and a window of zero turns it off.
    /// </summary>
    internal async Task ReplayGapAsync(DateTime gapStartUtc, DateTime subscribedUtc, CancellationToken ct)
    {
        var window = BacklogWindow();
        if (window <= TimeSpan.Zero || BacklogEventXPath is null)
        {
            return;
        }

        var oldest = subscribedUtc - window;
        try
        {
            await ReplayBacklogAsync(gapStartUtc > oldest ? gapStartUtc : oldest, subscribedUtc, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Shutting down.
        }
        catch (Exception ex)
        {
            Logger.LogWarning(ex, "{Detector}: replaying the subscription gap failed; live detection is unaffected.", Name);
        }
    }

    private async Task MonitorAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(RetryInterval, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            ReconcileSubscription();
        }
    }

    /// <summary>Subscribes or lets go, whichever the current state calls for.</summary>
    internal void ReconcileSubscription()
    {
        if (!_running)
        {
            TrySubscribe();
        }
        else if (!WantsSubscription())
        {
            Unsubscribe();
            Logger.LogInformation("{Detector}: unsubscribed from {Channel}; the feature is off.", Name, LogChannel);
        }
    }

    internal void TrySubscribe()
    {
        // Taken before subscribing: an event in the instant between the two is missed rather than
        // counted twice, the same trade-off as the start-up replay.
        var subscribedUtc = DateTime.UtcNow;
        DateTime? gapStartUtc;
        lock (_lock)
        {
            if (_stopped || _running || !WantsSubscription())
            {
                return;
            }

            if (OpenSubscription(out var lastError))
            {
                _running = true;
                Logger.LogInformation(
                    _failureLogged ? "{Detector}: subscription to {Channel} restored." : "{Detector}: subscribed to {Channel}.",
                    Name,
                    LogChannel);
                _failureLogged = false;
                gapStartUtc = _gapStartUtc;
                _gapStartUtc = null;
            }
            else
            {
                _gapStartUtc ??= subscribedUtc;
                gapStartUtc = null;
                LogSubscribeFailure(lastError);
            }
        }

        if (gapStartUtc is { } gapStart)
        {
            _ = Task.Run(() => ReplayGapAsync(gapStart, subscribedUtc, _stopping), CancellationToken.None);
        }
    }

    /// <summary>Opens the first query the channel accepts. Tests replace it to run without real event logs.</summary>
    private protected virtual bool OpenSubscription(out Exception? lastError)
    {
        lastError = null;
        foreach (var (queryText, tolerate) in Queries)
        {
            EventLogWatcher? watcher = null;
            try
            {
                var query = new EventLogQuery(LogChannel, PathType.LogName, queryText)
                {
                    TolerateQueryErrors = tolerate,
                };
                watcher = new EventLogWatcher(query);
                watcher.EventRecordWritten += OnEventRecordWritten;
                watcher.Enabled = true;

                _watcher = watcher;
                return true;
            }
            catch (Exception ex)
            {
                lastError = ex;
                SafeDispose(watcher);
            }
        }

        return false;
    }

    private void LogSubscribeFailure(Exception? lastError)
    {
        // Log the failure once, not on every retry.
        if (!_failureLogged)
        {
            _failureLogged = true;
            Logger.LogError(
                lastError,
                "{Detector} could not subscribe to the {Channel} channel; detection is inactive (retrying every {Seconds}s).",
                Name,
                LogChannel,
                RetryInterval.TotalSeconds);
        }
        else
        {
            Logger.LogDebug(lastError, "{Detector}: subscription retry failed.", Name);
        }
    }

    private void OnEventRecordWritten(object? sender, EventRecordWrittenEventArgs args)
    {
        var record = args.EventRecord;
        if (record is null)
        {
            if (args.EventException is not null && sender is EventLogWatcher watcher)
            {
                OnSubscriptionFault(watcher, args.EventException);
            }

            return;
        }

        try
        {
            using (record)
            {
                // Live toggle: honor the enabled setting per event, not only at subscribe time.
                if (!IsEnabled())
                {
                    return;
                }

                var failed = Parse(record);
                if (failed is not null && _sink is { } sink && ShouldForward(sink) && !sink.Writer.TryWrite(failed))
                {
                    Logger.LogWarning("{Detector} could not write to the sink channel (closed).", Name);
                }
            }
        }
        catch (Exception ex)
        {
            Logger.LogWarning(ex, "{Detector} failed to process an event record.", Name);
        }
    }

    /// <summary>
    /// The watcher reports a broken subscription through an event with no record. Drop it and
    /// subscribe again: quickly the first time, then on the monitor's schedule if faults repeat.
    /// What is logged until then is replayed once the new subscription is up.
    /// </summary>
    internal void OnSubscriptionFault(EventLogWatcher? source, Exception error)
    {
        bool quickRetry;
        lock (_lock)
        {
            if (!ReferenceEquals(source, _watcher))
            {
                return;
            }

            _watcher = null;
            _running = false;
            var now = DateTime.UtcNow;
            _gapStartUtc ??= now;
            quickRetry = now - _lastFaultUtc > RetryInterval;
            _lastFaultUtc = now;
        }

        Logger.LogWarning(error, "{Detector}: the {Channel} subscription failed; re-subscribing.", Name, LogChannel);

        // Never dispose a watcher from inside its own callback.
        _ = Task.Run(async () =>
        {
            SafeDispose(source);
            if (quickRetry)
            {
                await Task.Delay(QuickRetryDelay).ConfigureAwait(false);
                TrySubscribe();
            }
        });
    }

    private void Stop()
    {
        _stopped = true;
        Unsubscribe();
    }

    private void Unsubscribe()
    {
        EventLogWatcher? watcher;
        lock (_lock)
        {
            watcher = _watcher;
            _watcher = null;
            _running = false;
        }

        SafeDispose(watcher);
    }

    private void SafeDispose(EventLogWatcher? watcher)
    {
        if (watcher is null)
        {
            return;
        }

        try
        {
            watcher.EventRecordWritten -= OnEventRecordWritten;
            watcher.Enabled = false;
            watcher.Dispose();
        }
        catch (Exception ex)
        {
            Logger.LogDebug(ex, "{Detector}: error while disposing the event-log watcher.", Name);
        }
    }
}
