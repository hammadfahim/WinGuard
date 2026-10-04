using System.Diagnostics.Eventing.Reader;
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
/// cleared, Event Log service restarted, channel enabled after start-up).
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
    private DateTime _lastFaultUtc = DateTime.MinValue;
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

    /// <summary>Whether the engine is currently enabled in the live settings.</summary>
    protected abstract bool IsEnabled();

    /// <summary>Turns one event record into a failure, or null when it is not one.</summary>
    protected abstract FailedLogin? Parse(EventRecord record);

    /// <inheritdoc />
    public Task StartAsync(Channel<FailedLogin> sink, CancellationToken ct)
    {
        _sink = sink ?? throw new ArgumentNullException(nameof(sink));
        TrySubscribe();
        ct.Register(Stop);
        _ = Task.Run(() => MonitorAsync(ct), CancellationToken.None);
        return Task.CompletedTask;
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

            if (!_running)
            {
                TrySubscribe();
            }
        }
    }

    private void TrySubscribe()
    {
        lock (_lock)
        {
            if (_stopped || _watcher is not null)
            {
                return;
            }

            Exception? lastError = null;
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
                    _running = true;
                    Logger.LogInformation(
                        _failureLogged ? "{Detector}: subscription to {Channel} restored." : "{Detector}: subscribed to {Channel}.",
                        Name,
                        LogChannel);
                    _failureLogged = false;
                    return;
                }
                catch (Exception ex)
                {
                    lastError = ex;
                    SafeDispose(watcher);
                }
            }

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
    }

    private void OnEventRecordWritten(object? sender, EventRecordWrittenEventArgs args)
    {
        var record = args.EventRecord;
        if (record is null)
        {
            if (args.EventException is not null)
            {
                OnSubscriptionFault(sender as EventLogWatcher, args.EventException);
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
                if (failed is not null && _sink is { } sink && !sink.Writer.TryWrite(failed))
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
    /// </summary>
    private void OnSubscriptionFault(EventLogWatcher? source, Exception error)
    {
        bool quickRetry;
        lock (_lock)
        {
            if (source is null || !ReferenceEquals(source, _watcher))
            {
                return;
            }

            _watcher = null;
            _running = false;
            var now = DateTime.UtcNow;
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
        EventLogWatcher? watcher;
        lock (_lock)
        {
            _stopped = true;
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
