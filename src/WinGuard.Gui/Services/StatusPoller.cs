using System.Windows.Threading;
using WinGuard.Core.Ipc;

namespace WinGuard.Gui.Services;

/// <summary>
/// Drives the ~2 s GUI refresh (PLAN.md §9): status every tick, new events after the
/// <see cref="EventCursor"/> every tick, and bans whenever a view that shows them is active or every
/// fourth tick. The <see cref="DispatcherTimer"/> fires on the UI thread, so event handlers may touch
/// the view-model collections directly. Calls are skipped while disconnected; the
/// <see cref="PipeClient"/> background loop reconnects on its own.
/// </summary>
public sealed class StatusPoller : IDisposable
{
    // The most the service returns per request. Asking for less loses the older part of a burst:
    // ListEvents hands back the newest rows after the cursor, so what does not fit is never returned.
    private const int EventBatchLimit = 1000;

    private const int PausedHeartbeatTicks = 5; // x 2 s timer = one status call every 10 s
    private const int SlowTicks = 15; // x 2 s timer = every 30 s

    private readonly PipeClient _client;
    private readonly DispatcherTimer _timer;
    private readonly EventCursor _cursor = new();

    private int _tick;
    private int _pausedTicks;
    private bool _busy;

    /// <summary>Set by the shell when a view showing bans is on screen (forces a ban refresh each tick).</summary>
    public bool BansViewActive { get; set; }

    /// <summary>When true (window hidden/minimized) ticks do nothing, saving IPC and CPU.</summary>
    public bool Paused { get; set; }

    /// <summary>Raised when a fresh service status snapshot arrives.</summary>
    public event Action<ServiceStatusDto>? StatusUpdated;

    /// <summary>Raised when new events arrive.</summary>
    public event Action<EventBatch>? EventsReceived;

    /// <summary>Raised when the ban list is refreshed.</summary>
    public event Action<IReadOnlyList<BanDto>>? BansReceived;

    /// <summary>Raised about every 30 s while visible, for data too expensive to poll every tick.</summary>
    public event Action? SlowTick;

    /// <summary>Creates the poller for the given client.</summary>
    public StatusPoller(PipeClient client)
    {
        _client = client;
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _timer.Tick += OnTick;
    }

    /// <summary>True while the timer is running.</summary>
    public bool IsRunning => _timer.IsEnabled;

    /// <summary>Starts periodic polling.</summary>
    public void Start() => _timer.Start();

    /// <summary>Stops periodic polling.</summary>
    public void Stop() => _timer.Stop();

    /// <summary>Runs one full poll now, for F5 and after a reconnect.</summary>
    public async Task PollNowAsync()
    {
        if (_busy || !_client.IsConnected)
        {
            return;
        }

        await PollAsync(forceBans: true).ConfigureAwait(true);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _timer.Tick -= OnTick;
        _timer.Stop();
    }

    private async void OnTick(object? sender, EventArgs e)
    {
        if (_busy)
        {
            return;
        }

        if (Paused)
        {
            // Hidden window: no view needs refreshing, but keep a slow heartbeat so a stopped
            // service is still noticed (the tray icon follows the connection state). The event
            // cursor stays where it is, so everything that arrives meanwhile is read on return.
            if (++_pausedTicks % PausedHeartbeatTicks != 0 || !_client.IsConnected)
            {
                return;
            }

            _busy = true;
            try
            {
                await _client.GetStatusAsync().ConfigureAwait(true);
            }
            catch
            {
                // The client marks itself disconnected on failure.
            }
            finally
            {
                _busy = false;
            }

            return;
        }

        if (!_client.IsConnected)
        {
            return;
        }

        await PollAsync(forceBans: false).ConfigureAwait(true);
    }

    private async Task PollAsync(bool forceBans)
    {
        _busy = true;
        try
        {
            var status = await _client.GetStatusAsync().ConfigureAwait(true);
            if (status is not null)
            {
                StatusUpdated?.Invoke(status);
            }

            _tick++;
            if (_tick % SlowTicks == 0)
            {
                await VerifyCursorAsync().ConfigureAwait(true);
            }

            var events = await _client.ListEventsAsync(EventBatchLimit, null, _cursor.LastId).ConfigureAwait(true);
            if (events is { Count: > 0 })
            {
                EventsReceived?.Invoke(_cursor.Accept(events, EventBatchLimit));
            }

            if (forceBans || BansViewActive || _tick % 4 == 0)
            {
                // Null means the request failed: keep what is on screen rather than show "no bans".
                var bans = await _client.ListBansAsync().ConfigureAwait(true);
                if (bans is not null)
                {
                    BansReceived?.Invoke(bans);
                }
            }

            if (_tick % SlowTicks == 0)
            {
                SlowTick?.Invoke();
            }
        }
        catch
        {
            // Polling must never surface an exception; the client marks itself disconnected on failure.
        }
        finally
        {
            _busy = false;
        }
    }

    private async Task VerifyCursorAsync()
    {
        if (_cursor.LastId is null)
        {
            return;
        }

        var newest = await _client.ListEventsAsync(1, null).ConfigureAwait(true);
        if (newest is { Count: > 0 })
        {
            _cursor.ObserveNewest(newest[0].Id);
        }
    }
}
