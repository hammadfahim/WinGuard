using System.Windows.Threading;
using WinGuard.Core.Ipc;

namespace WinGuard.Gui.Services;

/// <summary>
/// Drives the ~2 s GUI refresh (PLAN.md §9): status every tick, new events since the last seen
/// timestamp every tick, and bans whenever the Blocked IPs view is active or every fourth tick.
/// The <see cref="DispatcherTimer"/> fires on the UI thread, so event handlers may touch the
/// view-model collections directly. Calls are skipped while disconnected; the <see cref="PipeClient"/>
/// background loop reconnects on its own.
/// </summary>
public sealed class StatusPoller : IDisposable
{
    private const int EventBatchLimit = 200;

    private readonly PipeClient _client;
    private readonly DispatcherTimer _timer;

    private long? _lastEventId;
    private int _tick;
    private bool _busy;

    /// <summary>Set by the shell when the Blocked IPs view is on screen (forces a ban refresh each tick).</summary>
    public bool BansViewActive { get; set; }

    /// <summary>When true (window hidden/minimized) ticks do nothing, saving IPC and CPU.</summary>
    public bool Paused { get; set; }

    /// <summary>Raised when a fresh service status snapshot arrives.</summary>
    public event Action<ServiceStatusDto>? StatusUpdated;

    /// <summary>Raised when new events arrive (newest-first).</summary>
    public event Action<IReadOnlyList<EventDto>>? EventsReceived;

    /// <summary>Raised when the ban list is refreshed.</summary>
    public event Action<IReadOnlyList<BanDto>>? BansReceived;

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

    /// <summary>Forgets the last-seen event timestamp (call after a reconnect).</summary>
    public void ResetEventCursor() => _lastEventId = null;

    /// <inheritdoc />
    public void Dispose()
    {
        _timer.Tick -= OnTick;
        _timer.Stop();
    }

    private async void OnTick(object? sender, EventArgs e)
    {
        if (_busy || Paused)
        {
            return;
        }

        _busy = true;
        try
        {
            if (!_client.IsConnected)
            {
                return;
            }

            var status = await _client.GetStatusAsync().ConfigureAwait(true);
            if (status is not null)
            {
                StatusUpdated?.Invoke(status);
            }

            var events = await _client.ListEventsAsync(EventBatchLimit, null, _lastEventId).ConfigureAwait(true);
            if (events.Count > 0)
            {
                _lastEventId = events.Max(dto => dto.Id);
                EventsReceived?.Invoke(events);
            }

            _tick++;
            if (BansViewActive || _tick % 4 == 0)
            {
                var bans = await _client.ListBansAsync().ConfigureAwait(true);
                BansReceived?.Invoke(bans);
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
}