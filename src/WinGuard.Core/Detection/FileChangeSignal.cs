namespace WinGuard.Core.Detection;

/// <summary>
/// Wakes a poll loop early when a watched log file changes, so detection latency drops from "up to
/// one poll interval" to a fraction of a second. Polling stays as the fallback (network shares and
/// locked-down hosts may not raise change events), so correctness never depends on the watcher.
/// </summary>
internal sealed class FileChangeSignal : IDisposable
{
    private static readonly TimeSpan Debounce = TimeSpan.FromMilliseconds(200);

    private readonly object _lock = new();
    private readonly Dictionary<string, FileSystemWatcher> _watchers = new(StringComparer.OrdinalIgnoreCase);
    private TaskCompletionSource? _waiter;
    private bool _pending;
    private bool _disposed;

    /// <summary>Ensures a watcher exists for the folder of every file and drops watchers no longer needed.</summary>
    public void Watch(IEnumerable<string> files)
    {
        var wanted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in files)
        {
            var dir = Path.GetDirectoryName(file);
            if (!string.IsNullOrEmpty(dir))
            {
                wanted.Add(dir);
            }
        }

        lock (_lock)
        {
            if (_disposed)
            {
                return;
            }

            foreach (var stale in _watchers.Keys.Where(k => !wanted.Contains(k)).ToList())
            {
                _watchers[stale].Dispose();
                _watchers.Remove(stale);
            }

            foreach (var dir in wanted)
            {
                if (_watchers.ContainsKey(dir) || !Directory.Exists(dir))
                {
                    continue;
                }

                try
                {
                    var watcher = new FileSystemWatcher(dir)
                    {
                        NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.FileName | NotifyFilters.CreationTime,
                        IncludeSubdirectories = false,
                        EnableRaisingEvents = true,
                    };
                    watcher.Changed += (_, _) => Signal();
                    watcher.Created += (_, _) => Signal();
                    watcher.Renamed += (_, _) => Signal();
                    watcher.Error += (_, _) => Signal();
                    _watchers[dir] = watcher;
                }
                catch (Exception)
                {
                    // Polling still covers this folder.
                }
            }
        }
    }

    /// <summary>Completes after <paramref name="interval"/> or shortly after a watched file changes, whichever is first.</summary>
    public async Task WaitAsync(TimeSpan interval, TimeProvider timeProvider, CancellationToken ct)
    {
        TaskCompletionSource? waiter;
        lock (_lock)
        {
            if (_pending)
            {
                _pending = false;
                waiter = null;
            }
            else
            {
                waiter = _waiter = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            }
        }

        if (waiter is null)
        {
            await Task.Delay(Debounce, ct).ConfigureAwait(false);
            return;
        }

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var delay = Task.Delay(interval, timeProvider, cts.Token);
        var finished = await Task.WhenAny(delay, waiter.Task).ConfigureAwait(false);
        cts.Cancel();
        lock (_lock)
        {
            _waiter = null;
        }

        if (finished == waiter.Task)
        {
            // Let the writer finish its burst of appends before we read.
            await Task.Delay(Debounce, ct).ConfigureAwait(false);
            return;
        }

        await delay.ConfigureAwait(false); // propagates caller cancellation
    }

    private void Signal()
    {
        lock (_lock)
        {
            if (_waiter is not null)
            {
                _waiter.TrySetResult();
            }
            else
            {
                _pending = true;
            }
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        lock (_lock)
        {
            _disposed = true;
            foreach (var watcher in _watchers.Values)
            {
                watcher.Dispose();
            }

            _watchers.Clear();
        }
    }
}
