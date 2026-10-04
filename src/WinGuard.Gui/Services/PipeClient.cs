using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using WinGuard.Core.Config;
using WinGuard.Core.Ipc;
using WinGuard.Core.Model;

namespace WinGuard.Gui.Services;

/// <summary>
/// GUI side of the WinGuard named-pipe JSON-line protocol (PLAN.md §8, CONTRACTS.md Agent D).
/// One request is written as a single UTF-8 line and exactly one response line is read back.
/// A background loop reconnects every two seconds while the service is down; callers observe
/// <see cref="IsConnected"/> / <see cref="StateChanged"/>. All public typed helpers never throw
/// for connectivity problems — they return null/empty so the UI can render "service not running".
/// </summary>
public sealed class PipeClient : IDisposable
{
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(5);

    private readonly SemaphoreSlim _requestLock = new(1, 1);
    private readonly SemaphoreSlim _connectLock = new(1, 1);
    private readonly object _stateLock = new();

    private NamedPipeClientStream? _pipe;
    private StreamReader? _reader;
    private StreamWriter? _writer;
    private CancellationTokenSource? _cts;
    private long _nextId;
    private volatile bool _isConnected;
    private bool _disposed;

    /// <summary>Raised whenever the connection state changes (true = connected).</summary>
    public event Action<bool>? StateChanged;

    /// <summary>True while a pipe connection is established.</summary>
    public bool IsConnected => _isConnected;

    /// <summary>Starts the background connect/retry loop.</summary>
    public void Start()
    {
        if (_cts is not null)
        {
            return;
        }

        _cts = new CancellationTokenSource();
        var token = _cts.Token;
        _ = Task.Run(() => ConnectLoopAsync(token), CancellationToken.None);
    }

    /// <summary>
    /// Sends one request and awaits its response. Throws <see cref="InvalidOperationException"/> when
    /// the service replies with an error, and <see cref="IOException"/> when the service is unreachable.
    /// </summary>
    public async Task<IpcResponse> SendAsync(string method, object? parameters, CancellationToken ct = default)
    {
        await _requestLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await EnsureConnectedAsync(ct).ConfigureAwait(false);

            var request = new IpcRequest
            {
                Id = Interlocked.Increment(ref _nextId),
                Method = method,
                Params = parameters is null ? null : JsonSerializer.SerializeToElement(parameters, IpcJson.Options),
            };
            var payload = JsonSerializer.Serialize(request, IpcJson.Options);

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(RequestTimeout);

            try
            {
                var writer = _writer ?? throw new IOException("Pipe writer unavailable.");
                var reader = _reader ?? throw new IOException("Pipe reader unavailable.");

                await writer.WriteLineAsync(payload.AsMemory(), timeout.Token).ConfigureAwait(false);
                var line = await reader.ReadLineAsync(timeout.Token).ConfigureAwait(false);
                if (line is null)
                {
                    throw new IOException("The WinGuard service closed the connection.");
                }

                var response = JsonSerializer.Deserialize<IpcResponse>(line, IpcJson.Options)
                    ?? throw new IOException("Malformed response from the WinGuard service.");
                if (!response.Ok)
                {
                    throw new InvalidOperationException(response.Error ?? "The WinGuard service reported an error.");
                }

                return response;
            }
            catch (Exception)
            {
                SetConnected(false);
                throw;
            }
        }
        finally
        {
            _requestLock.Release();
        }
    }

    /// <summary>Gets the current service status, or null when the service is unavailable.</summary>
    public Task<ServiceStatusDto?> GetStatusAsync(CancellationToken ct = default) =>
        GetAsync<ServiceStatusDto>(IpcMethods.GetStatus, null, ct);

    /// <summary>Lists active bans, or an empty list when the service is unavailable.</summary>
    public async Task<List<BanDto>> ListBansAsync(CancellationToken ct = default) =>
        await GetAsync<List<BanDto>>(IpcMethods.ListBans, null, ct).ConfigureAwait(false) ?? [];

    /// <summary>Lists events newest-first (optionally only those newer than <paramref name="sinceUtc"/>).</summary>
    public async Task<List<EventDto>> ListEventsAsync(int limit, DateTime? sinceUtc, CancellationToken ct = default) =>
        await GetAsync<List<EventDto>>(
            IpcMethods.ListEvents,
            new ListEventsParams { Limit = limit, SinceUtc = sinceUtc },
            ct).ConfigureAwait(false) ?? [];

    /// <summary>Lists whitelist and blacklist entries.</summary>
    public async Task<List<ListEntryDto>> ListListsAsync(CancellationToken ct = default) =>
        await GetAsync<List<ListEntryDto>>(IpcMethods.ListLists, null, ct).ConfigureAwait(false) ?? [];

    /// <summary>Removes a ban, optionally adding the IP to the whitelist.</summary>
    public Task UnblockAsync(string ip, bool alsoWhitelist, CancellationToken ct = default) =>
        PostAsync(IpcMethods.Unblock, new UnblockParams { Ip = ip, AlsoWhitelist = alsoWhitelist }, ct);

    /// <summary>Manually blocks an IP for a duration or permanently.</summary>
    public Task BlockNowAsync(string ip, TimeSpan? duration, bool permanent, string? note, CancellationToken ct = default) =>
        PostAsync(IpcMethods.BlockNow, new BlockNowParams { Ip = ip, Duration = duration, Permanent = permanent, Note = note }, ct);

    /// <summary>Adds an entry to the whitelist or the blacklist.</summary>
    public Task AddToListAsync(bool whitelist, string value, CancellationToken ct = default) =>
        PostAsync(
            whitelist ? IpcMethods.WhitelistAdd : IpcMethods.BlacklistAdd,
            new ListValueParams { Value = value },
            ct);

    /// <summary>Removes one entry from the given list.</summary>
    public Task RemoveListEntryAsync(ListKind kind, string value, CancellationToken ct = default) =>
        PostAsync(IpcMethods.ListRemove, new ListRemoveParams { Kind = kind, Value = value }, ct);

    /// <summary>Fetches the live settings, or null when the service is unavailable.</summary>
    public Task<WinGuardSettings?> GetSettingsAsync(CancellationToken ct = default) =>
        GetAsync<WinGuardSettings>(IpcMethods.GetSettings, null, ct);

    /// <summary>Pushes new settings to the service (hot-reload).</summary>
    public Task UpdateSettingsAsync(WinGuardSettings settings, CancellationToken ct = default) =>
        PostAsync(IpcMethods.UpdateSettings, new UpdateSettingsParams { Settings = settings }, ct);

    /// <summary>Checks detection prerequisites, or null when the service is unavailable.</summary>
    public Task<PrereqsDto?> CheckPrereqsAsync(CancellationToken ct = default) =>
        GetAsync<PrereqsDto>(IpcMethods.CheckPrereqs, null, ct);

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        try
        {
            _cts?.Cancel();
        }
        catch
        {
            // Ignore.
        }

        SetConnected(false);
        _cts?.Dispose();
        _cts = null;
        _requestLock.Dispose();
        _connectLock.Dispose();
    }

    private async Task<T?> GetAsync<T>(string method, object? parameters, CancellationToken ct)
    {
        try
        {
            var response = await SendAsync(method, parameters, ct).ConfigureAwait(false);
            return response.Result is { } result
                ? JsonSerializer.Deserialize<T>(result, IpcJson.Options)
                : default;
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or OperationCanceledException or TimeoutException)
        {
            return default;
        }
    }

    private async Task PostAsync(string method, object? parameters, CancellationToken ct)
    {
        await SendAsync(method, parameters, ct).ConfigureAwait(false);
    }

    private async Task EnsureConnectedAsync(CancellationToken ct)
    {
        if (IsConnected)
        {
            return;
        }

        if (!await TryConnectAsync(ct).ConfigureAwait(false))
        {
            throw new IOException("The WinGuard service is not running.");
        }
    }

    private async Task<bool> TryConnectAsync(CancellationToken ct)
    {
        await _connectLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (IsConnected)
            {
                return true;
            }

            var pipe = new NamedPipeClientStream(
                ".",
                PipeConstants.PipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous);

            try
            {
                await pipe.ConnectAsync(500, ct).ConfigureAwait(false);
            }
            catch (Exception)
            {
                pipe.Dispose();
                return false;
            }

            var reader = new StreamReader(pipe, new UTF8Encoding(false));
            var writer = new StreamWriter(pipe, new UTF8Encoding(false))
            {
                AutoFlush = true,
                NewLine = "\n",
            };

            lock (_stateLock)
            {
                _pipe = pipe;
                _reader = reader;
                _writer = writer;
            }

            SetConnected(true);
            return true;
        }
        finally
        {
            _connectLock.Release();
        }
    }

    private async Task ConnectLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (!IsConnected)
                {
                    await TryConnectAsync(ct).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                // Retry on the next tick.
            }

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(2), ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    private void SetConnected(bool connected)
    {
        bool changed;
        lock (_stateLock)
        {
            changed = _isConnected != connected;
            _isConnected = connected;

            if (!connected)
            {
                DisposePipeLocked();
            }
        }

        if (changed)
        {
            StateChanged?.Invoke(connected);
        }
    }

    private void DisposePipeLocked()
    {
        try
        {
            _reader?.Dispose();
        }
        catch
        {
            // Ignore.
        }

        try
        {
            _writer?.Dispose();
        }
        catch
        {
            // Ignore.
        }

        try
        {
            _pipe?.Dispose();
        }
        catch
        {
            // Ignore.
        }

        _reader = null;
        _writer = null;
        _pipe = null;
    }
}