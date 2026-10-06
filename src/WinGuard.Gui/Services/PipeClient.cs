using System.IO;
using System.IO.Pipes;
using System.Security.Principal;
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

    // How long one attempt waits for a free instance of the service's pipe.
    private const int ConnectTimeoutMs = 2000;

    // Requests that make the service do real work (run auditpol, rewrite firewall rules, reload
    // lists) can legitimately take longer than a status read.
    private static readonly TimeSpan LongRequestTimeout = TimeSpan.FromSeconds(30);

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

    // Backoff state: sessions that die within seconds (e.g. the service rejecting our
    // identity) escalate the reconnect delay exponentially instead of hammering.
    private int _rapidFailures;
    private DateTime _connectedAtUtc;

    /// <summary>Raised whenever the connection state changes (true = connected).</summary>
    public event Action<bool>? StateChanged;

    /// <summary>
    /// True once the service has answered a request on the current connection — an open pipe alone
    /// does not count, because the service may still refuse the caller.
    /// </summary>
    public bool IsConnected => _isConnected;

    /// <summary>
    /// Why the service cannot be used although it is there (it refused this caller, or Windows
    /// denied access to its pipe). Null when there is no such problem — including when the service
    /// is simply not running.
    /// </summary>
    public string? LastProblem { get; private set; }

    /// <summary>Raised when <see cref="LastProblem"/> changes.</summary>
    public event Action<string?>? ProblemChanged;

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
    public async Task<IpcResponse> SendAsync(string method, object? parameters, CancellationToken ct = default, TimeSpan? requestTimeout = null)
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
            timeout.CancelAfter(requestTimeout ?? RequestTimeout);

            IpcResponse response;
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

                response = JsonSerializer.Deserialize<IpcResponse>(line, IpcJson.Options)
                    ?? throw new IOException("Malformed response from the WinGuard service.");

                // One request, one response, in order: anything else means the stream is out of step.
                if (response.Id != request.Id)
                {
                    throw new IOException("Out-of-sequence response from the WinGuard service.");
                }
            }
            catch (Exception)
            {
                SetConnected(false);
                throw;
            }

            // A service-reported error is a healthy round trip: surface it without dropping
            // the connection (which would flicker the UI and escalate the reconnect backoff).
            if (!response.Ok)
            {
                throw new InvalidOperationException(response.Error ?? "The WinGuard service reported an error.");
            }

            return response;
        }
        finally
        {
            _requestLock.Release();
        }
    }

    /// <summary>
    /// Tries to connect right now instead of waiting for the retry loop (for example just after the
    /// user started the service). Returns whether the service is connected afterwards.
    /// </summary>
    public async Task<bool> TryReconnectNowAsync(CancellationToken ct = default)
    {
        if (IsConnected)
        {
            return true;
        }

        lock (_stateLock)
        {
            _rapidFailures = 0;
        }

        try
        {
            return await TryConnectAsync(ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException)
        {
            return false;
        }
    }

    /// <summary>Gets the current service status, or null when the service is unavailable.</summary>
    public Task<ServiceStatusDto?> GetStatusAsync(CancellationToken ct = default) =>
        GetAsync<ServiceStatusDto>(IpcMethods.GetStatus, null, ct);

    /// <summary>Lists active bans, or null when the request failed (so "no bans" and "no answer" differ).</summary>
    public Task<List<BanDto>?> ListBansAsync(CancellationToken ct = default) =>
        GetAsync<List<BanDto>>(IpcMethods.ListBans, null, ct);

    /// <summary>
    /// Lists events newest-first: the latest <paramref name="limit"/> when <paramref name="afterId"/>
    /// is null, otherwise only those with a larger id. Null when the request failed.
    /// </summary>
    public Task<List<EventDto>?> ListEventsAsync(int limit, DateTime? sinceUtc, long? afterId = null, CancellationToken ct = default) =>
        GetAsync<List<EventDto>>(
            IpcMethods.ListEvents,
            new ListEventsParams { Limit = limit, SinceUtc = sinceUtc, AfterId = afterId },
            ct);

    /// <summary>Lists whitelist and blacklist entries, or null when the request failed.</summary>
    public Task<List<ListEntryDto>?> ListListsAsync(CancellationToken ct = default) =>
        GetAsync<List<ListEntryDto>>(IpcMethods.ListLists, null, ct);

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

    /// <summary>
    /// Pushes new settings to the service (hot-reload) and returns them as the service stored them
    /// (after its own normalization). Throws when the service rejects them.
    /// </summary>
    public async Task<WinGuardSettings?> UpdateSettingsAsync(WinGuardSettings settings, CancellationToken ct = default)
    {
        var response = await SendAsync(IpcMethods.UpdateSettings, new UpdateSettingsParams { Settings = settings }, ct, LongRequestTimeout)
            .ConfigureAwait(false);
        return response.Result is { } result ? JsonSerializer.Deserialize<WinGuardSettings>(result, IpcJson.Options) : null;
    }

    /// <summary>Checks detection prerequisites, or null when the service is unavailable.</summary>
    public Task<PrereqsDto?> CheckPrereqsAsync(CancellationToken ct = default) =>
        GetAsync<PrereqsDto>(IpcMethods.CheckPrereqs, null, ct, LongRequestTimeout);

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

    private async Task<T?> GetAsync<T>(string method, object? parameters, CancellationToken ct, TimeSpan? requestTimeout = null)
    {
        try
        {
            var response = await SendAsync(method, parameters, ct, requestTimeout).ConfigureAwait(false);
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
        await SendAsync(method, parameters, ct, LongRequestTimeout).ConfigureAwait(false);
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

            // Identification: the service may look at who we are (it only accepts administrators)
            // but cannot act as us. Asking for a level also fixes our identity at connect time,
            // which is what lets the service identify us before we have sent anything.
            var pipe = new NamedPipeClientStream(
                ".",
                PipeConstants.PipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous,
                TokenImpersonationLevel.Identification);

            try
            {
                await pipe.ConnectAsync(ConnectTimeoutMs, ct).ConfigureAwait(false);
            }
            catch (UnauthorizedAccessException)
            {
                pipe.Dispose();
                SetProblem("Windows denied access to the WinGuard service. This console must be run as an administrator.");
                NoteFailedAttempt();
                return false;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                pipe.Dispose();
                throw;
            }
            catch (Exception ex)
            {
                pipe.Dispose();
                if (!ServicePipeExists())
                {
                    // No pipe: the service is not running. That is not a "problem" to explain, and
                    // there is nothing to back off from — notice quickly when it comes up.
                    SetProblem(null);
                    lock (_stateLock)
                    {
                        _rapidFailures = 0;
                    }

                    return false;
                }

                // The service's pipe is there but could not be opened in time: say so instead of
                // claiming the service is not running.
                SetProblem(ex is TimeoutException
                    ? "The WinGuard service is running but is not accepting connections (its pipe is busy). Restart the WinGuard service; if this keeps happening, check the service log."
                    : "Could not connect to the WinGuard service: " + ex.Message);
                NoteFailedAttempt();
                return false;
            }

            var reader = new StreamReader(pipe, new UTF8Encoding(false));
            var writer = new StreamWriter(pipe, new UTF8Encoding(false))
            {
                AutoFlush = true,
                NewLine = "\n",
            };

            // Handshake: the connection only counts once the service has answered. A service that
            // refuses this caller answers with a reason and closes the pipe; reporting "connected"
            // before knowing that would make the window flicker and start loads that cannot work.
            var problem = await HandshakeAsync(reader, writer, ct).ConfigureAwait(false);
            if (problem is not null)
            {
                reader.Dispose();
                writer.Dispose();
                pipe.Dispose();
                SetProblem(problem);
                NoteFailedAttempt();
                return false;
            }

            lock (_stateLock)
            {
                _pipe = pipe;
                _reader = reader;
                _writer = writer;
            }

            SetProblem(null);
            SetConnected(true);
            return true;
        }
        finally
        {
            _connectLock.Release();
        }
    }

    /// <summary>
    /// Sends one status request on a freshly opened pipe. Returns null when the service answered
    /// it, otherwise the reason the service cannot be used.
    /// </summary>
    private async Task<string?> HandshakeAsync(StreamReader reader, StreamWriter writer, CancellationToken ct)
    {
        var probe = new IpcRequest { Id = Interlocked.Increment(ref _nextId), Method = IpcMethods.GetStatus };
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(RequestTimeout);

        string? line;
        try
        {
            await writer.WriteLineAsync(JsonSerializer.Serialize(probe, IpcJson.Options).AsMemory(), timeout.Token).ConfigureAwait(false);
            line = await reader.ReadLineAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException)
        {
            return "The WinGuard service is running but did not answer this console.";
        }

        if (line is null)
        {
            return "The WinGuard service closed the connection without answering.";
        }

        IpcResponse? response;
        try
        {
            response = JsonSerializer.Deserialize<IpcResponse>(line, IpcJson.Options);
        }
        catch (JsonException)
        {
            response = null;
        }

        if (response is null)
        {
            return "The WinGuard service sent an answer this console does not understand. Reinstall so both are the same version.";
        }

        // A refusal is not an answer to our request (it carries id 0): it is the service telling
        // every unauthorized caller why it is about to hang up.
        if (!response.Ok && response.Id != probe.Id)
        {
            return response.Error ?? "The WinGuard service refused this console.";
        }

        return null;
    }

    /// <summary>
    /// Whether the service's pipe exists at all. The pipe directory is listed rather than probing
    /// the name, because probing a pipe name opens (and uses up) one of its instances.
    /// </summary>
    private static bool ServicePipeExists()
    {
        try
        {
            foreach (var path in Directory.EnumerateFiles(@"\\.\pipe\"))
            {
                if (string.Equals(Path.GetFileName(path), PipeConstants.PipeName, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }
        catch (Exception)
        {
            // Cannot tell: treat as absent.
        }

        return false;
    }

    private void SetProblem(string? problem)
    {
        if (string.Equals(LastProblem, problem, StringComparison.Ordinal))
        {
            return;
        }

        LastProblem = problem;
        ProblemChanged?.Invoke(problem);
    }

    /// <summary>A connection that was opened but could not be used also slows the retry loop down.</summary>
    private void NoteFailedAttempt()
    {
        lock (_stateLock)
        {
            _rapidFailures = Math.Min(_rapidFailures + 1, 5);
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
                // 2 s baseline, doubling per consecutive rapid failure up to 64 s.
                var failures = Volatile.Read(ref _rapidFailures);
                var delay = TimeSpan.FromSeconds(2 * Math.Pow(2, failures));
                await Task.Delay(delay, ct).ConfigureAwait(false);
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

            if (connected)
            {
                _connectedAtUtc = DateTime.UtcNow;
            }
            else
            {
                if (changed)
                {
                    // A session that died within seconds counts as a rapid failure and
                    // escalates the reconnect backoff; a healthy session resets it.
                    _rapidFailures = (DateTime.UtcNow - _connectedAtUtc) < TimeSpan.FromSeconds(5)
                        ? Math.Min(_rapidFailures + 1, 5)
                        : 0;
                }

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