using System.IO;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using WinGuard.Core.Config;
using WinGuard.Core.Model;

namespace WinGuard.Core.Ipc;

/// <summary>
/// Console side of the WinGuard named-pipe JSON-line protocol (PLAN.md §8, CONTRACTS.md Agent D).
/// It lives in the shared library (not in the GUI project) so the end-to-end tests can run this
/// exact client against the service's real pipe server.
/// One request is written as a single UTF-8 line and exactly one response line is read back.
/// A background loop reconnects every two seconds while the service is down; callers observe
/// <see cref="IsConnected"/> / <see cref="StateChanged"/>. All public typed helpers never throw
/// for connectivity problems — they return null/empty so the UI can render "service not running".
/// <para>
/// Nothing is sent until <see cref="PipeServerIdentity"/> has confirmed who owns the pipe: its name
/// is free for any local user to take while the service is down.
/// </para>
/// </summary>
public sealed class PipeClient : IDisposable
{
    /// <summary>What to tell the user when there is no service to talk to.</summary>
    public const string ServiceNotRunningMessage = "The WinGuard service is not running.";

    private const string UnreadableAnswerMessage =
        "The WinGuard service sent an answer this console does not understand. Reinstall so both are the same version.";

    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(5);

    // How long one attempt waits for a free instance of the service's pipe.
    private const int ConnectTimeoutMs = 2000;

    // Requests that make the service do real work (run auditpol, rewrite firewall rules, reload
    // lists) can legitimately take longer than a status read.
    private static readonly TimeSpan LongRequestTimeout = TimeSpan.FromSeconds(30);

    private readonly SemaphoreSlim _requestLock = new(1, 1);
    private readonly SemaphoreSlim _connectLock = new(1, 1);
    private readonly object _stateLock = new();

    private readonly string _pipeName;
    private readonly Func<NamedPipeClientStream, PipeServerIdentity.Result> _verifyServer;

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

    /// <summary>Creates the client.</summary>
    /// <param name="pipeName">Pipe to connect to; the service's pipe when omitted (tests pass their own).</param>
    public PipeClient(string? pipeName = null)
        : this(pipeName, PipeServerIdentity.Verify)
    {
    }

    /// <summary>
    /// For the end-to-end tests only (internal, and only the test assembly sees this library's
    /// internals): tests serve on their own pipe from a process that need not be elevated, so they
    /// stand in for the server check. The console and the CLI always use the public constructor.
    /// </summary>
    internal PipeClient(string? pipeName, Func<NamedPipeClientStream, PipeServerIdentity.Result> verifyServer)
    {
        _pipeName = string.IsNullOrWhiteSpace(pipeName) ? PipeConstants.PipeName : pipeName;
        _verifyServer = verifyServer ?? throw new ArgumentNullException(nameof(verifyServer));
    }

    /// <summary>Raised whenever the connection state changes (true = connected).</summary>
    public event Action<bool>? StateChanged;

    /// <summary>
    /// True once the service has answered a request on the current connection — an open pipe alone
    /// does not count, because the service may still refuse the caller.
    /// </summary>
    public bool IsConnected => _isConnected;

    /// <summary>
    /// Why the service cannot be used although something is there (it refused this caller, Windows
    /// denied access to its pipe, or the pipe belongs to a process that is not the service). Null
    /// when there is no such problem — including when the service is simply not running.
    /// </summary>
    public string? LastProblem { get; private set; }

    /// <summary>Raised when <see cref="LastProblem"/> changes.</summary>
    public event Action<string?>? ProblemChanged;

    /// <summary>
    /// Why the last typed read returned null (the service reported an error, sent something
    /// unreadable, or could not be reached), so that a null can be explained. Null after a success.
    /// </summary>
    public string? LastRequestError { get; private set; }

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

                response = ParseResponse(line)
                    ?? throw new IOException(UnreadableAnswerMessage);

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

    /// <summary>
    /// Manually blocks an IP for a duration or permanently. Returns the ban the service recorded,
    /// which is the real outcome: without a duration the service picks it, and it caps what it is
    /// given. Null when the service did not say (a release before protocol v4).
    /// </summary>
    public async Task<BanDto?> BlockNowAsync(string ip, TimeSpan? duration, bool permanent, string? note, CancellationToken ct = default)
    {
        var response = await SendAsync(
                IpcMethods.BlockNow,
                new BlockNowParams { Ip = ip, Duration = duration, Permanent = permanent, Note = note },
                ct,
                LongRequestTimeout)
            .ConfigureAwait(false);
        return response.Result is { } result ? JsonSerializer.Deserialize<BanDto>(result, IpcJson.Options) : null;
    }

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

    /// <summary>Statistics for the GUI view (daily counters, top offenders), or null when unavailable.</summary>
    public Task<StatisticsDto?> GetStatisticsAsync(int days = 30, CancellationToken ct = default) =>
        GetAsync<StatisticsDto>(IpcMethods.GetStatistics, new GetStatisticsParams { Days = days }, ct);

    /// <summary>Ban-history rows newest-first, or null when the service is unavailable.</summary>
    public Task<List<BanHistoryDto>?> ListBanHistoryAsync(int limit = 100, CancellationToken ct = default) =>
        GetAsync<List<BanHistoryDto>>(IpcMethods.ListBanHistory, new ListBanHistoryParams { Limit = limit }, ct);

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
            var value = response.Result is { } result
                ? JsonSerializer.Deserialize<T>(result, IpcJson.Options)
                : default;
            LastRequestError = null;
            return value;
        }
        catch (JsonException)
        {
            // A well-formed line whose result has another shape: a service from another release.
            LastRequestError = UnreadableAnswerMessage;
            return default;
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or OperationCanceledException or TimeoutException)
        {
            LastRequestError = ex is OperationCanceledException or TimeoutException
                ? "The WinGuard service did not answer in time."
                : ex.Message;
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
            throw new IOException(LastProblem ?? ServiceNotRunningMessage);
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
                _pipeName,
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

            // Before a single byte goes out: a process squatting on the name must learn nothing,
            // and must not be able to pose as the service.
            var server = _verifyServer(pipe);
            if (!server.Trusted)
            {
                CloseQuietly(null, null, pipe);
                SetProblem(server.Problem ?? "This console could not verify that the WinGuard pipe belongs to the service.");
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
            string? problem;
            try
            {
                problem = await HandshakeAsync(reader, writer, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                CloseQuietly(reader, writer, pipe);
                throw;
            }
            catch (Exception ex)
            {
                problem = "Could not talk to the WinGuard service: " + ex.Message;
            }

            if (problem is not null)
            {
                // The reason must reach the screen whatever happens while closing: closing a pipe
                // the service has already hung up on throws, and that used to swallow the reason.
                CloseQuietly(reader, writer, pipe);
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
        catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException or InvalidOperationException)
        {
            return "The WinGuard service is running but did not answer this console.";
        }

        if (line is null)
        {
            return "The WinGuard service closed the connection without answering.";
        }

        var response = ParseResponse(line);
        if (response is null)
        {
            return UnreadableAnswerMessage;
        }

        if (response.Id == probe.Id)
        {
            return null;
        }

        // A refusal is not an answer to our request (it carries id 0): it is the service telling
        // every unauthorized caller why it is about to hang up. Any other stray id would leave the
        // stream out of step for every request that follows.
        return response.Ok ? UnreadableAnswerMessage : response.Error ?? "The WinGuard service refused this console.";
    }

    /// <summary>Parses one response line; null when it is not one.</summary>
    private static IpcResponse? ParseResponse(string line)
    {
        try
        {
            return JsonSerializer.Deserialize<IpcResponse>(line, IpcJson.Options);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Whether the service's pipe exists at all. The pipe directory is listed rather than probing
    /// the name, because probing a pipe name opens (and uses up) one of its instances.
    /// </summary>
    private bool ServicePipeExists()
    {
        try
        {
            foreach (var path in Directory.EnumerateFiles(@"\\.\pipe\"))
            {
                if (string.Equals(Path.GetFileName(path), _pipeName, StringComparison.OrdinalIgnoreCase))
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

    /// <summary>Closes a connection that is being given up; never throws.</summary>
    private static void CloseQuietly(StreamReader? reader, StreamWriter? writer, NamedPipeClientStream? pipe)
    {
        // The writer first: disposing it flushes, which fails once the stream is closed or broken.
        try
        {
            writer?.Dispose();
        }
        catch (Exception)
        {
            // Already closed or broken.
        }

        try
        {
            reader?.Dispose();
        }
        catch (Exception)
        {
            // Already closed.
        }

        try
        {
            pipe?.Dispose();
        }
        catch (Exception)
        {
            // Already closed.
        }
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
        CloseQuietly(_reader, _writer, _pipe);

        _reader = null;
        _writer = null;
        _pipe = null;
    }
}