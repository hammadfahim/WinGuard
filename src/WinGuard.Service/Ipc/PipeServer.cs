using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32.SafeHandles;
using WinGuard.Core.Ipc;

namespace WinGuard.Service.Ipc;

/// <summary>
/// Named-pipe JSON-lines server for the service↔GUI protocol (PLAN.md §8). It owns the transport
/// and the access control; the requests themselves are executed by <see cref="IpcRequestHandler"/>.
/// It accepts concurrent clients and processes each client's lines sequentially.
/// <para>
/// <b>Access control:</b> the pipe is created with an explicit DACL — SYSTEM and Administrators
/// only — plus <c>PIPE_REJECT_REMOTE_CLIENTS</c> and first-instance anti-squatting, via P/Invoke
/// (<c>PipeSecurity</c> lives in the System.IO.Pipes.AccessControl package, which is intentionally
/// not referenced). No other account can open the pipe or create another instance of it. Every
/// connection is additionally authorized by <see cref="PipeClientIdentity"/>, which reads the
/// access token of the client process: only LocalSystem and elevated administrators are accepted;
/// everything else fails closed. This enforces the PLAN.md §8 "Administrators + LocalSystem only"
/// intent (reviews S-M1/S-M2).
/// </para>
/// <para>
/// A caller that cannot be identified straight away is given one more chance after its first
/// request line has been read (impersonation, the fallback, can need that) and BEFORE that request
/// is executed. No request is ever executed for a caller that has not been authorized.
/// </para>
/// </summary>
public sealed partial class PipeServer : BackgroundService
{
    // An unidentified client must send its first request within this time.
    private static readonly TimeSpan FirstRequestTimeout = TimeSpan.FromSeconds(10);

    private readonly IpcRequestHandler _handler;
    private readonly ILogger<PipeServer> _logger;
    private readonly Func<NamedPipeServerStream>? _pipeFactory;
    private readonly Func<NamedPipeServerStream, PipeClientIdentity.Result> _identify;
    private readonly ConcurrentDictionary<int, Task> _clients = new();

    private int _nextClientId;
    private long _rejectedConnections;
    private bool _firstPipeInstanceCreated;

    /// <summary>Creates the pipe server.</summary>
    /// <param name="handler">Executes the requests of authorized clients.</param>
    /// <param name="logger">Diagnostic logger.</param>
    public PipeServer(IpcRequestHandler handler, ILogger<PipeServer> logger)
        : this(handler, logger, pipeFactory: null, identify: null)
    {
    }

    /// <summary>
    /// For the end-to-end tests only (not reachable from the service's composition): lets a test
    /// serve on its own pipe and stand in for the caller check, so the accept loop, the handshake
    /// and every request can be exercised without administrator rights. The service always uses
    /// the public constructor: the secured pipe and <see cref="PipeClientIdentity.Identify"/>.
    /// </summary>
    internal PipeServer(
        IpcRequestHandler handler,
        ILogger<PipeServer> logger,
        Func<NamedPipeServerStream>? pipeFactory,
        Func<NamedPipeServerStream, PipeClientIdentity.Result>? identify)
    {
        _handler = handler ?? throw new ArgumentNullException(nameof(handler));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _pipeFactory = pipeFactory;
        _identify = identify ?? PipeClientIdentity.Identify;
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Load everything the caller check uses now, under the service's own identity.
        PipeClientIdentity.Prewarm();

        _logger.LogInformation("Pipe server listening on \\\\.\\pipe\\{Pipe}.", PipeConstants.PipeName);

        while (!stoppingToken.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                pipe = _pipeFactory is null ? CreateSecuredPipe() : _pipeFactory();

                await pipe.WaitForConnectionAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                pipe?.Dispose();
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Named-pipe accept loop failed; retrying shortly.");
                pipe?.Dispose();
                await SafeDelayAsync(stoppingToken).ConfigureAwait(false);
                continue;
            }

            // Everything about this client — identifying it included — runs on its own task. The
            // accept loop goes straight back to listening, so no single client (and nothing the
            // identity check might wait on) can keep others from connecting.
            var clientId = Interlocked.Increment(ref _nextClientId);
            var accepted = pipe;
            var task = Task.Run(() => HandleClientAsync(accepted, stoppingToken), CancellationToken.None);
            _clients[clientId] = task;
            _ = task.ContinueWith(
                _ =>
                {
                    _clients.TryRemove(KeyValuePair.Create(clientId, task));
                },
                CancellationToken.None,
                TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
        }

        await WaitForClientsAsync().ConfigureAwait(false);
        _logger.LogInformation("Pipe server stopped.");
    }

    // ---- client handling ----

    private enum ClientVerdict
    {
        /// <summary>Identified as LocalSystem or an elevated administrator.</summary>
        Authorized,

        /// <summary>Identified as somebody else.</summary>
        Denied,

        /// <summary>Windows cannot tell yet who the client is (nothing has been read from it).</summary>
        NotYetKnown,
    }

    private ClientVerdict Authorize(NamedPipeServerStream pipe, out string clientName, out string? detail)
    {
        var result = _identify(pipe);
        clientName = result.Client;
        detail = result.Error;
        if (!result.Identified)
        {
            return ClientVerdict.NotYetKnown;
        }

        return result.Authorized ? ClientVerdict.Authorized : ClientVerdict.Denied;
    }

    /// <summary>Tells the client why it is refused and counts the refusal (logging is rate-limited).</summary>
    private void Reject(NamedPipeServerStream pipe, string clientName, string? detail)
    {
        // Rate-limited logging: a local connect loop must not exhaust the disk (review S-N2).
        // The reason is always included: "who" alone does not say why a caller was turned away.
        var rejected = Interlocked.Increment(ref _rejectedConnections);
        if (rejected <= 3 || rejected % 100 == 0)
        {
            _logger.LogWarning(
                "Rejected named-pipe connection from {Client} (total rejected: {Count}). Reason: {Reason}",
                clientName,
                rejected,
                detail ?? "the caller is neither LocalSystem nor an elevated administrator");
        }

        TryWriteRejection(pipe);
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        try
        {
            using (pipe)
            using (var writer = new StreamWriter(pipe, new UTF8Encoding(false), bufferSize: 4096, leaveOpen: false) { AutoFlush = true, NewLine = "\n" })
            {
                var verdict = Authorize(pipe, out var firstName, out var firstDetail);
                if (verdict == ClientVerdict.Denied)
                {
                    Reject(pipe, firstName, firstDetail);
                    return;
                }

                var authorized = verdict == ClientVerdict.Authorized;
                if (authorized)
                {
                    _logger.LogInformation("Console connected (client {Client}).", firstName);
                }

                // Bounded reader: ReadLineAsync has no length cap; a runaway or hostile
                // client could force unbounded (LOH) allocations (review S-N3).
                var reader = new BoundedLineReader(pipe, _logger);
                while (!ct.IsCancellationRequested)
                {
                    string? line;
                    try
                    {
                        if (authorized)
                        {
                            line = await reader.ReadLineAsync(ct).ConfigureAwait(false);
                        }
                        else
                        {
                            using var firstRequest = CancellationTokenSource.CreateLinkedTokenSource(ct);
                            firstRequest.CancelAfter(FirstRequestTimeout);
                            line = await reader.ReadLineAsync(firstRequest.Token).ConfigureAwait(false);
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }

                    if (line is null)
                    {
                        break;
                    }

                    if (!authorized)
                    {
                        // Data has now been read from the client, so Windows can identify it.
                        // The request that was just read is only executed if this succeeds.
                        if (Authorize(pipe, out var clientName, out var detail) != ClientVerdict.Authorized)
                        {
                            Reject(pipe, clientName, detail);
                            break;
                        }

                        authorized = true;
                        _logger.LogInformation("Console connected (client {Client}, identified after its first request).", clientName);
                    }

                    var response = await _handler.HandleLineAsync(line, ct).ConfigureAwait(false);
                    if (response is null)
                    {
                        continue;
                    }

                    try
                    {
                        await writer.WriteLineAsync(response.AsMemory(), ct).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    catch (IOException)
                    {
                        break;
                    }
                }
            }
        }
        catch (IOException)
        {
            // Client disconnected mid-conversation: expected.
        }
        catch (OperationCanceledException)
        {
            // Service is stopping.
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Named-pipe client handler ended with an error.");
        }
    }

    private async Task WaitForClientsAsync()
    {
        try
        {
            await Task.WhenAll(_clients.Values.ToArray()).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "One or more named-pipe client handlers ended with an error.");
        }
    }

    private static async Task SafeDelayAsync(CancellationToken ct)
    {
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(1), ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Ignored; the accept loop will observe cancellation at the top.
        }
    }

    /// <summary>
    /// Best-effort one-line rejection reason so a refused client can show WHY instead of
    /// observing a bare EOF (helps the standard-user-runs-the-GUI case).
    /// </summary>
    private void TryWriteRejection(NamedPipeServerStream pipe)
    {
        try
        {
            var response = IpcResponse.Fail(0, "Access denied: the WinGuard GUI must run with administrator privileges.");
            var json = JsonSerializer.Serialize(response, IpcJson.Options) + "\n";
            var bytes = Encoding.UTF8.GetBytes(json);
            pipe.Write(bytes, 0, bytes.Length);
            pipe.Flush();
        }
        catch (Exception)
        {
            // The client may already be gone; nothing to do.
        }
    }
}
