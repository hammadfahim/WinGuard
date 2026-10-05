using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WinGuard.Core.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Detection;
using WinGuard.Core.Engine;
using WinGuard.Core.Ipc;
using WinGuard.Core.Model;

namespace WinGuard.Service.Ipc;

/// <summary>
/// Named-pipe JSON-lines server implementing the service↔GUI protocol (PLAN.md §8,
/// <c>Core/Ipc/Contracts.cs</c>). It accepts concurrent clients and processes each client's lines
/// sequentially, dispatching every <see cref="IpcMethods"/> method against the shared store, ban
/// engine and settings holder.
/// <para>
/// <b>Access control:</b> the pipe is created with an explicit DACL — SYSTEM and Administrators
/// only — plus <c>PIPE_REJECT_REMOTE_CLIENTS</c> and first-instance anti-squatting, via P/Invoke
/// (<c>PipeSecurity</c> lives in the System.IO.Pipes.AccessControl package, which is intentionally
/// not referenced). No other account can open the pipe or create another instance of it. Every
/// connection is additionally authorized by impersonating the client
/// (<see cref="NamedPipeServerStream.RunAsClient"/>): only LocalSystem and elevated
/// administrators are accepted; everything else fails closed. This enforces the PLAN.md §8
/// "Administrators + LocalSystem only" intent (reviews S-M1/S-M2).
/// </para>
/// </summary>
public sealed partial class PipeServer : BackgroundService
{
    private readonly IStore _store;
    private readonly BanEngine _engine;
    private readonly SettingsHolder _settings;
    private readonly IFirewall _firewall;
    private readonly DetectorRuntimeState _state;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<PipeServer> _logger;
    private readonly ConcurrentDictionary<int, Task> _clients = new();

    private int _nextClientId;
    private DateTime _startedUtc;
    private long _rejectedConnections;
    private bool _firstPipeInstanceCreated;

    /// <summary>Creates the pipe server.</summary>
    /// <param name="store">Persistence (single-writer state).</param>
    /// <param name="engine">Ban engine for manual block/unblock.</param>
    /// <param name="settings">Live settings holder.</param>
    /// <param name="firewall">Firewall abstraction (prerequisite probe).</param>
    /// <param name="state">Shared detector running flags.</param>
    /// <param name="timeProvider">Clock abstraction for "today" calculations.</param>
    /// <param name="logger">Diagnostic logger.</param>
    public PipeServer(
        IStore store,
        BanEngine engine,
        SettingsHolder settings,
        IFirewall firewall,
        DetectorRuntimeState state,
        TimeProvider timeProvider,
        ILogger<PipeServer> logger)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _engine = engine ?? throw new ArgumentNullException(nameof(engine));
        _settings = settings ?? throw new ArgumentNullException(nameof(settings));
        _firewall = firewall ?? throw new ArgumentNullException(nameof(firewall));
        _state = state ?? throw new ArgumentNullException(nameof(state));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _startedUtc = _timeProvider.GetUtcNow().UtcDateTime;
        _logger.LogInformation("Pipe server listening on \\\\.\\pipe\\{Pipe}.", PipeConstants.PipeName);

        while (!stoppingToken.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                pipe = CreateSecuredPipe();

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

            if (!Authorize(pipe, out var clientName))
            {
                // Rate-limited logging: a local connect loop must not exhaust the disk (review S-N2).
                var rejected = Interlocked.Increment(ref _rejectedConnections);
                if (rejected == 1 || rejected % 100 == 0)
                {
                    _logger.LogWarning(
                        "Rejected unauthorized named-pipe connection from {Client} (total rejected: {Count}).",
                        clientName,
                        rejected);
                }

                TryWriteRejection(pipe);
                pipe.Dispose();
                continue;
            }

            var clientId = Interlocked.Increment(ref _nextClientId);
            var task = HandleClientAsync(pipe, stoppingToken);
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

    private bool Authorize(NamedPipeServerStream pipe, out string clientName)
    {
        var authorized = false;
        var name = "unknown";
        try
        {
            pipe.RunAsClient(() =>
            {
                using var identity = WindowsIdentity.GetCurrent(true);
                if (identity is null)
                {
                    // Fail closed: authorized stays false.
                    return;
                }

                name = identity.Name ?? "unknown";
                authorized = IsAuthorized(identity);
            });
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not determine the named-pipe client identity; rejecting the connection.");
        }

        clientName = name;
        return authorized;
    }

    private static bool IsAuthorized(WindowsIdentity identity)
    {
        // PLAN §8: Administrators + LocalSystem ONLY. Service accounts (LocalService /
        // NetworkService) are NOT trusted: any third-party service running under them
        // must not be able to unban attackers or rewrite policy (review S-M1).
        if (identity.User is { } sid && sid.IsWellKnown(WellKnownSidType.LocalSystemSid))
        {
            return true;
        }

        // Only an ELEVATED administrator: IsInRole is true when the Administrators group is
        // enabled in the token. Under UAC a non-elevated process of an admin user carries that
        // group as deny-only and is refused, which is why the GUI's manifest requests elevation.
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        try
        {
            using (pipe)
            using (var writer = new StreamWriter(pipe, new UTF8Encoding(false), bufferSize: 4096, leaveOpen: false) { AutoFlush = true, NewLine = "\n" })
            {
                // Bounded reader: ReadLineAsync has no length cap; a runaway or hostile
                // client could force unbounded (LOH) allocations (review S-N3).
                var reader = new BoundedLineReader(pipe, _logger);
                while (!ct.IsCancellationRequested)
                {
                    string? line;
                    try
                    {
                        line = await reader.ReadLineAsync(ct).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }

                    if (line is null)
                    {
                        break;
                    }

                    if (string.IsNullOrWhiteSpace(line))
                    {
                        continue;
                    }

                    IpcResponse response;
                    long id = 0;
                    try
                    {
                        var request = JsonSerializer.Deserialize<IpcRequest>(line, IpcJson.Options);
                        if (request is null)
                        {
                            continue;
                        }

                        id = request.Id;
                        response = await DispatchAsync(request, ct).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "IPC request failed.");
                        response = IpcResponse.Fail(id, ex.Message);
                    }

                    try
                    {
                        var json = JsonSerializer.Serialize(response, IpcJson.Options);
                        await writer.WriteLineAsync(json.AsMemory(), ct).ConfigureAwait(false);
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

    // ---- dispatch ----

    private async Task<IpcResponse> DispatchAsync(IpcRequest request, CancellationToken ct) => request.Method switch
    {
        IpcMethods.GetStatus => IpcResponse.Success(request.Id, await GetStatusAsync(ct).ConfigureAwait(false)),
        IpcMethods.ListBans => IpcResponse.Success(request.Id, await ListBansAsync(ct).ConfigureAwait(false)),
        IpcMethods.ListEvents => IpcResponse.Success(request.Id, await ListEventsAsync(Params<ListEventsParams>(request), ct).ConfigureAwait(false)),
        IpcMethods.ListLists => IpcResponse.Success(request.Id, await ListListsAsync(ct).ConfigureAwait(false)),
        IpcMethods.Unblock => await UnblockAsync(request, ct).ConfigureAwait(false),
        IpcMethods.BlockNow => await BlockNowAsync(request, ct).ConfigureAwait(false),
        IpcMethods.WhitelistAdd => await WhitelistAddAsync(request, ct).ConfigureAwait(false),
        IpcMethods.BlacklistAdd => await BlacklistAddAsync(request, ct).ConfigureAwait(false),
        IpcMethods.ListRemove => await ListRemoveAsync(request, ct).ConfigureAwait(false),
        IpcMethods.GetSettings => IpcResponse.Success(request.Id, _settings.Current),
        IpcMethods.UpdateSettings => await UpdateSettingsAsync(request, ct).ConfigureAwait(false),
        IpcMethods.CheckPrereqs => IpcResponse.Success(request.Id, await CheckPrereqsAsync(ct).ConfigureAwait(false)),
        _ => IpcResponse.Fail(request.Id, $"Unknown method '{request.Method}'."),
    };

    private async Task<ServiceStatusDto> GetStatusAsync(CancellationToken ct)
    {
        var settings = _settings.Current;
        var bans = await _store.GetActiveBansAsync(ct).ConfigureAwait(false);

        var engines = new List<EngineStatusDto>();
        foreach (var source in KnownSources)
        {
            engines.Add(new EngineStatusDto
            {
                Source = source,
                Name = NameFor(source),
                Enabled = IsEnabled(source, settings),
                Running = _state.IsRunning(source),
                DetectionsToday = _engine.GetDetectionsToday(source),
                ActiveBans = bans.Count(ban => ban.Source == source),
            });
        }

        return new ServiceStatusDto
        {
            ServiceRunning = true,
            Version = Version,
            ProtocolVersion = PipeConstants.ProtocolVersion,
            StartedUtc = _startedUtc,
            ActiveBans = bans.Count,
            Engines = engines,
        };
    }

    private async Task<List<BanDto>> ListBansAsync(CancellationToken ct)
    {
        var bans = await _store.GetActiveBansAsync(ct).ConfigureAwait(false);
        return bans.Select(BanDto.From).ToList();
    }

    private async Task<List<EventDto>> ListEventsAsync(ListEventsParams parameters, CancellationToken ct)
    {
        var limit = Math.Clamp(parameters.Limit <= 0 ? 200 : parameters.Limit, 1, 1000);
        var events = await _store.GetEventsAsync(limit, parameters.SinceUtc, parameters.AfterId, ct).ConfigureAwait(false);
        return events.Select(EventDto.From).ToList();
    }

    private async Task<List<ListEntryDto>> ListListsAsync(CancellationToken ct)
    {
        var whitelist = await _store.GetListAsync(ListKind.Whitelist, ct).ConfigureAwait(false);
        var blacklist = await _store.GetListAsync(ListKind.Blacklist, ct).ConfigureAwait(false);

        var result = new List<ListEntryDto>(whitelist.Count + blacklist.Count);
        result.AddRange(whitelist.Select(value => new ListEntryDto { Kind = ListKind.Whitelist, Value = value }));
        result.AddRange(blacklist.Select(value => new ListEntryDto { Kind = ListKind.Blacklist, Value = value }));
        return result;
    }

    private async Task<IpcResponse> UnblockAsync(IpcRequest request, CancellationToken ct)
    {
        var parameters = Params<UnblockParams>(request);
        if (!IpMatcher.TryNormalize(parameters.Ip, out var ip))
        {
            return IpcResponse.Fail(request.Id, "Invalid IP address.");
        }

        if (parameters.AlsoWhitelist)
        {
            // Whitelist FIRST and reload the engine matcher, so an in-flight attack cannot
            // re-ban the IP in the window before the next housekeeping pass (review S-M7).
            await _store.AddToListAsync(ListKind.Whitelist, ip, ct).ConfigureAwait(false);
            await _store.RemoveFromListAsync(ListKind.Blacklist, ip, ct).ConfigureAwait(false);
            await _engine.ReloadListsAsync(ct).ConfigureAwait(false);
        }

        await _engine.UnbanAsync(ip, ct).ConfigureAwait(false);
        return IpcResponse.Success(request.Id, null);
    }

    private async Task<IpcResponse> BlockNowAsync(IpcRequest request, CancellationToken ct)
    {
        var parameters = Params<BlockNowParams>(request);
        if (!IpMatcher.TryNormalize(parameters.Ip, out var ip))
        {
            return IpcResponse.Fail(request.Id, "Invalid IP address.");
        }

        await _engine.BanNowAsync(ip, parameters.Duration, parameters.Permanent, parameters.Note, ct).ConfigureAwait(false);
        return IpcResponse.Success(request.Id, null);
    }

    private async Task<IpcResponse> WhitelistAddAsync(IpcRequest request, CancellationToken ct)
    {
        var parameters = Params<ListValueParams>(request);
        if (!TryNormalizeListValue(request, parameters.Value, out var value, out var failure))
        {
            return failure!;
        }

        await _store.AddToListAsync(ListKind.Whitelist, value, ct).ConfigureAwait(false);

        // Reload the engine's in-memory matcher so the new entry takes effect immediately.
        await _engine.ReloadListsAsync(ct).ConfigureAwait(false);

        // A whitelisted single host should immediately stop being blocked.
        if (IpMatcher.TryNormalize(value, out var ip))
        {
            await _engine.UnbanAsync(ip, ct).ConfigureAwait(false);
        }
        else
        {
            // CIDR range: unban every active ban that falls inside it.
            var range = new IpMatcher([value], []);
            foreach (var ban in await _store.GetActiveBansAsync(ct).ConfigureAwait(false))
            {
                if (range.IsWhitelisted(ban.IpAddress))
                {
                    await _engine.UnbanAsync(ban.IpAddress, ct).ConfigureAwait(false);
                }
            }
        }

        return IpcResponse.Success(request.Id, null);
    }

    private async Task<IpcResponse> BlacklistAddAsync(IpcRequest request, CancellationToken ct)
    {
        var parameters = Params<ListValueParams>(request);
        if (!TryNormalizeListValue(request, parameters.Value, out var value, out var failure))
        {
            return failure!;
        }

        await _store.AddToListAsync(ListKind.Blacklist, value, ct).ConfigureAwait(false);

        // Reload the engine's in-memory matcher so the new entry takes effect immediately.
        await _engine.ReloadListsAsync(ct).ConfigureAwait(false);

        // A blacklisted single host is blocked right away (RdpGuard-style). CIDR ranges
        // take effect at detection time via PLAN §5 step 3. A whitelisted IP is refused
        // by the engine (whitelist always wins) — expected, not an error.
        if (IpMatcher.TryNormalize(value, out var ip))
        {
            try
            {
                await _engine.BanNowAsync(ip, null, permanent: true, BlacklistNote, ct).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogInformation(ex, "Blacklisted IP {Ip} was not banned immediately.", ip);
            }
        }

        return IpcResponse.Success(request.Id, null);
    }

    private async Task<IpcResponse> ListRemoveAsync(IpcRequest request, CancellationToken ct)
    {
        var parameters = Params<ListRemoveParams>(request);
        if (!TryNormalizeListValue(request, parameters.Value, out var value, out var failure))
        {
            return failure!;
        }

        await _store.RemoveFromListAsync(parameters.Kind, value, ct).ConfigureAwait(false);

        // Reload the engine's in-memory matcher so the removal takes effect immediately.
        await _engine.ReloadListsAsync(ct).ConfigureAwait(false);

        // Taking an entry off the blacklist also lifts the permanent bans it created, unless
        // another blacklist entry still covers the address. Manual bans are left alone.
        if (parameters.Kind == ListKind.Blacklist)
        {
            var removed = new IpMatcher([], [value]);
            var remaining = new IpMatcher([], await _store.GetListAsync(ListKind.Blacklist, ct).ConfigureAwait(false));
            foreach (var ban in await _store.GetActiveBansAsync(ct).ConfigureAwait(false))
            {
                if (ban.IsPermanent
                    && string.Equals(ban.Note, BlacklistNote, StringComparison.OrdinalIgnoreCase)
                    && removed.IsBlacklisted(ban.IpAddress)
                    && !remaining.IsBlacklisted(ban.IpAddress))
                {
                    await _engine.UnbanAsync(ban.IpAddress, ct).ConfigureAwait(false);
                }
            }
        }

        return IpcResponse.Success(request.Id, null);
    }

    private async Task<IpcResponse> UpdateSettingsAsync(IpcRequest request, CancellationToken ct)
    {
        var parameters = Params<UpdateSettingsParams>(request);
        if (parameters.Settings is null)
        {
            return IpcResponse.Fail(request.Id, "Settings payload is required.");
        }

        parameters.Settings.Normalize();
        var problems = SettingsValidator.Validate(parameters.Settings);
        if (problems.Count > 0)
        {
            return IpcResponse.Fail(request.Id, string.Join(" ", problems));
        }

        await _settings.ApplyAsync(parameters.Settings, ct).ConfigureAwait(false);
        return IpcResponse.Success(request.Id, _settings.Current);
    }

    // ---- helpers ----

    private static readonly ProtocolSource[] KnownSources =
    [
        ProtocolSource.Rdp,
        ProtocolSource.MsSql,
        ProtocolSource.Ftp,
        ProtocolSource.Custom,
    ];

    private static T Params<T>(IpcRequest request) where T : new() =>
        request.Params is { } element ? element.Deserialize<T>(IpcJson.Options) ?? new T() : new T();

    private static string NameFor(ProtocolSource source) => source switch
    {
        ProtocolSource.Rdp => "RDP / logon",
        ProtocolSource.MsSql => "MS SQL",
        ProtocolSource.Ftp => "FTP",
        ProtocolSource.Custom => "Custom",
        _ => source.ToString(),
    };

    private static bool IsEnabled(ProtocolSource source, WinGuardSettings settings) => source switch
    {
        ProtocolSource.Rdp => settings.Rdp.Enabled,
        ProtocolSource.MsSql => settings.MsSql.Enabled,
        ProtocolSource.Ftp => settings.Ftp.Enabled,
        ProtocolSource.Custom => settings.CustomSources.Any(entry => entry.Enabled),
        _ => false,
    };

    /// <summary>Note stored on bans created from the blacklist (matches the engine's own note).</summary>
    private const string BlacklistNote = "blacklist";

    private static string Version =>
        typeof(PipeServer).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";

    // ---- list value handling ----

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

    /// <summary>
    /// Validates and normalizes a whitelist/blacklist entry (single IP or CIDR). Rejects
    /// prefixes shorter than /8: e.g. 0.0.0.0/0 would disable all banning (whitelist) or
    /// ban the entire internet at detection time (blacklist).
    /// </summary>
    private static bool TryNormalizeListValue(IpcRequest request, string raw, out string value, out IpcResponse? failure)
    {
        value = string.Empty;
        failure = null;

        if (!IpMatcher.TryParseCidr(raw, out var network))
        {
            failure = IpcResponse.Fail(request.Id, "Invalid IP or CIDR value.");
            return false;
        }

        var isIPv6 = network.BaseAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        var minimumPrefix = isIPv6 ? 32 : 8;
        if (network.PrefixLength < minimumPrefix)
        {
            failure = IpcResponse.Fail(
                request.Id,
                $"Prefixes shorter than /{minimumPrefix} are rejected for {(isIPv6 ? "IPv6" : "IPv4")}: too broad for a host-protection list.");
            return false;
        }

        // Persist the canonical form so remove/lookups match what was added.
        value = IpMatcher.TryNormalize(raw, out var single) ? single : network.ToString();
        return true;
    }
}
