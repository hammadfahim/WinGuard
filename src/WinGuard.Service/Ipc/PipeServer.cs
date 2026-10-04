using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
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
/// <b>Access control:</b> the pipe is created with <see cref="NamedPipeServerStream"/> only (the
/// <c>System.IO.Pipes.AccessControl</c> package that provides <c>NamedPipeServerStreamAcl</c> /
/// <c>PipeSecurity</c> is intentionally NOT referenced). Instead, immediately after a client
/// connects, the server impersonates the caller with <see cref="NamedPipeServerStream.RunAsClient"/>
/// and rejects anyone who is not a local administrator, LocalSystem, LocalService or NetworkService.
/// Errors while determining the identity fail closed (the connection is rejected). This enforces the
/// PLAN.md §8 "Administrators + LocalSystem only" intent without adding a package.
/// </para>
/// </summary>
public sealed class PipeServer : BackgroundService
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
                pipe = new NamedPipeServerStream(
                    PipeConstants.PipeName,
                    PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous);

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
                _logger.LogWarning("Rejected named-pipe connection from unauthorized identity {Client}.", clientName);
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
        if (identity.User is { } sid
            && (sid.IsWellKnown(WellKnownSidType.LocalSystemSid)
                || sid.IsWellKnown(WellKnownSidType.LocalServiceSid)
                || sid.IsWellKnown(WellKnownSidType.NetworkServiceSid)))
        {
            return true;
        }

        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        try
        {
            using (pipe)
            using (var reader = new StreamReader(pipe, new UTF8Encoding(false), detectEncodingFromByteOrderMarks: false, bufferSize: 4096, leaveOpen: false))
            using (var writer = new StreamWriter(pipe, new UTF8Encoding(false), bufferSize: 4096, leaveOpen: false) { AutoFlush = true, NewLine = "\n" })
            {
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
        var sinceUtc = LocalMidnightUtc();

        var engines = new List<EngineStatusDto>();
        foreach (var source in KnownSources)
        {
            engines.Add(new EngineStatusDto
            {
                Source = source,
                Name = NameFor(source),
                Enabled = IsEnabled(source, settings),
                Running = _state.IsRunning(source),
                DetectionsToday = await _store.CountFailedLoginsSinceAsync(sinceUtc, source, ct).ConfigureAwait(false),
                ActiveBans = bans.Count(ban => ban.Source == source),
            });
        }

        return new ServiceStatusDto
        {
            ServiceRunning = true,
            Version = Version,
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
        var limit = parameters.Limit <= 0 ? 200 : parameters.Limit;
        var events = await _store.GetEventsAsync(limit, parameters.SinceUtc, ct).ConfigureAwait(false);
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

        await _engine.UnbanAsync(ip, ct).ConfigureAwait(false);
        if (parameters.AlsoWhitelist)
        {
            await _store.AddToListAsync(ListKind.Whitelist, ip, ct).ConfigureAwait(false);
            await _store.RemoveFromListAsync(ListKind.Blacklist, ip, ct).ConfigureAwait(false);
        }

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
        if (!IpMatcher.TryParseCidr(parameters.Value, out _))
        {
            return IpcResponse.Fail(request.Id, "Invalid IP or CIDR value.");
        }

        var value = parameters.Value.Trim();
        await _store.AddToListAsync(ListKind.Whitelist, value, ct).ConfigureAwait(false);

        // Reload the engine's in-memory matcher so the new entry takes effect immediately.
        await _engine.HousekeepOnceAsync(ct).ConfigureAwait(false);

        // A whitelisted single host should immediately stop being blocked.
        if (IpMatcher.TryNormalize(value, out var ip))
        {
            await _engine.UnbanAsync(ip, ct).ConfigureAwait(false);
        }

        return IpcResponse.Success(request.Id, null);
    }

    private async Task<IpcResponse> BlacklistAddAsync(IpcRequest request, CancellationToken ct)
    {
        var parameters = Params<ListValueParams>(request);
        if (!IpMatcher.TryParseCidr(parameters.Value, out _))
        {
            return IpcResponse.Fail(request.Id, "Invalid IP or CIDR value.");
        }

        var value = parameters.Value.Trim();
        await _store.AddToListAsync(ListKind.Blacklist, value, ct).ConfigureAwait(false);

        // Reload the engine's in-memory matcher so the new entry takes effect immediately.
        await _engine.HousekeepOnceAsync(ct).ConfigureAwait(false);

        // A blacklisted single host is blocked right away (RdpGuard-style). CIDR ranges
        // take effect at detection time via PLAN §5 step 3. A whitelisted IP is refused
        // by the engine (whitelist always wins) — expected, not an error.
        if (IpMatcher.TryNormalize(value, out var ip))
        {
            try
            {
                await _engine.BanNowAsync(ip, null, permanent: true, "blacklist", ct).ConfigureAwait(false);
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
        if (string.IsNullOrWhiteSpace(parameters.Value))
        {
            return IpcResponse.Fail(request.Id, "A list value is required.");
        }

        await _store.RemoveFromListAsync(parameters.Kind, parameters.Value.Trim(), ct).ConfigureAwait(false);

        // Reload the engine's in-memory matcher so the removal takes effect immediately.
        await _engine.HousekeepOnceAsync(ct).ConfigureAwait(false);
        return IpcResponse.Success(request.Id, null);
    }

    private async Task<IpcResponse> UpdateSettingsAsync(IpcRequest request, CancellationToken ct)
    {
        var parameters = Params<UpdateSettingsParams>(request);
        if (parameters.Settings is null)
        {
            return IpcResponse.Fail(request.Id, "Settings payload is required.");
        }

        await _settings.ApplyAsync(parameters.Settings, ct).ConfigureAwait(false);
        return IpcResponse.Success(request.Id, _settings.Current);
    }

    // ---- prerequisites ----

    private async Task<PrereqsDto> CheckPrereqsAsync(CancellationToken ct)
    {
        var dto = new PrereqsDto();

        var auditEnabled = await QueryAuditLogonFailureAsync(ct).ConfigureAwait(false);
        dto.AuditLogonFailureEnabled = auditEnabled;

        var firewallRunning = false;
        try
        {
            firewallRunning = _firewall.IsServiceRunning();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Firewall service probe failed.");
        }

        dto.FirewallServiceRunning = firewallRunning;

        string? channelWarning = null;
        try
        {
            var configuration = new EventLogConfiguration(
                RdpCoreTsDetector.ChannelName,
                new EventLogSession());
            dto.RdpCoreTsChannelEnabled = configuration.IsEnabled;
        }
        catch (Exception ex)
        {
            // Channel does not exist when the RDP role is not installed.
            dto.RdpCoreTsChannelEnabled = false;
            channelWarning = $"RdpCoreTS/Operational channel is not available: {ex.Message}";
        }

        var warnings = new List<string>();
        if (!auditEnabled)
        {
            warnings.Add("Logon failure auditing is disabled; RDP 4625 events will not be recorded. Enable it with: auditpol /set /subcategory:\"Logon\" /success:enable /failure:enable");
        }

        if (!firewallRunning)
        {
            warnings.Add("Windows Defender Firewall service (MpsSvc) is not running; block rules will not take effect.");
        }

        if (channelWarning is not null)
        {
            warnings.Add(channelWarning);
        }
        else if (!dto.RdpCoreTsChannelEnabled)
        {
            warnings.Add("RdpCoreTS/Operational channel is disabled; the RDP TLS/NLA fallback detector will not see event 140.");
        }

        dto.Warnings = warnings;
        return dto;
    }

    private async Task<bool> QueryAuditLogonFailureAsync(CancellationToken ct)
    {
        try
        {
            var auditpol = Path.Combine(Environment.SystemDirectory, "auditpol.exe");
            var startInfo = new ProcessStartInfo
            {
                FileName = auditpol,
                RedirectStandardOutput = true,
                RedirectStandardError = false,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            startInfo.ArgumentList.Add("/get");
            startInfo.ArgumentList.Add("/subcategory:Logon");
            startInfo.ArgumentList.Add("/r");

            using var process = Process.Start(startInfo);
            if (process is null)
            {
                return false;
            }

            var output = await process.StandardOutput.ReadToEndAsync(ct).ConfigureAwait(false);
            await process.WaitForExitAsync(ct).ConfigureAwait(false);

            // Tolerate UTF-16 output on some builds.
            output = output.Replace("\0", string.Empty);
            return ParseAuditCsv(output);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not query the audit policy with auditpol.");
            return false;
        }
    }

    private static bool ParseAuditCsv(string csv)
    {
        var lines = csv.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length == 0)
        {
            return false;
        }

        var header = SplitCsvLine(lines[0]);
        var subcategoryIndex = FindColumn(header, "Subcategory");
        var inclusionIndex = FindColumn(header, "Inclusion Setting");

        for (var i = 1; i < lines.Length; i++)
        {
            var cells = SplitCsvLine(lines[i]);
            if (cells.Length == 0)
            {
                continue;
            }

            if (subcategoryIndex >= 0 && subcategoryIndex < cells.Length
                && !cells[subcategoryIndex].Trim().Equals("Logon", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var inclusion = inclusionIndex >= 0 && inclusionIndex < cells.Length
                ? cells[inclusionIndex]
                : string.Join(",", cells);
            if (inclusion.Contains("Failure", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static string[] SplitCsvLine(string line)
    {
        if (string.IsNullOrEmpty(line))
        {
            return [];
        }

        var cells = new List<string>();
        var builder = new StringBuilder();
        var inQuotes = false;

        foreach (var c in line)
        {
            switch (c)
            {
                case '"':
                    inQuotes = !inQuotes;
                    break;
                case ',' when !inQuotes:
                    cells.Add(builder.ToString());
                    builder.Clear();
                    break;
                case '\r':
                    break;
                default:
                    builder.Append(c);
                    break;
            }
        }

        cells.Add(builder.ToString());
        return cells.ToArray();
    }

    private static int FindColumn(string[] header, string name)
    {
        for (var i = 0; i < header.Length; i++)
        {
            if (header[i].Trim().Contains(name, StringComparison.OrdinalIgnoreCase))
            {
                return i;
            }
        }

        return -1;
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
        ProtocolSource.Rdp => "RDP",
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

    private DateTime LocalMidnightUtc()
    {
        var localNow = _timeProvider.GetLocalNow();
        var localMidnight = localNow.Date;
        return TimeZoneInfo.ConvertTimeToUtc(localMidnight, TimeZoneInfo.Local);
    }

    private static string Version =>
        typeof(PipeServer).Assembly.GetName().Version?.ToString() ?? "0.0.0";
}