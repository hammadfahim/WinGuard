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
/// full control, Authenticated Users read/write — plus <c>PIPE_REJECT_REMOTE_CLIENTS</c> and
/// first-instance anti-squatting, via P/Invoke (<c>PipeSecurity</c> lives in the
/// System.IO.Pipes.AccessControl package, which is intentionally not referenced). Every
/// connection is additionally authorized by impersonating the client
/// (<see cref="NamedPipeServerStream.RunAsClient"/>): only LocalSystem and members of the
/// Administrators group — checked by group SID so the non-elevated GUI's UAC-filtered token
/// is recognized — are accepted; everything else fails closed. This enforces the PLAN.md §8
/// "Administrators + LocalSystem only" intent (reviews S-M1/S-M2).
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

        // Group-SID check instead of IsInRole: under UAC Admin Approval Mode the
        // non-elevated GUI token carries Administrators as a *deny-only* SID, which
        // IsInRole reports as false. Deny-only SIDs never appear in non-admin tokens,
        // so membership in Groups still proves the user is an administrator (review S-M2).
        if (identity.Groups is { } groups)
        {
            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            foreach (var group in groups)
            {
                if (group is SecurityIdentifier groupSid && groupSid.Equals(admins))
                {
                    return true;
                }
            }
        }

        return false;
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
        var limit = Math.Clamp(parameters.Limit <= 0 ? 200 : parameters.Limit, 1, 1000);
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

        if (parameters.AlsoWhitelist)
        {
            // Whitelist FIRST and reload the engine matcher, so an in-flight attack cannot
            // re-ban the IP in the window before the next housekeeping pass (review S-M7).
            await _store.AddToListAsync(ListKind.Whitelist, ip, ct).ConfigureAwait(false);
            await _store.RemoveFromListAsync(ListKind.Blacklist, ip, ct).ConfigureAwait(false);
            await _engine.HousekeepOnceAsync(ct).ConfigureAwait(false);
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
        if (!TryNormalizeListValue(request, parameters.Value, out var value, out var failure))
        {
            return failure!;
        }

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
        if (!TryNormalizeListValue(request, parameters.Value, out var value, out var failure))
        {
            return failure!;
        }

        await _store.RemoveFromListAsync(parameters.Kind, value, ct).ConfigureAwait(false);

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
            warnings.Add("Logon failure auditing is disabled; RDP 4625 events will not be recorded. Enable it with: auditpol /set /subcategory:\"{0CCE9215-69AE-11D9-BED3-505054503030}\" /success:enable /failure:enable (the GUID form also works on localized Windows)");
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
            // Locale-independent subcategory GUID for "Logon" — the English name fails on
            // localized Windows (review P-M4).
            startInfo.ArgumentList.Add("/subcategory:{0CCE9215-69AE-11D9-BED3-505054503030}");
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
        var settingValueIndex = FindColumn(header, "Setting Value");

        for (var i = 1; i < lines.Length; i++)
        {
            var cells = SplitCsvLine(lines[i]);
            if (cells.Length == 0)
            {
                continue;
            }

            // The query is scoped by the locale-independent Logon subcategory GUID, so every
            // data row belongs to Logon regardless of its localized display name; only skip
            // structurally malformed rows.
            if (subcategoryIndex >= cells.Length)
            {
                continue;
            }

            // Prefer the numeric Setting Value (0=none,1=success,2=failure,3=both): it is
            // locale-independent, unlike the "Failure" text.
            if (settingValueIndex >= 0 && settingValueIndex < cells.Length
                && int.TryParse(cells[settingValueIndex].Trim(), out var settingValue))
            {
                return (settingValue & 2) != 0;
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

        if (network.PrefixLength < 8)
        {
            failure = IpcResponse.Fail(request.Id, "Prefixes shorter than /8 are rejected: too broad for a host-protection list.");
            return false;
        }

        // Persist the canonical form so remove/lookups match what was added.
        value = IpMatcher.TryNormalize(raw, out var single) ? single : network.ToString();
        return true;
    }

    // ---- secured pipe creation (review S-M2) ----

    private const int MaxLineBytes = 1024 * 1024;
    private const int SecurityDescriptorRevision = 1;
    private const int PipeUnlimitedInstances = 255;
    private const int PipeAccessDuplex = 0x00000003;
    private const int FileFlagOverlapped = 0x40000000;
    private const int PipeFirstPipeInstance = 0x00080000;
    private const int PipeTypeByte = 0x00000000;
    private const int PipeReadmodeByte = 0x00000000;
    private const int PipeWait = 0x00000000;
    private const int PipeRejectRemoteClients = 0x00000008;
    private const int ErrorAccessDenied = 5;

    /// <summary>
    /// SYSTEM + Administrators full control; Authenticated Users read/write so the
    /// non-elevated (UAC-filtered) admin GUI can submit requests — identity is still
    /// verified per connection in <see cref="Authorize"/>. No Everyone/Anonymous access.
    /// </summary>
    private const string PipeSddl = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)";

    private NamedPipeServerStream CreateSecuredPipe()
    {
        var openMode = PipeAccessDuplex | FileFlagOverlapped;
        if (!_firstPipeInstanceCreated)
        {
            // Fail instead of silently adding an instance to a squatted pipe name.
            openMode |= PipeFirstPipeInstance;
        }

        var pipeMode = PipeTypeByte | PipeReadmodeByte | PipeWait | PipeRejectRemoteClients;

        if (!TryCreateSecurityDescriptor(PipeSddl, out var securityDescriptor))
        {
            _logger.LogWarning(
                "Could not build the pipe security descriptor; falling back to the OS default DACL " +
                "(non-elevated GUI connections may be rejected by the OS).");
            return new NamedPipeServerStream(
                PipeConstants.PipeName,
                PipeDirection.InOut,
                NamedPipeServerStream.MaxAllowedServerInstances,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous);
        }

        try
        {
            var securityAttributes = new SecurityAttributes
            {
                nLength = Marshal.SizeOf<SecurityAttributes>(),
                lpSecurityDescriptor = securityDescriptor,
                bInheritHandle = false,
            };

            var handle = NativeMethods.CreateNamedPipe(
                @"\\.\pipe\" + PipeConstants.PipeName,
                openMode,
                pipeMode,
                PipeUnlimitedInstances,
                4096,
                4096,
                0,
                ref securityAttributes);

            if (handle.IsInvalid)
            {
                var error = Marshal.GetLastWin32Error();
                if (!_firstPipeInstanceCreated && error == ErrorAccessDenied)
                {
                    _logger.LogError(
                        "The pipe name \\\\.\\pipe\\{Pipe} is already in use by another process " +
                        "(possible name squatting); WinGuard IPC cannot start.",
                        PipeConstants.PipeName);
                }

                throw new IOException($"CreateNamedPipe failed with Win32 error {error}.");
            }

            _firstPipeInstanceCreated = true;
            return new NamedPipeServerStream(PipeDirection.InOut, isAsync: true, isConnected: false, handle);
        }
        finally
        {
            if (securityDescriptor != IntPtr.Zero)
            {
                // The pipe object keeps its own copy of the descriptor.
                NativeMethods.LocalFree(securityDescriptor);
            }
        }
    }

    private static bool TryCreateSecurityDescriptor(string sddl, out IntPtr securityDescriptor)
    {
        securityDescriptor = IntPtr.Zero;
        try
        {
            return NativeMethods.ConvertStringSecurityDescriptorToSecurityDescriptor(
                       sddl, SecurityDescriptorRevision, out securityDescriptor, IntPtr.Zero)
                   && securityDescriptor != IntPtr.Zero;
        }
        catch (Exception)
        {
            securityDescriptor = IntPtr.Zero;
            return false;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }

    private static class NativeMethods
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern SafePipeHandle CreateNamedPipe(
            string lpName,
            int dwOpenMode,
            int dwPipeMode,
            int nMaxInstances,
            int nOutBufferSize,
            int nInBufferSize,
            int nDefaultTimeOut,
            ref SecurityAttributes lpSecurityAttributes);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
            string stringSecurityDescriptor,
            int stringSDRevision,
            out IntPtr securityDescriptor,
            IntPtr securityDescriptorSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr LocalFree(IntPtr hMem);
    }

    /// <summary>UTF-8 line reader with a hard per-line byte cap (review S-N3).</summary>
    private sealed class BoundedLineReader
    {
        private readonly Stream _stream;
        private readonly ILogger _logger;
        private readonly byte[] _buffer = new byte[8192];
        private readonly MemoryStream _line = new();
        private int _start;
        private int _count;

        public BoundedLineReader(Stream stream, ILogger logger)
        {
            _stream = stream;
            _logger = logger;
        }

        /// <summary>
        /// Reads the next '\n'-terminated line (a trailing '\r' is trimmed). Returns null at
        /// EOF; throws <see cref="IOException"/> when a line exceeds <see cref="MaxLineBytes"/>.
        /// </summary>
        public async Task<string?> ReadLineAsync(CancellationToken ct)
        {
            while (true)
            {
                if (_start >= _count)
                {
                    _count = await _stream.ReadAsync(_buffer.AsMemory(0, _buffer.Length), ct).ConfigureAwait(false);
                    _start = 0;
                    if (_count == 0)
                    {
                        return _line.Length == 0 ? null : TakeLine();
                    }
                }

                var newline = Array.IndexOf(_buffer, (byte)'\n', _start, _count - _start);
                var end = newline >= 0 ? newline : _count;
                if (end > _start)
                {
                    _line.Write(_buffer, _start, end - _start);
                    _start = end;
                    if (_line.Length > MaxLineBytes)
                    {
                        _logger.LogWarning("IPC client exceeded the {Cap}-byte line cap; disconnecting it.", MaxLineBytes);
                        _line.SetLength(0);
                        throw new IOException($"IPC line exceeded the {MaxLineBytes}-byte cap.");
                    }
                }

                if (newline >= 0)
                {
                    _start++; // consume '\n'
                    return TakeLine();
                }
            }
        }

        private string TakeLine()
        {
            var text = Encoding.UTF8.GetString(_line.GetBuffer(), 0, (int)_line.Length);
            _line.SetLength(0);
            return text.EndsWith('\r') ? text[..^1] : text;
        }
    }
}