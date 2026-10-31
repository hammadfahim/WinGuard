using System.Text.Json;
using Microsoft.Extensions.Logging;
using WinGuard.Core.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Engine;
using WinGuard.Core.Ipc;
using WinGuard.Core.Model;

namespace WinGuard.Service.Ipc;

/// <summary>
/// Executes the service side of the GUI protocol (PLAN.md §8, <c>Core/Ipc/Contracts.cs</c>): one
/// JSON request line in, one JSON response line out, dispatched against the shared store, ban
/// engine and settings holder. It knows nothing about pipes or callers — <see cref="PipeServer"/>
/// owns the transport and only hands lines to this class after the caller has been authorized —
/// which also makes every request testable without a pipe.
/// </summary>
public sealed partial class IpcRequestHandler
{
    private readonly IStore _store;
    private readonly BanEngine _engine;
    private readonly SettingsHolder _settings;
    private readonly IFirewall _firewall;
    private readonly DetectorRuntimeState _state;
    private readonly ILogger<IpcRequestHandler> _logger;
    private readonly TimeProvider _timeProvider;
    private readonly DateTime _startedUtc;

    /// <summary>Creates the handler.</summary>
    /// <param name="store">Persistence (single-writer state).</param>
    /// <param name="engine">Ban engine for manual block/unblock.</param>
    /// <param name="settings">Live settings holder.</param>
    /// <param name="firewall">Firewall abstraction (prerequisite probe).</param>
    /// <param name="state">Shared detector running flags.</param>
    /// <param name="timeProvider">Clock used for the reported service start time and statistics windows.</param>
    /// <param name="logger">Diagnostic logger.</param>
    public IpcRequestHandler(
        IStore store,
        BanEngine engine,
        SettingsHolder settings,
        IFirewall firewall,
        DetectorRuntimeState state,
        TimeProvider timeProvider,
        ILogger<IpcRequestHandler> logger)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _engine = engine ?? throw new ArgumentNullException(nameof(engine));
        _settings = settings ?? throw new ArgumentNullException(nameof(settings));
        _firewall = firewall ?? throw new ArgumentNullException(nameof(firewall));
        _state = state ?? throw new ArgumentNullException(nameof(state));
        ArgumentNullException.ThrowIfNull(timeProvider);
        _timeProvider = timeProvider;
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _startedUtc = timeProvider.GetUtcNow().UtcDateTime;
    }

    /// <summary>
    /// Handles one request line and returns the response line, or null when the line holds no
    /// request. A request that fails is answered with <c>ok = false</c> and the reason; it never
    /// throws (other than for cancellation).
    /// </summary>
    public async Task<string?> HandleLineAsync(string line, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return null;
        }

        IpcResponse response;
        long id = 0;
        try
        {
            var request = JsonSerializer.Deserialize<IpcRequest>(line, IpcJson.Options);
            if (request is null)
            {
                return null;
            }

            id = request.Id;
            response = await DispatchAsync(request, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "IPC request failed.");
            response = IpcResponse.Fail(id, ex.Message);
        }

        return JsonSerializer.Serialize(response, IpcJson.Options);
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
        IpcMethods.GetStatistics => IpcResponse.Success(request.Id, await GetStatisticsAsync(Params<GetStatisticsParams>(request), ct).ConfigureAwait(false)),
        IpcMethods.ListBanHistory => IpcResponse.Success(request.Id, await ListBanHistoryAsync(Params<ListBanHistoryParams>(request), ct).ConfigureAwait(false)),
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
            ReportOnly = settings.ReportOnly,
        };
    }

    private async Task<List<BanDto>> ListBansAsync(CancellationToken ct)
    {
        var settings = _settings.Current;
        var bans = await _store.GetActiveBansAsync(ct).ConfigureAwait(false);
        return bans.Select(ban => BanDto.From(ban, settings)).ToList();
    }

    private async Task<List<EventDto>> ListEventsAsync(ListEventsParams parameters, CancellationToken ct)
    {
        var limit = Math.Clamp(parameters.Limit <= 0 ? 200 : parameters.Limit, 1, 1000);
        var events = await _store.GetEventsAsync(limit, parameters.SinceUtc, parameters.AfterId, ct).ConfigureAwait(false);
        return events.Select(EventDto.From).ToList();
    }

    private async Task<StatisticsDto> GetStatisticsAsync(GetStatisticsParams parameters, CancellationToken ct)
    {
        var days = Math.Clamp(parameters.Days <= 0 ? 30 : parameters.Days, 1, 365);

        // The engine buckets the daily rows by local calendar day, so the window counts local days too.
        var since = _timeProvider.GetLocalNow().Date.AddDays(-(days - 1));

        var daily = await _store.GetDailyStatsAsync(since, ct).ConfigureAwait(false);
        var topOffenders = await _store.GetTopOffendersAsync(10, ct).ConfigureAwait(false);
        var historyRows = await _store.CountBanHistoryAsync(ct).ConfigureAwait(false);
        var bans = await _store.GetActiveBansAsync(ct).ConfigureAwait(false);

        return new StatisticsDto
        {
            Daily = daily.Select(DailyStatDto.From).ToList(),
            TopOffenders = topOffenders.Select(TopOffenderDto.From).ToList(),
            TotalActiveBans = bans.Count,
            HistoryRows = historyRows,
        };
    }

    private async Task<List<BanHistoryDto>> ListBanHistoryAsync(ListBanHistoryParams parameters, CancellationToken ct)
    {
        var limit = Math.Clamp(parameters.Limit <= 0 ? 100 : parameters.Limit, 1, 1000);
        var history = await _store.GetBanHistoryAsync(limit, ct).ConfigureAwait(false);
        return history.Select(BanHistoryDto.From).ToList();
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
        // A ban can be a range: IPv6 aggregate bans are stored under their prefix.
        var parameters = Params<UnblockParams>(request);
        if (!IpMatcher.TryNormalizeBanTarget(parameters.Ip, out var ip))
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

        return await LiftBansAsync(request, [ip], ct).ConfigureAwait(false);
    }

    private async Task<IpcResponse> BlockNowAsync(IpcRequest request, CancellationToken ct)
    {
        // A range is accepted only when it is already banned (promoting an IPv6 aggregate ban to
        // permanent); blocking a new subnet is what the blacklist is for.
        var parameters = Params<BlockNowParams>(request);
        if (!IpMatcher.TryNormalizeBanTarget(parameters.Ip, out var ip)
            || (ip.Contains('/') && await _store.GetBanAsync(ip, ct).ConfigureAwait(false) is null))
        {
            return IpcResponse.Fail(request.Id, "Invalid IP address.");
        }

        await _engine.BanNowAsync(ip, parameters.Duration, parameters.Permanent, parameters.Note, ct).ConfigureAwait(false);

        // The answer is what was recorded: the engine picks the duration when none is given and
        // caps the ones it is given.
        var ban = await _store.GetBanAsync(ip, ct).ConfigureAwait(false);
        return IpcResponse.Success(request.Id, ban is null ? null : BanDto.From(ban, _settings.Current));
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
            return await LiftBansAsync(request, [ip], ct).ConfigureAwait(false);
        }

        // CIDR range: unban every active ban that falls inside it.
        var range = new IpMatcher([value], []);
        var bans = await _store.GetActiveBansAsync(ct).ConfigureAwait(false);
        var inside = bans.Select(ban => ban.IpAddress).Where(range.IsWhitelisted).ToList();
        return await LiftBansAsync(request, inside, ct).ConfigureAwait(false);
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

        // A blacklisted single host is blocked right away (RdpGuard-style). CIDR ranges were
        // enforced as range rules by the pass above. A whitelisted IP or a non-host address is
        // refused by the engine (whitelist always wins) — expected, not an error. A database
        // failure is not one either: the engine blocks first and saves the ban when it can.
        if (IpMatcher.TryNormalize(value, out var ip))
        {
            try
            {
                await _engine.BanNowAsync(ip, null, permanent: true, BlacklistNote, ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is InvalidOperationException or ArgumentException)
            {
                _logger.LogInformation(ex, "Blacklisted IP {Ip} was not banned immediately.", ip);
            }
        }

        return IpcResponse.Success(request.Id, null);
    }

    private async Task<IpcResponse> ListRemoveAsync(IpcRequest request, CancellationToken ct)
    {
        // Removal goes by what is stored, not by what may be added today: an entry from an older
        // version, however broad or malformed, must not become impossible to take off the list.
        var parameters = Params<ListRemoveParams>(request);
        var value = await FindListEntryAsync(parameters.Kind, parameters.Value, ct).ConfigureAwait(false);
        if (value is null)
        {
            return IpcResponse.Fail(request.Id, "Invalid IP or CIDR value.");
        }

        await _store.RemoveFromListAsync(parameters.Kind, value, ct).ConfigureAwait(false);

        // Reload the engine's in-memory matcher so the removal takes effect immediately.
        await _engine.HousekeepOnceAsync(ct).ConfigureAwait(false);

        // Taking an entry off the blacklist also lifts the permanent bans it created, unless
        // another blacklist entry still covers the address. Manual bans are left alone.
        if (parameters.Kind == ListKind.Blacklist)
        {
            var removed = new IpMatcher([], [value]);
            var remaining = new IpMatcher([], await _store.GetListAsync(ListKind.Blacklist, ct).ConfigureAwait(false));
            var bans = await _store.GetActiveBansAsync(ct).ConfigureAwait(false);
            var created = bans
                .Where(ban => ban.IsPermanent
                    && string.Equals(ban.Note, BlacklistNote, StringComparison.OrdinalIgnoreCase)
                    && removed.IsBlacklisted(ban.IpAddress)
                    && !remaining.IsBlacklisted(ban.IpAddress))
                .Select(ban => ban.IpAddress)
                .ToList();
            return await LiftBansAsync(request, created, ct).ConfigureAwait(false);
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
        typeof(IpcRequestHandler).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";

    /// <summary>
    /// Lifts each ban. One that cannot be lifted does not stop the rest, and the caller is told
    /// exactly which remain: the store is asked, because the engine logs a removal the store refused
    /// and carries on, and the firewall would block that address again at the next reconcile.
    /// </summary>
    private async Task<IpcResponse> LiftBansAsync(IpcRequest request, IReadOnlyList<string> ips, CancellationToken ct)
    {
        foreach (var ip in ips)
        {
            try
            {
                await _engine.UnbanAsync(ip, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Could not lift the ban of {Ip}.", ip);
            }
        }

        var active = await _store.GetActiveBansAsync(ct).ConfigureAwait(false);
        var remaining = ips.Where(ip => active.Any(ban => string.Equals(ban.IpAddress, ip, StringComparison.OrdinalIgnoreCase))).ToList();
        if (remaining.Count == 0)
        {
            return IpcResponse.Success(request.Id, null);
        }

        return IpcResponse.Fail(
            request.Id,
            $"{remaining.Count} of {ips.Count} ban(s) could not be lifted: {string.Join(", ", remaining.Take(5))}. " +
            "Everything else in this request was applied; see the service log, then try again.");
    }

    /// <summary>
    /// Finds the stored entry a removal request means: the same text, or the same network written
    /// differently. A valid value that is not stored comes back as is, so a removal can be repeated
    /// after a partial failure; null when the value is neither stored nor valid.
    /// </summary>
    private async Task<string?> FindListEntryAsync(ListKind kind, string? raw, CancellationToken ct)
    {
        var text = raw?.Trim();
        if (string.IsNullOrEmpty(text))
        {
            return null;
        }

        var stored = await _store.GetListAsync(kind, ct).ConfigureAwait(false);
        var isNetwork = IpMatcher.TryParseCidr(text, out var network);
        return stored.FirstOrDefault(entry => string.Equals(entry.Trim(), text, StringComparison.OrdinalIgnoreCase))
            ?? stored.FirstOrDefault(entry => isNetwork && IpMatcher.TryParseCidr(entry, out var other) && other.Equals(network))
            ?? (isNetwork ? text : null);
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

        // Persist the canonical form so remove/lookups match what was added. A single-host CIDR is
        // that host, which also gets a blacklisted one banned at once.
        value = IpMatcher.TryNormalizeBanTarget(raw, out var target) ? target : network.ToString();
        return true;
    }
}
