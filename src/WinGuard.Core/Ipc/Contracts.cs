using System.Text.Json;
using WinGuard.Core.Config;
using WinGuard.Core.Model;

namespace WinGuard.Core.Ipc;

/// <summary>
/// Named-pipe JSON line protocol between the service (server) and the GUI (client).
/// PLAN.md §8. One JSON object per line, UTF-8, '\n' terminated. Request -> single Response
/// with the matching Id. The GUI never touches the DB or firewall directly.
/// </summary>
public static class PipeConstants
{
    public const string PipeName = "WinGuard";

    /// <summary>
    /// Bumped whenever a request, response or DTO changes shape. The service reports it in
    /// <see cref="ServiceStatusDto.ProtocolVersion"/> so a GUI from another release can say so
    /// instead of misbehaving.
    /// </summary>
    public const int ProtocolVersion = 2;
}

/// <summary>Method names used in <see cref="IpcRequest.Method"/>.</summary>
public static class IpcMethods
{
    public const string GetStatus = "GetStatus";
    public const string ListBans = "ListBans";
    public const string ListEvents = "ListEvents";           // params: ListEventsParams; result: List<EventDto>
    public const string ListLists = "ListLists";             // result: List<ListEntryDto>
    public const string Unblock = "Unblock";                 // params: UnblockParams
    public const string BlockNow = "BlockNow";               // params: BlockNowParams
    public const string WhitelistAdd = "WhitelistAdd";       // params: ListValueParams
    public const string BlacklistAdd = "BlacklistAdd";       // params: ListValueParams
    public const string ListRemove = "ListRemove";           // params: ListRemoveParams
    public const string GetSettings = "GetSettings";         // result: WinGuardSettings
    public const string UpdateSettings = "UpdateSettings";   // params: UpdateSettingsParams (hot-reload)
    public const string CheckPrereqs = "CheckPrereqs";       // result: PrereqsDto
}

public sealed class IpcRequest
{
    public long Id { get; set; }
    public string Method { get; set; } = string.Empty;
    public JsonElement? Params { get; set; }
}

public sealed class IpcResponse
{
    public long Id { get; set; }
    public bool Ok { get; set; }
    public string? Error { get; set; }
    public JsonElement? Result { get; set; }

    public static IpcResponse Success(long id, object? result) => new()
    {
        Id = id,
        Ok = true,
        Result = result is null ? null : JsonSerializer.SerializeToElement(result, IpcJson.Options),
    };

    public static IpcResponse Fail(long id, string error) => new() { Id = id, Ok = false, Error = error };
}

/// <summary>Shared serializer options (camelCase; TimeSpan supported natively).</summary>
public static class IpcJson
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
    };
}

// ---- DTOs ----

public sealed class ServiceStatusDto
{
    public bool ServiceRunning { get; set; }
    public string Version { get; set; } = string.Empty;

    /// <summary>The service's <see cref="PipeConstants.ProtocolVersion"/> (0 from releases before it existed).</summary>
    public int ProtocolVersion { get; set; }
    public DateTime StartedUtc { get; set; }
    public int ActiveBans { get; set; }
    public List<EngineStatusDto> Engines { get; set; } = [];
}

public sealed class EngineStatusDto
{
    public ProtocolSource Source { get; set; }
    public string Name { get; set; } = string.Empty;
    public bool Enabled { get; set; }
    public bool Running { get; set; }
    public int DetectionsToday { get; set; }
    public int ActiveBans { get; set; }
}

public sealed class BanDto
{
    public string IpAddress { get; set; } = string.Empty;
    public ProtocolSource Source { get; set; }
    public DateTime BannedAtUtc { get; set; }
    public DateTime ExpiresUtc { get; set; }
    public int OffenseCount { get; set; }
    public bool IsPermanent { get; set; }
    public string? Note { get; set; }

    public static BanDto From(BanEntry b) => new()
    {
        IpAddress = b.IpAddress,
        Source = b.Source,
        BannedAtUtc = b.BannedAtUtc,
        ExpiresUtc = b.ExpiresUtc,
        OffenseCount = b.OffenseCount,
        IsPermanent = b.IsPermanent,
        Note = b.Note,
    };
}

public sealed class EventDto
{
    /// <summary>Monotonic store id used as the GUI polling cursor.</summary>
    public long Id { get; set; }
    public DateTime TimestampUtc { get; set; }
    public LogEventLevel Level { get; set; }
    public ProtocolSource? Source { get; set; }
    public string? IpAddress { get; set; }
    public string Message { get; set; } = string.Empty;

    public static EventDto From(LogEvent e) => new()
    {
        Id = e.Id,
        TimestampUtc = e.TimestampUtc,
        Level = e.Level,
        Source = e.Source,
        IpAddress = e.IpAddress,
        Message = e.Message,
    };
}

public sealed class ListEntryDto
{
    public ListKind Kind { get; set; }
    public string Value { get; set; } = string.Empty;
}

public sealed class PrereqsDto
{
    /// <summary>auditpol: Logon subcategory failure auditing enabled (needed for 4625).</summary>
    public bool AuditLogonFailureEnabled { get; set; }

    /// <summary>Windows Defender Firewall service (MpsSvc) running.</summary>
    public bool FirewallServiceRunning { get; set; }

    /// <summary>RdpCoreTS/Operational channel exists and is enabled.</summary>
    public bool RdpCoreTsChannelEnabled { get; set; }

    public List<string> Warnings { get; set; } = [];
}

// ---- method params ----

public sealed class ListEventsParams
{
    public int Limit { get; set; } = 200;
    public DateTime? SinceUtc { get; set; }

    /// <summary>When set, only events with a larger <see cref="EventDto.Id"/> are returned.</summary>
    public long? AfterId { get; set; }
}

public sealed class UnblockParams
{
    public string Ip { get; set; } = string.Empty;
    public bool AlsoWhitelist { get; set; }
}

public sealed class BlockNowParams
{
    public string Ip { get; set; } = string.Empty;
    public TimeSpan? Duration { get; set; }
    public bool Permanent { get; set; }
    public string? Note { get; set; }
}

public sealed class ListValueParams
{
    /// <summary>IP or CIDR.</summary>
    public string Value { get; set; } = string.Empty;
}

public sealed class ListRemoveParams
{
    public ListKind Kind { get; set; }
    public string Value { get; set; } = string.Empty;
}

public sealed class UpdateSettingsParams
{
    public WinGuardSettings Settings { get; set; } = new();
}
