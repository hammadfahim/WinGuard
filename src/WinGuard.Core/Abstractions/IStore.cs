using WinGuard.Core.Model;

namespace WinGuard.Core.Abstractions;

/// <summary>
/// Persistence contract (SQLite, %ProgramData%\WinGuard\winguard.db).
/// The service is the single writer; all timestamps are UTC ISO-8601 ("o").
/// Implementations must be safe for concurrent use from the engine loop,
/// housekeeping timer and IPC handlers.
/// </summary>
public interface IStore
{
    /// <summary>Create DB file/directory and schema if missing.</summary>
    Task InitializeAsync(CancellationToken ct = default);

    // ---- failed_logins ----
    Task AddFailedLoginAsync(FailedLogin failed, CancellationToken ct = default);

    /// <summary>Count attempts for ip with ts_utc &gt;= sinceUtc (optionally for one source only).</summary>
    Task<int> CountFailedLoginsAsync(string ip, DateTime sinceUtc, ProtocolSource? source = null, CancellationToken ct = default);

    /// <summary>Look up the most recent attempt for ip within [sinceUtc, nowUtc] (used for 4625/140 de-dup). Null when none.</summary>
    Task<FailedLogin?> GetRecentFailedLoginAsync(string ip, ProtocolSource source, DateTime sinceUtc, CancellationToken ct = default);

    /// <summary>Delete this IP's counter rows (after a ban fires, so the next tier starts fresh).</summary>
    Task ClearFailedLoginsAsync(string ip, CancellationToken ct = default);

    /// <summary>Forget attempts older than the given UTC time (counter reset housekeeping).</summary>
    Task PruneFailedLoginsAsync(DateTime olderThanUtc, CancellationToken ct = default);

    /// <summary>Per-engine detection count since the given UTC time (dashboard "today").</summary>
    Task<int> CountFailedLoginsSinceAsync(DateTime sinceUtc, ProtocolSource? source = null, CancellationToken ct = default);

    // ---- bans ----
    Task<BanEntry?> GetBanAsync(string ip, CancellationToken ct = default);

    /// <summary>All bans that are permanent or not yet expired.</summary>
    Task<IReadOnlyList<BanEntry>> GetActiveBansAsync(CancellationToken ct = default);

    /// <summary>
    /// Non-permanent bans with ExpiresUtc &lt;= <paramref name="nowUtc"/> that are due for
    /// auto-unblock. The caller supplies "now" so the engine's TimeProvider stays
    /// authoritative — implementations must NOT pre-filter with the wall clock.
    /// </summary>
    Task<IReadOnlyList<BanEntry>> GetDueBansAsync(DateTime nowUtc, CancellationToken ct = default);

    Task UpsertBanAsync(BanEntry ban, CancellationToken ct = default);

    Task RemoveBanAsync(string ip, CancellationToken ct = default);

    // ---- whitelist / blacklist ----
    Task<IReadOnlyList<string>> GetListAsync(ListKind kind, CancellationToken ct = default);

    Task AddToListAsync(ListKind kind, string value, CancellationToken ct = default);

    Task RemoveFromListAsync(ListKind kind, string value, CancellationToken ct = default);

    // ---- events ----
    Task AddEventAsync(LogEvent logEvent, CancellationToken ct = default);

    /// <summary>Newest-first, capped at <paramref name="limit"/>.</summary>
    Task<IReadOnlyList<LogEvent>> GetEventsAsync(int limit, DateTime? sinceUtc = null, CancellationToken ct = default);

    // ---- settings ----
    Task<IReadOnlyDictionary<string, string>> GetAllSettingsAsync(CancellationToken ct = default);

    Task SetSettingAsync(string key, string value, CancellationToken ct = default);
}
