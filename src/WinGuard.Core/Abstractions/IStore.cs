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

    /// <summary>
    /// Records the attempt and returns how many attempts this IP has for the same source with
    /// ts_utc &gt;= sinceUtc (the new one included) in a single round trip — the engine's hot path.
    /// </summary>
    Task<int> AddFailedLoginAndCountAsync(FailedLogin failed, DateTime sinceUtc, CancellationToken ct = default);

    /// <summary>Deletes the newest attempt of this IP for the source (takes back one count). No-op when none.</summary>
    Task RemoveLatestFailedLoginAsync(string ip, ProtocolSource source, CancellationToken ct = default);

    /// <summary>Delete this IP's counter rows (after a ban fires, so the next tier starts fresh).</summary>
    Task ClearFailedLoginsAsync(string ip, CancellationToken ct = default);

    /// <summary>Forget attempts older than the given UTC time (counter reset housekeeping).</summary>
    Task PruneFailedLoginsAsync(DateTime olderThanUtc, CancellationToken ct = default);

    /// <summary>Per-engine detection count since the given UTC time (dashboard "today").</summary>
    Task<int> CountFailedLoginsSinceAsync(DateTime sinceUtc, ProtocolSource? source = null, CancellationToken ct = default);

    // ---- bans ----
    Task<BanEntry?> GetBanAsync(string ip, CancellationToken ct = default);

    /// <summary>
    /// All bans that are permanent or not yet expired. NOTE: implementations filter with
    /// the wall clock — use this for status/startup/reconcile views only. Expiry processing
    /// must use <see cref="GetDueBansAsync"/> so the engine's TimeProvider stays authoritative.
    /// </summary>
    Task<IReadOnlyList<BanEntry>> GetActiveBansAsync(CancellationToken ct = default);

    /// <summary>
    /// Non-permanent bans with ExpiresUtc &lt;= <paramref name="nowUtc"/> that are due for
    /// auto-unblock. The caller supplies "now" so the engine's TimeProvider stays
    /// authoritative — implementations must NOT pre-filter with the wall clock.
    /// </summary>
    Task<IReadOnlyList<BanEntry>> GetDueBansAsync(DateTime nowUtc, CancellationToken ct = default);

    Task UpsertBanAsync(BanEntry ban, CancellationToken ct = default);

    Task RemoveBanAsync(string ip, CancellationToken ct = default);

    // ---- offense counts (ban-tier escalation) ----

    /// <summary>Every persisted offense count.</summary>
    Task<IReadOnlyList<OffenseCountEntry>> GetOffenseCountsAsync(CancellationToken ct = default);

    /// <summary>
    /// Writes the given rows and deletes the given IPs' rows in one transaction. Only what changed
    /// is written, so the cost of a ban does not grow with the number of remembered attackers.
    /// </summary>
    Task SaveOffenseCountsAsync(IReadOnlyCollection<OffenseCountEntry> changed, IReadOnlyCollection<string> removed, CancellationToken ct = default);

    // ---- whitelist / blacklist ----
    Task<IReadOnlyList<string>> GetListAsync(ListKind kind, CancellationToken ct = default);

    Task AddToListAsync(ListKind kind, string value, CancellationToken ct = default);

    Task RemoveFromListAsync(ListKind kind, string value, CancellationToken ct = default);

    // ---- ban history (append-only; survives ban deletion) ----

    /// <summary>Appends one lifecycle row (banned / expired / unbanned / updated).</summary>
    Task AddBanHistoryAsync(BanHistoryEntry entry, CancellationToken ct = default);

    /// <summary>Newest-first ban-history rows, capped at <paramref name="limit"/>.</summary>
    Task<IReadOnlyList<BanHistoryEntry>> GetBanHistoryAsync(int limit, CancellationToken ct = default);

    // ---- daily statistics ----

    /// <summary>
    /// Adds deltas to the (day, source) counter row, creating it when missing. The engine buffers
    /// increments in memory and flushes them here during housekeeping, so the write rate stays low.
    /// </summary>
    Task AddDailyStatsAsync(DateTime dayUtc, ProtocolSource source, int detectionsDelta, int bansDelta, CancellationToken ct = default);

    /// <summary>Statistics rows for every day >= <paramref name="sinceDayUtc"/> (date part), oldest first.</summary>
    Task<IReadOnlyList<DailyStatEntry>> GetDailyStatsAsync(DateTime sinceDayUtc, CancellationToken ct = default);

    /// <summary>Most-banned IPs within the ban history (for the statistics view).</summary>
    Task<IReadOnlyList<TopOffenderEntry>> GetTopOffendersAsync(int limit, CancellationToken ct = default);

    // ---- events ----
    Task AddEventAsync(LogEvent logEvent, CancellationToken ct = default);

    /// <summary>Newest-first, capped at <paramref name="limit"/>. When <paramref name="afterId"/> is set only events with a larger <see cref="LogEvent.Id"/> are returned (cursor polling).</summary>
    Task<IReadOnlyList<LogEvent>> GetEventsAsync(int limit, DateTime? sinceUtc = null, long? afterId = null, CancellationToken ct = default);

    /// <summary>Forget events older than the given UTC time (retention housekeeping; the events table must not grow unbounded).</summary>
    Task PruneEventsAsync(DateTime olderThanUtc, CancellationToken ct = default);

    // ---- settings ----
    Task<IReadOnlyDictionary<string, string>> GetAllSettingsAsync(CancellationToken ct = default);

    Task SetSettingAsync(string key, string value, CancellationToken ct = default);
}
