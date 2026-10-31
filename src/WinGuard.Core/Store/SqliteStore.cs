using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using WinGuard.Core.Abstractions;
using WinGuard.Core.Model;

namespace WinGuard.Core.Store;

/// <summary>
/// SQLite-backed <see cref="IStore"/> (PLAN.md §3). Single file (default
/// <c>%ProgramData%\WinGuard\winguard.db</c>), created on first use together with its
/// directory. All timestamps are persisted as UTC ISO-8601 round-trip strings ("o"),
/// which also sort chronologically under SQLite's default BINARY collation.
/// <para>
/// Access is serialized with a <see cref="SemaphoreSlim"/>(1,1) over a single guarded
/// connection, so the engine loop, housekeeping timer and IPC handlers can call freely.
/// WAL journaling and a busy timeout are enabled to keep readers/writers cooperating.
/// </para>
/// </summary>
public sealed class SqliteStore : IStore, ISecretScrubbingStore, IAsyncDisposable
{
    private const int BusyTimeoutMs = 5_000;

    // VACUUM rewrites the whole file while the service is still starting, and Windows gives a
    // service 30 seconds for that. Pruning keeps a normal database well below this.
    private const long MaxBytesToVacuumAtStartup = 64 * 1024 * 1024;

    // A locked database is retried for 30 seconds by default, as long as that whole allowance.
    private const int ScrubCommandTimeoutSeconds = 5;

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly string _databasePath;
    private readonly string _connectionString;
    private readonly ILogger<SqliteStore> _logger;
    private readonly TimeProvider _timeProvider;

    private SqliteConnection? _connection;
    private bool _initialized;
    private bool _disposed;

    /// <summary>Creates a store for the given database file. <see cref="InitializeAsync"/> creates it if missing.</summary>
    /// <param name="databasePath">Absolute path to the SQLite file (directory is created as needed).</param>
    /// <param name="logger">Diagnostic logger.</param>
    public SqliteStore(string databasePath, ILogger<SqliteStore> logger, TimeProvider? timeProvider = null)
    {
        if (string.IsNullOrWhiteSpace(databasePath))
        {
            throw new ArgumentException("A database path is required.", nameof(databasePath));
        }

        _databasePath = Path.GetFullPath(databasePath);
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _timeProvider = timeProvider ?? TimeProvider.System;

        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Default,
            Pooling = false,
        }.ToString();
    }

    /// <inheritdoc />
    public async Task InitializeAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            await EnsureInitializedLockedAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    // ---- failed_logins ----

    /// <inheritdoc />
    public async Task AddFailedLoginAsync(FailedLogin failed, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(failed);
        await WithConnectionAsync(
            async connection =>
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText =
                    "INSERT INTO failed_logins (ip, source, ts_utc, user, raw) VALUES ($ip, $source, $ts, $user, NULL);";
                cmd.Parameters.AddWithValue("$ip", failed.IpAddress);
                cmd.Parameters.AddWithValue("$source", (int)failed.Source);
                cmd.Parameters.AddWithValue("$ts", ToDb(failed.TimestampUtc));
                cmd.Parameters.AddWithValue("$user", (object?)failed.UserName ?? DBNull.Value);
                await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            },
            ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<int> CountFailedLoginsAsync(string ip, DateTime sinceUtc, ProtocolSource? source = null, CancellationToken ct = default)
    {
        return await WithConnectionAsync(
            async connection =>
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText = source is null
                    ? "SELECT COUNT(*) FROM failed_logins WHERE ip = $ip AND ts_utc >= $since;"
                    : "SELECT COUNT(*) FROM failed_logins WHERE ip = $ip AND ts_utc >= $since AND source = $source;";
                cmd.Parameters.AddWithValue("$ip", ip);
                cmd.Parameters.AddWithValue("$since", ToDb(sinceUtc));
                if (source is not null)
                {
                    cmd.Parameters.AddWithValue("$source", (int)source.Value);
                }

                var result = await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false);
                return Convert.ToInt32(result, CultureInfo.InvariantCulture);
            },
            ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<int> AddFailedLoginAndCountAsync(FailedLogin failed, DateTime sinceUtc, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(failed);
        return await WithConnectionAsync(
            async connection =>
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText =
                    "INSERT INTO failed_logins (ip, source, ts_utc, user, raw) VALUES ($ip, $source, $ts, $user, NULL); " +
                    "SELECT COUNT(*) FROM failed_logins WHERE ip = $ip AND ts_utc >= $since AND source = $source;";
                cmd.Parameters.AddWithValue("$ip", failed.IpAddress);
                cmd.Parameters.AddWithValue("$source", (int)failed.Source);
                cmd.Parameters.AddWithValue("$ts", ToDb(failed.TimestampUtc));
                cmd.Parameters.AddWithValue("$user", (object?)failed.UserName ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$since", ToDb(sinceUtc));
                var result = await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false);
                return Convert.ToInt32(result, CultureInfo.InvariantCulture);
            },
            ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task RemoveLatestFailedLoginAsync(string ip, ProtocolSource source, CancellationToken ct = default)
    {
        await WithConnectionAsync(
            async connection =>
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText =
                    "DELETE FROM failed_logins WHERE rowid = (" +
                    "SELECT rowid FROM failed_logins WHERE ip = $ip AND source = $source ORDER BY ts_utc DESC, rowid DESC LIMIT 1);";
                cmd.Parameters.AddWithValue("$ip", ip);
                cmd.Parameters.AddWithValue("$source", (int)source);
                await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
                return true;
            },
            ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<string>> GetFailedLoginUsersAsync(string ip, DateTime sinceUtc, CancellationToken ct = default)
    {
        return await WithConnectionAsync(
            async connection =>
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText =
                    "SELECT DISTINCT user FROM failed_logins WHERE ip = $ip AND ts_utc >= $since AND user IS NOT NULL;";
                cmd.Parameters.AddWithValue("$ip", ip);
                cmd.Parameters.AddWithValue("$since", ToDb(sinceUtc));

                var users = new List<string>();
                await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
                while (await reader.ReadAsync(ct).ConfigureAwait(false))
                {
                    users.Add(reader.GetString(0));
                }

                return (IReadOnlyList<string>)users;
            },
            ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task SetFailedLoginUserAsync(string ip, ProtocolSource source, string user, DateTime sinceUtc, CancellationToken ct = default)
    {
        await WithConnectionAsync(
            async connection =>
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText =
                    "UPDATE failed_logins SET user = $user WHERE rowid = (" +
                    "SELECT rowid FROM failed_logins WHERE ip = $ip AND source = $source AND ts_utc >= $since AND user IS NULL " +
                    "ORDER BY ts_utc DESC, rowid DESC LIMIT 1);";
                cmd.Parameters.AddWithValue("$user", user);
                cmd.Parameters.AddWithValue("$ip", ip);
                cmd.Parameters.AddWithValue("$source", (int)source);
                cmd.Parameters.AddWithValue("$since", ToDb(sinceUtc));
                await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
                return true;
            },
            ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task ClearFailedLoginsAsync(string ip, CancellationToken ct = default)
    {
        await WithConnectionAsync(
            async connection =>
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText = "DELETE FROM failed_logins WHERE ip = $ip;";
                cmd.Parameters.AddWithValue("$ip", ip);
                await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
                return true;
            },
            ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task PruneFailedLoginsAsync(DateTime olderThanUtc, CancellationToken ct = default)
    {
        await WithConnectionAsync(
            async connection =>
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText = "DELETE FROM failed_logins WHERE ts_utc < $before;";
                cmd.Parameters.AddWithValue("$before", ToDb(olderThanUtc));
                await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
                return true;
            },
            ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<int> CountFailedLoginsSinceAsync(DateTime sinceUtc, ProtocolSource? source = null, CancellationToken ct = default)
    {
        return await WithConnectionAsync(
            async connection =>
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText = source is null
                    ? "SELECT COUNT(*) FROM failed_logins WHERE ts_utc >= $since;"
                    : "SELECT COUNT(*) FROM failed_logins WHERE ts_utc >= $since AND source = $source;";
                cmd.Parameters.AddWithValue("$since", ToDb(sinceUtc));
                if (source is not null)
                {
                    cmd.Parameters.AddWithValue("$source", (int)source.Value);
                }

                var result = await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false);
                return Convert.ToInt32(result, CultureInfo.InvariantCulture);
            },
            ct).ConfigureAwait(false);
    }

    // ---- bans ----

    /// <inheritdoc />
    public async Task<BanEntry?> GetBanAsync(string ip, CancellationToken ct = default)
    {
        return await WithConnectionAsync(
            async connection =>
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText = "SELECT " + BanColumns + " FROM bans WHERE ip = $ip LIMIT 1;";
                cmd.Parameters.AddWithValue("$ip", ip);

                await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
                return await reader.ReadAsync(ct).ConfigureAwait(false) ? ReadBan(reader) : null;
            },
            ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<BanEntry>> GetActiveBansAsync(CancellationToken ct = default)
    {
        return await WithConnectionAsync(
            async connection =>
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText =
                    "SELECT " + BanColumns + " FROM bans WHERE is_permanent = 1 OR expires_utc > $now ORDER BY banned_at_utc;";
                cmd.Parameters.AddWithValue("$now", ToDb(_timeProvider.GetUtcNow().UtcDateTime));

                var bans = new List<BanEntry>();
                await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
                while (await reader.ReadAsync(ct).ConfigureAwait(false))
                {
                    bans.Add(ReadBan(reader));
                }

                return (IReadOnlyList<BanEntry>)bans;
            },
            ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<BanEntry>> GetDueBansAsync(DateTime nowUtc, CancellationToken ct = default)
    {
        return await WithConnectionAsync(
            async connection =>
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText =
                    "SELECT " + BanColumns + " FROM bans WHERE is_permanent = 0 AND expires_utc <= $now ORDER BY banned_at_utc;";
                cmd.Parameters.AddWithValue("$now", ToDb(nowUtc));

                var bans = new List<BanEntry>();
                await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
                while (await reader.ReadAsync(ct).ConfigureAwait(false))
                {
                    bans.Add(ReadBan(reader));
                }

                return (IReadOnlyList<BanEntry>)bans;
            },
            ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task UpsertBanAsync(BanEntry ban, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(ban);
        await WithConnectionAsync(
            async connection =>
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText =
                    "INSERT INTO bans (ip, source, banned_at_utc, expires_utc, offense_count, is_permanent, note, port_scope) " +
                    "VALUES ($ip, $source, $banned, $expires, $offense, $permanent, $note, $portScope) " +
                    "ON CONFLICT(ip) DO UPDATE SET " +
                    "source = excluded.source, banned_at_utc = excluded.banned_at_utc, " +
                    "expires_utc = excluded.expires_utc, offense_count = excluded.offense_count, " +
                    "is_permanent = excluded.is_permanent, note = excluded.note, port_scope = excluded.port_scope;";
                cmd.Parameters.AddWithValue("$ip", ban.IpAddress);
                cmd.Parameters.AddWithValue("$source", (int)ban.Source);
                cmd.Parameters.AddWithValue("$banned", ToDb(ban.BannedAtUtc));
                cmd.Parameters.AddWithValue("$expires", ToDb(ban.ExpiresUtc));
                cmd.Parameters.AddWithValue("$offense", ban.OffenseCount);
                cmd.Parameters.AddWithValue("$permanent", ban.IsPermanent ? 1 : 0);
                cmd.Parameters.AddWithValue("$note", (object?)ban.Note ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$portScope", (object?)ban.PortScope ?? DBNull.Value);
                await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
                return true;
            },
            ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task RemoveBanAsync(string ip, CancellationToken ct = default)
    {
        await WithConnectionAsync(
            async connection =>
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText = "DELETE FROM bans WHERE ip = $ip;";
                cmd.Parameters.AddWithValue("$ip", ip);
                await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
                return true;
            },
            ct).ConfigureAwait(false);
    }

    // ---- offense counts ----

    /// <inheritdoc />
    public async Task<IReadOnlyList<OffenseCountEntry>> GetOffenseCountsAsync(CancellationToken ct = default)
    {
        return await WithConnectionAsync(
            async connection =>
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText = "SELECT ip, offense_count, last_utc FROM offense_counts;";

                var rows = new List<OffenseCountEntry>();
                await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
                while (await reader.ReadAsync(ct).ConfigureAwait(false))
                {
                    rows.Add(new OffenseCountEntry
                    {
                        IpAddress = reader.GetString(0),
                        Count = reader.GetInt32(1),
                        LastUtc = FromDb(reader.GetString(2)),
                    });
                }

                return (IReadOnlyList<OffenseCountEntry>)rows;
            },
            ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task SaveOffenseCountsAsync(IReadOnlyCollection<OffenseCountEntry> changed, IReadOnlyCollection<string> removed, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(changed);
        ArgumentNullException.ThrowIfNull(removed);
        if (changed.Count == 0 && removed.Count == 0)
        {
            return;
        }

        await WithConnectionAsync(
            async connection =>
            {
                await using var transaction = connection.BeginTransaction();
                await UpsertOffenseCountsAsync(connection, transaction, changed, ct).ConfigureAwait(false);

                await using (var cmd = connection.CreateCommand())
                {
                    cmd.Transaction = transaction;
                    cmd.CommandText = "DELETE FROM offense_counts WHERE ip = $ip;";
                    var ip = cmd.Parameters.Add("$ip", SqliteType.Text);
                    foreach (var value in removed)
                    {
                        ip.Value = value;
                        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
                    }
                }

                await transaction.CommitAsync(ct).ConfigureAwait(false);
                return true;
            },
            ct).ConfigureAwait(false);
    }

    private static async Task UpsertOffenseCountsAsync(SqliteConnection connection, SqliteTransaction transaction, IEnumerable<OffenseCountEntry> rows, CancellationToken ct)
    {
        await using var cmd = connection.CreateCommand();
        cmd.Transaction = transaction;
        cmd.CommandText =
            "INSERT INTO offense_counts (ip, offense_count, last_utc) VALUES ($ip, $count, $last) " +
            "ON CONFLICT(ip) DO UPDATE SET offense_count = excluded.offense_count, last_utc = excluded.last_utc;";
        var ip = cmd.Parameters.Add("$ip", SqliteType.Text);
        var count = cmd.Parameters.Add("$count", SqliteType.Integer);
        var last = cmd.Parameters.Add("$last", SqliteType.Text);
        foreach (var row in rows)
        {
            ip.Value = row.IpAddress;
            count.Value = row.Count;
            last.Value = ToDb(row.LastUtc);
            await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }
    }

    // ---- whitelist / blacklist ----

    /// <inheritdoc />
    public async Task<IReadOnlyList<string>> GetListAsync(ListKind kind, CancellationToken ct = default)
    {
        return await WithConnectionAsync(
            async connection =>
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText = "SELECT value FROM lists WHERE kind = $kind ORDER BY value;";
                cmd.Parameters.AddWithValue("$kind", (int)kind);

                var values = new List<string>();
                await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
                while (await reader.ReadAsync(ct).ConfigureAwait(false))
                {
                    values.Add(reader.GetString(0));
                }

                return (IReadOnlyList<string>)values;
            },
            ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task AddToListAsync(ListKind kind, string value, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        await WithConnectionAsync(
            async connection =>
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText =
                    "INSERT INTO lists (value, kind) " +
                    "SELECT $value, $kind WHERE NOT EXISTS (" +
                    "SELECT 1 FROM lists WHERE value = $value AND kind = $kind);";
                cmd.Parameters.AddWithValue("$value", value.Trim());
                cmd.Parameters.AddWithValue("$kind", (int)kind);
                await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
                return true;
            },
            ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task RemoveFromListAsync(ListKind kind, string value, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        await WithConnectionAsync(
            async connection =>
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText = "DELETE FROM lists WHERE kind = $kind AND value = $value;";
                cmd.Parameters.AddWithValue("$kind", (int)kind);
                cmd.Parameters.AddWithValue("$value", value.Trim());
                await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
                return true;
            },
            ct).ConfigureAwait(false);
    }

    // ---- ban history ----

    /// <inheritdoc />
    public async Task AddBanHistoryAsync(BanHistoryEntry entry, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(entry);
        await WithConnectionAsync(
            async connection =>
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText =
                    "INSERT INTO ban_history (ts_utc, action, ip, source, offense_count, is_permanent, duration, note) " +
                    "VALUES ($ts, $action, $ip, $source, $offense, $permanent, $duration, $note);";
                cmd.Parameters.AddWithValue("$ts", ToDb(entry.TimestampUtc));
                cmd.Parameters.AddWithValue("$action", (int)entry.Action);
                cmd.Parameters.AddWithValue("$ip", entry.IpAddress);
                cmd.Parameters.AddWithValue("$source", (int)entry.Source);
                cmd.Parameters.AddWithValue("$offense", entry.OffenseCount);
                cmd.Parameters.AddWithValue("$permanent", entry.IsPermanent ? 1 : 0);
                cmd.Parameters.AddWithValue("$duration", (object?)(entry.Duration?.Ticks) ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$note", (object?)entry.Note ?? DBNull.Value);
                await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
                return true;
            },
            ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<BanHistoryEntry>> GetBanHistoryAsync(int limit, CancellationToken ct = default)
    {
        var take = limit <= 0 ? 100 : Math.Min(limit, 1000);
        return await WithConnectionAsync(
            async connection =>
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText =
                    "SELECT ts_utc, action, ip, source, offense_count, is_permanent, duration, note FROM ban_history " +
                    "ORDER BY id DESC LIMIT $limit;";
                cmd.Parameters.AddWithValue("$limit", take);

                var rows = new List<BanHistoryEntry>();
                await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
                while (await reader.ReadAsync(ct).ConfigureAwait(false))
                {
                    rows.Add(new BanHistoryEntry
                    {
                        TimestampUtc = FromDb(reader.GetString(0)),
                        Action = (BanHistoryAction)reader.GetInt32(1),
                        IpAddress = reader.GetString(2),
                        Source = (ProtocolSource)reader.GetInt32(3),
                        OffenseCount = reader.GetInt32(4),
                        IsPermanent = reader.GetInt32(5) != 0,
                        Duration = reader.IsDBNull(6) ? null : TimeSpan.FromTicks(reader.GetInt64(6)),
                        Note = reader.IsDBNull(7) ? null : reader.GetString(7),
                    });
                }

                return (IReadOnlyList<BanHistoryEntry>)rows;
            },
            ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<int> CountBanHistoryAsync(CancellationToken ct = default)
    {
        return await WithConnectionAsync(
            async connection =>
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText = "SELECT COUNT(*) FROM ban_history;";
                var result = await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false);
                return Convert.ToInt32(result, CultureInfo.InvariantCulture);
            },
            ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<int> PruneBanHistoryAsync(DateTime olderThanUtc, int maxRows, CancellationToken ct = default)
    {
        return await WithConnectionAsync(
            async connection =>
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText =
                    "DELETE FROM ban_history WHERE id IN (" +
                    "SELECT id FROM ban_history WHERE ts_utc < $before ORDER BY ts_utc LIMIT $limit);";
                cmd.Parameters.AddWithValue("$before", ToDb(olderThanUtc));
                cmd.Parameters.AddWithValue("$limit", maxRows);
                return await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            },
            ct).ConfigureAwait(false);
    }

    // ---- daily statistics ----

    /// <inheritdoc />
    public async Task AddDailyStatsAsync(DateTime dayUtc, ProtocolSource source, int detectionsDelta, int bansDelta, CancellationToken ct = default)
    {
        var day = dayUtc.Date;
        await WithConnectionAsync(
            async connection =>
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText =
                    "INSERT INTO daily_stats (day_utc, source, detections, bans) VALUES ($day, $source, $detections, $bans) " +
                    "ON CONFLICT(day_utc, source) DO UPDATE SET " +
                    "detections = detections + $detections, bans = bans + $bans;";
                cmd.Parameters.AddWithValue("$day", ToDb(day));
                cmd.Parameters.AddWithValue("$source", (int)source);
                cmd.Parameters.AddWithValue("$detections", detectionsDelta);
                cmd.Parameters.AddWithValue("$bans", bansDelta);
                await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
                return true;
            },
            ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<DailyStatEntry>> GetDailyStatsAsync(DateTime sinceDayUtc, CancellationToken ct = default)
    {
        return await WithConnectionAsync(
            async connection =>
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText =
                    "SELECT day_utc, source, detections, bans FROM daily_stats WHERE day_utc >= $since ORDER BY day_utc, source;";
                cmd.Parameters.AddWithValue("$since", ToDb(sinceDayUtc.Date));

                var rows = new List<DailyStatEntry>();
                await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
                while (await reader.ReadAsync(ct).ConfigureAwait(false))
                {
                    rows.Add(new DailyStatEntry
                    {
                        DayUtc = FromDb(reader.GetString(0)),
                        Source = (ProtocolSource)reader.GetInt32(1),
                        Detections = reader.GetInt32(2),
                        Bans = reader.GetInt32(3),
                    });
                }

                return (IReadOnlyList<DailyStatEntry>)rows;
            },
            ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<TopOffenderEntry>> GetTopOffendersAsync(int limit, CancellationToken ct = default)
    {
        var take = limit <= 0 ? 10 : Math.Min(limit, 100);
        return await WithConnectionAsync(
            async connection =>
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText =
                    "SELECT ip, COUNT(*), MAX(offense_count), MAX(ts_utc) FROM ban_history " +
                    "WHERE action = 0 GROUP BY ip ORDER BY COUNT(*) DESC, MAX(ts_utc) DESC LIMIT $limit;";
                cmd.Parameters.AddWithValue("$limit", take);

                var rows = new List<TopOffenderEntry>();
                await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
                while (await reader.ReadAsync(ct).ConfigureAwait(false))
                {
                    rows.Add(new TopOffenderEntry
                    {
                        IpAddress = reader.GetString(0),
                        BanCount = reader.GetInt32(1),
                        MaxOffense = reader.GetInt32(2),
                        LastSeenUtc = FromDb(reader.GetString(3)),
                    });
                }

                return (IReadOnlyList<TopOffenderEntry>)rows;
            },
            ct).ConfigureAwait(false);
    }

    // ---- events ----

    /// <inheritdoc />
    public async Task AddEventAsync(LogEvent logEvent, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(logEvent);
        await WithConnectionAsync(
            async connection =>
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText =
                    "INSERT INTO events (ts_utc, level, source, ip, message) VALUES ($ts, $level, $source, $ip, $message);";
                cmd.Parameters.AddWithValue("$ts", ToDb(logEvent.TimestampUtc));
                cmd.Parameters.AddWithValue("$level", (int)logEvent.Level);
                cmd.Parameters.AddWithValue("$source", logEvent.Source is null ? (object)DBNull.Value : (int)logEvent.Source.Value);
                cmd.Parameters.AddWithValue("$ip", (object?)logEvent.IpAddress ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$message", logEvent.Message);
                await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            },
            ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<LogEvent>> GetEventsAsync(int limit, DateTime? sinceUtc = null, long? afterId = null, CancellationToken ct = default)
    {
        var take = limit <= 0 ? 200 : limit;
        return await WithConnectionAsync(
            async connection =>
            {
                await using var cmd = connection.CreateCommand();
                var where = new List<string>();
                if (sinceUtc is not null)
                {
                    where.Add("ts_utc >= $since");
                    cmd.Parameters.AddWithValue("$since", ToDb(sinceUtc.Value));
                }

                if (afterId is not null)
                {
                    where.Add("rowid > $after");
                    cmd.Parameters.AddWithValue("$after", afterId.Value);
                }

                cmd.CommandText =
                    "SELECT ts_utc, level, source, ip, message, rowid FROM events" +
                    (where.Count > 0 ? " WHERE " + string.Join(" AND ", where) : string.Empty) +
                    (afterId is not null ? " ORDER BY rowid DESC" : " ORDER BY ts_utc DESC") +
                    " LIMIT $limit;";
                cmd.Parameters.AddWithValue("$limit", take);

                var events = new List<LogEvent>();
                await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
                while (await reader.ReadAsync(ct).ConfigureAwait(false))
                {
                    events.Add(ReadEvent(reader));
                }

                return (IReadOnlyList<LogEvent>)events;
            },
            ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<LogEvent>> GetEventsAfterAsync(long afterId, int limit, CancellationToken ct = default)
    {
        var take = limit <= 0 ? 200 : limit;
        return await WithConnectionAsync(
            async connection =>
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText =
                    "SELECT ts_utc, level, source, ip, message, rowid FROM events WHERE rowid > $after ORDER BY rowid ASC LIMIT $limit;";
                cmd.Parameters.AddWithValue("$after", afterId);
                cmd.Parameters.AddWithValue("$limit", take);

                var events = new List<LogEvent>();
                await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
                while (await reader.ReadAsync(ct).ConfigureAwait(false))
                {
                    events.Add(ReadEvent(reader));
                }

                return (IReadOnlyList<LogEvent>)events;
            },
            ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task PruneEventsAsync(DateTime olderThanUtc, CancellationToken ct = default)
    {
        await WithConnectionAsync(
            async connection =>
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText = "DELETE FROM events WHERE ts_utc < $before;";
                cmd.Parameters.AddWithValue("$before", ToDb(olderThanUtc));
                await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            },
            ct).ConfigureAwait(false);
    }

    // ---- settings ----

    /// <inheritdoc />
    public async Task<IReadOnlyDictionary<string, string>> GetAllSettingsAsync(CancellationToken ct = default)
    {
        return await WithConnectionAsync(
            async connection =>
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText = "SELECT key, value FROM settings;";

                var settings = new Dictionary<string, string>(StringComparer.Ordinal);
                await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
                while (await reader.ReadAsync(ct).ConfigureAwait(false))
                {
                    settings[reader.GetString(0)] = reader.GetString(1);
                }

                return (IReadOnlyDictionary<string, string>)settings;
            },
            ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task SetSettingAsync(string key, string value, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(key))
        {
            throw new ArgumentException("A settings key is required.", nameof(key));
        }

        await WithConnectionAsync(
            async connection =>
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText =
                    "INSERT INTO settings (key, value) VALUES ($key, $value) " +
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value;";
                cmd.Parameters.AddWithValue("$key", key);
                cmd.Parameters.AddWithValue("$value", value);
                await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
                return true;
            },
            ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    /// <remarks>
    /// In WAL mode an update leaves the old row in the main file until a checkpoint. secure_delete
    /// zeroes what this write frees, and the checkpoint carries that into the main file; VACUUM
    /// goes further and also drops the copies earlier saves left in free pages and page slack,
    /// which no write can reach, as long as the file is small enough to rewrite during start-up.
    /// </remarks>
    public async Task SetSettingAndScrubAsync(string key, string value, CancellationToken ct = default)
    {
        await WithConnectionAsync(
            async connection =>
            {
                var secureDelete = await ReadPragmaAsync(connection, "secure_delete", ct).ConfigureAwait(false);
                await ExecuteNonQueryAsync(connection, "PRAGMA secure_delete=ON;", ct).ConfigureAwait(false);
                try
                {
                    await using var cmd = connection.CreateCommand();
                    cmd.CommandText =
                        "INSERT INTO settings (key, value) VALUES ($key, $value) " +
                        "ON CONFLICT(key) DO UPDATE SET value = excluded.value;";
                    cmd.Parameters.AddWithValue("$key", key);
                    cmd.Parameters.AddWithValue("$value", value);
                    await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
                }
                finally
                {
                    await ExecuteNonQueryAsync(connection, $"PRAGMA secure_delete={secureDelete};", ct).ConfigureAwait(false);
                }

                await TryScrubFilesAsync(connection, ct).ConfigureAwait(false);
                return true;
            },
            ct).ConfigureAwait(false);
    }

    /// <summary>Never throws but for a cancelled start: the new value is stored by now.</summary>
    private async Task TryScrubFilesAsync(SqliteConnection connection, CancellationToken ct)
    {
        try
        {
            var bytes = await ReadPragmaAsync(connection, "page_count", ct).ConfigureAwait(false)
                * await ReadPragmaAsync(connection, "page_size", ct).ConfigureAwait(false);
            if (bytes <= MaxBytesToVacuumAtStartup)
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText = "VACUUM;";
                cmd.CommandTimeout = ScrubCommandTimeoutSeconds;
                await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            }
            else
            {
                _logger.LogInformation(
                    "The database is {Bytes} bytes, too large to rewrite during start-up. Copies of old settings in free pages stay until SQLite reuses those pages.",
                    bytes);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _logger.LogWarning(ex, "Could not compact the database; copies of old settings may stay in its free pages.");
        }

        try
        {
            await using var cmd = connection.CreateCommand();
            cmd.CommandText = "PRAGMA wal_checkpoint(TRUNCATE);";
            cmd.CommandTimeout = ScrubCommandTimeoutSeconds;
            await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
            if (await reader.ReadAsync(ct).ConfigureAwait(false) && reader.GetInt32(0) != 0)
            {
                _logger.LogWarning("The database checkpoint was blocked; old settings stay in the main file until the next one.");
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _logger.LogWarning(ex, "Could not checkpoint the database; old settings stay in the main file until the next checkpoint.");
        }
    }

    private static async Task<long> ReadPragmaAsync(SqliteConnection connection, string name, CancellationToken ct)
    {
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = $"PRAGMA {name};";
        return Convert.ToInt64(await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false), CultureInfo.InvariantCulture);
    }

    // ---- plumbing ----

    private const string BanColumns =
        "ip, source, banned_at_utc, expires_utc, offense_count, is_permanent, note, port_scope";

    private async Task<T> WithConnectionAsync<T>(Func<SqliteConnection, Task<T>> action, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var connection = await EnsureInitializedLockedAsync(ct).ConfigureAwait(false);
            return await action(connection).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task WithConnectionAsync(Func<SqliteConnection, Task> action, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var connection = await EnsureInitializedLockedAsync(ct).ConfigureAwait(false);
            await action(connection).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<SqliteConnection> EnsureInitializedLockedAsync(CancellationToken ct)
    {
        if (_initialized && _connection is not null)
        {
            return _connection;
        }

        var directory = Path.GetDirectoryName(_databasePath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
            TryHardenDirectoryAcl(directory);
        }

        var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(ct).ConfigureAwait(false);

        try
        {
            await ExecuteNonQueryAsync(connection, "PRAGMA journal_mode=WAL;", ct).ConfigureAwait(false);
            // WAL + synchronous=NORMAL is crash-safe for the DB file and avoids an fsync per insert,
            // the dominant cost when a brute-force burst writes one row per attempt.
            await ExecuteNonQueryAsync(connection, "PRAGMA synchronous=NORMAL;", ct).ConfigureAwait(false);
            await ExecuteNonQueryAsync(connection, "PRAGMA temp_store=MEMORY;", ct).ConfigureAwait(false);
            await ExecuteNonQueryAsync(connection, $"PRAGMA busy_timeout={BusyTimeoutMs};", ct).ConfigureAwait(false);
            await ExecuteNonQueryAsync(connection, SchemaSql, ct).ConfigureAwait(false);
            await MigrateAsync(connection, ct).ConfigureAwait(false);
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }

        _connection = connection;
        _initialized = true;
        _logger.LogInformation("SqliteStore initialized at {DatabasePath}", _databasePath);
        return connection;
    }

    /// <summary>
    /// Brings an existing database up to <see cref="SchemaVersion"/> (tracked in PRAGMA user_version).
    /// v2: the events table gets an AUTOINCREMENT id so the GUI's event cursor never sees an id
    /// reused after pruning, and raw log lines stored by older versions are discarded.
    /// v4: offense counts move from one settings row into their own table.
    /// v5: bans get a port scope. Rows from before it have none, and keep following BlockedPorts.
    /// </summary>
    private async Task MigrateAsync(SqliteConnection connection, CancellationToken ct)
    {
        int version;
        await using (var cmd = connection.CreateCommand())
        {
            cmd.CommandText = "PRAGMA user_version;";
            version = Convert.ToInt32(await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false), CultureInfo.InvariantCulture);
        }

        if (version >= SchemaVersion)
        {
            return;
        }

        string? eventsSql;
        await using (var cmd = connection.CreateCommand())
        {
            cmd.CommandText = "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'events';";
            eventsSql = await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false) as string;
        }

        if (eventsSql is not null && !eventsSql.Contains("AUTOINCREMENT", StringComparison.OrdinalIgnoreCase))
        {
            await ExecuteNonQueryAsync(
                connection,
                """
                BEGIN;
                CREATE TABLE events_new (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  ts_utc TEXT NOT NULL,
                  level INTEGER NOT NULL,
                  source INTEGER,
                  ip TEXT,
                  message TEXT
                );
                INSERT INTO events_new (ts_utc, level, source, ip, message)
                  SELECT ts_utc, level, source, ip, message FROM events ORDER BY rowid;
                DROP TABLE events;
                ALTER TABLE events_new RENAME TO events;
                CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts_utc);
                COMMIT;
                """,
                ct).ConfigureAwait(false);
        }

        await ImportOffenseCountsBlobAsync(connection, ct).ConfigureAwait(false);
        await AddBanPortScopeAsync(connection, ct).ConfigureAwait(false);

        await ExecuteNonQueryAsync(
            connection,
            $"UPDATE failed_logins SET raw = NULL WHERE raw IS NOT NULL; PRAGMA user_version = {SchemaVersion};",
            ct).ConfigureAwait(false);
    }

    /// <summary>Adds the column to a bans table from before v5; a new table has it already.</summary>
    private static async Task AddBanPortScopeAsync(SqliteConnection connection, CancellationToken ct)
    {
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM pragma_table_info('bans') WHERE name = 'port_scope';";
        if (Convert.ToInt32(await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false), CultureInfo.InvariantCulture) == 0)
        {
            await ExecuteNonQueryAsync(connection, "ALTER TABLE bans ADD COLUMN port_scope TEXT;", ct).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Moves the offense counts that versions before schema 4 kept in one JSON settings row into the
    /// offense_counts table. A row that cannot be read costs escalation memory, not the service: it
    /// is dropped with a warning, because a store that refuses to open would stop all protection.
    /// </summary>
    private async Task ImportOffenseCountsBlobAsync(SqliteConnection connection, CancellationToken ct)
    {
        string? json;
        await using (var cmd = connection.CreateCommand())
        {
            cmd.CommandText = "SELECT value FROM settings WHERE key = $key;";
            cmd.Parameters.AddWithValue("$key", LegacyOffenseCountsKey);
            json = await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false) as string;
        }

        if (json is null)
        {
            return;
        }

        var rows = new List<OffenseCountEntry>();
        try
        {
            var legacy = JsonSerializer.Deserialize<Dictionary<string, LegacyOffenseCount>>(json);
            foreach (var (ip, record) in legacy ?? [])
            {
                if (record is { Count: > 0 })
                {
                    rows.Add(new OffenseCountEntry { IpAddress = ip, Count = record.Count, LastUtc = record.LastUtc });
                }
            }
        }
        catch (JsonException ex)
        {
            _logger.LogWarning(ex, "Discarding unreadable offense counts; tier escalation restarts for the IPs without an active ban.");
        }

        // One transaction: an interrupted upgrade finds the row still there and starts over.
        await using var transaction = connection.BeginTransaction();
        await UpsertOffenseCountsAsync(connection, transaction, rows, ct).ConfigureAwait(false);
        await using (var cmd = connection.CreateCommand())
        {
            cmd.Transaction = transaction;
            cmd.CommandText = "DELETE FROM settings WHERE key = $key;";
            cmd.Parameters.AddWithValue("$key", LegacyOffenseCountsKey);
            await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }

        await transaction.CommitAsync(ct).ConfigureAwait(false);
        _logger.LogInformation("Moved {Count} offense count(s) into their own table.", rows.Count);
    }

    private const int SchemaVersion = 5;

    private const string LegacyOffenseCountsKey = "offense_counts";

    private sealed record LegacyOffenseCount(int Count, DateTime LastUtc);

    private static async Task ExecuteNonQueryAsync(SqliteConnection connection, string sql, CancellationToken ct)
    {
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = sql;
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Best-effort ACL hardening of the data directory (review S-M5): only SYSTEM and
    /// Administrators keep access, so a local standard user cannot pre-create or tamper
    /// with the database (e.g. seeding a whitelist) while it is absent. Only applied to
    /// the production location under %ProgramData%; failures are logged and never block
    /// startup. The installer applies the same ACL via icacls.
    /// </summary>
    private void TryHardenDirectoryAcl(string directoryPath)
    {
        try
        {
            var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            if (string.IsNullOrEmpty(programData)
                || !directoryPath.StartsWith(programData.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase))
            {
                // Not the production location (e.g. unit tests on temp files): leave ACLs alone.
                return;
            }

            // "P" = protected DACL (no inheritance, mirrors the installer's
            // icacls /inheritance:r); SYSTEM + Administrators full control only.
            if (!AclInterop.ConvertStringSecurityDescriptorToSecurityDescriptor(
                    "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", 1, out var securityDescriptor, IntPtr.Zero)
                || securityDescriptor == IntPtr.Zero)
            {
                _logger.LogWarning(
                    "Could not build the data-directory security descriptor (Win32 error {Error}); " +
                    "ACL hardening skipped — the installer's icacls step is the fallback.",
                    Marshal.GetLastWin32Error());
                return;
            }

            try
            {
                // SetNamedSecurityInfo wants the DACL itself, not the security descriptor —
                // passing the SD pointer silently no-ops (verified live), so extract first.
                if (!AclInterop.GetSecurityDescriptorDacl(securityDescriptor, out var daclPresent, out var dacl, out _)
                    || !daclPresent || dacl == IntPtr.Zero)
                {
                    _logger.LogWarning(
                        "Could not extract the DACL from the security descriptor (Win32 error {Error}); " +
                        "data-directory ACL hardening skipped.",
                        Marshal.GetLastWin32Error());
                    return;
                }

                var result = AclInterop.SetNamedSecurityInfo(
                    directoryPath,
                    AclInterop.SeFileObject,
                    AclInterop.DaclSecurityInformation,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    dacl,
                    IntPtr.Zero);
                if (result != 0)
                {
                    _logger.LogWarning(
                        "SetNamedSecurityInfo on {Directory} returned Win32 error {Error}; " +
                        "data-directory ACL hardening was not applied.",
                        directoryPath,
                        result);
                }
            }
            finally
            {
                AclInterop.LocalFree(securityDescriptor);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not harden the WinGuard data directory ACL.");
        }
    }

    private static class AclInterop
    {
        internal const uint SeFileObject = 1;
        internal const uint DaclSecurityInformation = 0x00000004;

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
            string stringSecurityDescriptor,
            int stringSDRevision,
            out IntPtr securityDescriptor,
            IntPtr securityDescriptorSize);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetSecurityDescriptorDacl(
            IntPtr securityDescriptor,
            [MarshalAs(UnmanagedType.Bool)] out bool daclPresent,
            out IntPtr dacl,
            [MarshalAs(UnmanagedType.Bool)] out bool daclDefaulted);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint SetNamedSecurityInfo(
            string objectName,
            uint objectType,
            uint securityInfo,
            IntPtr owner,
            IntPtr group,
            IntPtr dacl,
            IntPtr sacl);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr LocalFree(IntPtr hMem);
    }

    private static BanEntry ReadBan(SqliteDataReader reader) => new()
    {
        IpAddress = reader.GetString(0),
        Source = (ProtocolSource)reader.GetInt32(1),
        BannedAtUtc = FromDb(reader.GetString(2)),
        ExpiresUtc = FromDb(reader.GetString(3)),
        OffenseCount = reader.GetInt32(4),
        IsPermanent = reader.GetInt32(5) != 0,
        Note = reader.IsDBNull(6) ? null : reader.GetString(6),
        PortScope = reader.IsDBNull(7) ? null : reader.GetString(7),
    };

    private static LogEvent ReadEvent(SqliteDataReader reader) => new()
    {
        Id = reader.FieldCount > 5 ? reader.GetInt64(5) : 0,
        TimestampUtc = FromDb(reader.GetString(0)),
        Level = (LogEventLevel)reader.GetInt32(1),
        Source = reader.IsDBNull(2) ? null : (ProtocolSource)reader.GetInt32(2),
        IpAddress = reader.IsDBNull(3) ? null : reader.GetString(3),
        Message = reader.GetString(4),
    };

    private static string ToDb(DateTime value)
    {
        var utc = value.Kind == DateTimeKind.Local
            ? value.ToUniversalTime()
            : DateTime.SpecifyKind(value, DateTimeKind.Utc);
        return utc.ToString("o", CultureInfo.InvariantCulture);
    }

    private static DateTime FromDb(string value)
    {
        if (!DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed))
        {
            return DateTime.MinValue;
        }

        return parsed.Kind == DateTimeKind.Local
            ? parsed.ToUniversalTime()
            : DateTime.SpecifyKind(parsed, DateTimeKind.Utc);
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            if (_connection is not null)
            {
                await _connection.DisposeAsync().ConfigureAwait(false);
                _connection = null;
            }

            _initialized = false;
        }
        finally
        {
            _gate.Release();
            _gate.Dispose();
        }
    }

    private const string SchemaSql = """
        CREATE TABLE IF NOT EXISTS failed_logins (
          ip TEXT NOT NULL,
          source INTEGER NOT NULL,
          ts_utc TEXT NOT NULL,
          user TEXT,
          raw TEXT
        );
        CREATE INDEX IF NOT EXISTS ix_fl_ip_ts ON failed_logins(ip, ts_utc);
        CREATE INDEX IF NOT EXISTS ix_fl_ts ON failed_logins(ts_utc);
        CREATE INDEX IF NOT EXISTS ix_fl_source_ts ON failed_logins(source, ts_utc);

        CREATE TABLE IF NOT EXISTS bans (
          ip TEXT PRIMARY KEY,
          source INTEGER NOT NULL,
          banned_at_utc TEXT NOT NULL,
          expires_utc TEXT NOT NULL,
          offense_count INTEGER NOT NULL DEFAULT 1,
          is_permanent INTEGER NOT NULL DEFAULT 0,
          note TEXT,
          port_scope TEXT
        );

        CREATE TABLE IF NOT EXISTS lists (
          value TEXT NOT NULL,
          kind  INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts_utc TEXT NOT NULL,
          level INTEGER NOT NULL,
          source INTEGER,
          ip TEXT,
          message TEXT
        );

        CREATE TABLE IF NOT EXISTS settings (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ban_history (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts_utc TEXT NOT NULL,
          action INTEGER NOT NULL,
          ip TEXT NOT NULL,
          source INTEGER NOT NULL,
          offense_count INTEGER NOT NULL DEFAULT 1,
          is_permanent INTEGER NOT NULL DEFAULT 0,
          duration INTEGER,
          note TEXT
        );
        CREATE INDEX IF NOT EXISTS ix_ban_history_ts ON ban_history(ts_utc);
        CREATE INDEX IF NOT EXISTS ix_ban_history_ip_ts ON ban_history(ip, ts_utc);
        CREATE INDEX IF NOT EXISTS ix_ban_history_top ON ban_history(ip, offense_count, ts_utc) WHERE action = 0;

        CREATE TABLE IF NOT EXISTS offense_counts (
          ip TEXT PRIMARY KEY,
          offense_count INTEGER NOT NULL,
          last_utc TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS daily_stats (
          day_utc TEXT NOT NULL,
          source INTEGER NOT NULL,
          detections INTEGER NOT NULL DEFAULT 0,
          bans INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY (day_utc, source)
        );

        CREATE INDEX IF NOT EXISTS ix_bans_expires ON bans(expires_utc);
        CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts_utc);
        """;
}