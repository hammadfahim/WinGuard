using System.Globalization;
using System.Runtime.InteropServices;
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
public sealed class SqliteStore : IStore, IAsyncDisposable
{
    private const int BusyTimeoutMs = 5_000;

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
                    "INSERT INTO failed_logins (ip, source, ts_utc, user, raw) VALUES ($ip, $source, $ts, $user, $raw);";
                cmd.Parameters.AddWithValue("$ip", failed.IpAddress);
                cmd.Parameters.AddWithValue("$source", (int)failed.Source);
                cmd.Parameters.AddWithValue("$ts", ToDb(failed.TimestampUtc));
                cmd.Parameters.AddWithValue("$user", (object?)failed.UserName ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$raw", failed.RawLog);
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
    public async Task<FailedLogin?> GetRecentFailedLoginAsync(string ip, ProtocolSource source, DateTime sinceUtc, CancellationToken ct = default)
    {
        return await WithConnectionAsync(
            async connection =>
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText =
                    "SELECT ip, source, ts_utc, user, raw FROM failed_logins " +
                    "WHERE ip = $ip AND source = $source AND ts_utc >= $since " +
                    "ORDER BY ts_utc DESC LIMIT 1;";
                cmd.Parameters.AddWithValue("$ip", ip);
                cmd.Parameters.AddWithValue("$source", (int)source);
                cmd.Parameters.AddWithValue("$since", ToDb(sinceUtc));

                await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
                if (!await reader.ReadAsync(ct).ConfigureAwait(false))
                {
                    return null;
                }

                return ReadFailedLogin(reader);
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
                    "INSERT INTO bans (ip, source, banned_at_utc, expires_utc, offense_count, is_permanent, note) " +
                    "VALUES ($ip, $source, $banned, $expires, $offense, $permanent, $note) " +
                    "ON CONFLICT(ip) DO UPDATE SET " +
                    "source = excluded.source, banned_at_utc = excluded.banned_at_utc, " +
                    "expires_utc = excluded.expires_utc, offense_count = excluded.offense_count, " +
                    "is_permanent = excluded.is_permanent, note = excluded.note;";
                cmd.Parameters.AddWithValue("$ip", ban.IpAddress);
                cmd.Parameters.AddWithValue("$source", (int)ban.Source);
                cmd.Parameters.AddWithValue("$banned", ToDb(ban.BannedAtUtc));
                cmd.Parameters.AddWithValue("$expires", ToDb(ban.ExpiresUtc));
                cmd.Parameters.AddWithValue("$offense", ban.OffenseCount);
                cmd.Parameters.AddWithValue("$permanent", ban.IsPermanent ? 1 : 0);
                cmd.Parameters.AddWithValue("$note", (object?)ban.Note ?? DBNull.Value);
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
    public async Task<IReadOnlyList<LogEvent>> GetEventsAsync(int limit, DateTime? sinceUtc = null, CancellationToken ct = default)
    {
        var take = limit <= 0 ? 200 : limit;
        return await WithConnectionAsync(
            async connection =>
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText = sinceUtc is null
                    ? "SELECT ts_utc, level, source, ip, message FROM events ORDER BY ts_utc DESC LIMIT $limit;"
                    : "SELECT ts_utc, level, source, ip, message FROM events WHERE ts_utc >= $since ORDER BY ts_utc DESC LIMIT $limit;";
                cmd.Parameters.AddWithValue("$limit", take);
                if (sinceUtc is not null)
                {
                    cmd.Parameters.AddWithValue("$since", ToDb(sinceUtc.Value));
                }

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

    // ---- plumbing ----

    private const string BanColumns =
        "ip, source, banned_at_utc, expires_utc, offense_count, is_permanent, note";

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
            await ExecuteNonQueryAsync(connection, $"PRAGMA busy_timeout={BusyTimeoutMs};", ct).ConfigureAwait(false);
            await ExecuteNonQueryAsync(connection, SchemaSql, ct).ConfigureAwait(false);
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
                || !directoryPath.StartsWith(programData, StringComparison.OrdinalIgnoreCase))
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

    private static FailedLogin ReadFailedLogin(SqliteDataReader reader) => new()
    {
        IpAddress = reader.GetString(0),
        Source = (ProtocolSource)reader.GetInt32(1),
        TimestampUtc = FromDb(reader.GetString(2)),
        UserName = reader.IsDBNull(3) ? null : reader.GetString(3),
        RawLog = reader.IsDBNull(4) ? string.Empty : reader.GetString(4),
    };

    private static BanEntry ReadBan(SqliteDataReader reader) => new()
    {
        IpAddress = reader.GetString(0),
        Source = (ProtocolSource)reader.GetInt32(1),
        BannedAtUtc = FromDb(reader.GetString(2)),
        ExpiresUtc = FromDb(reader.GetString(3)),
        OffenseCount = reader.GetInt32(4),
        IsPermanent = reader.GetInt32(5) != 0,
        Note = reader.IsDBNull(6) ? null : reader.GetString(6),
    };

    private static LogEvent ReadEvent(SqliteDataReader reader) => new()
    {
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
          note TEXT
        );

        CREATE TABLE IF NOT EXISTS lists (
          value TEXT NOT NULL,
          kind  INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS events (
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

        CREATE INDEX IF NOT EXISTS ix_bans_expires ON bans(expires_utc);
        CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts_utc);
        """;
}