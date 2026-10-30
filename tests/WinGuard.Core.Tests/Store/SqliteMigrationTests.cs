using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using WinGuard.Core.Model;
using WinGuard.Core.Store;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>Opening a database written by an earlier release upgrades it in place.</summary>
public class SqliteMigrationTests
{
    [Fact]
    public async Task A_version_1_database_is_upgraded_and_keeps_its_data()
    {
        var dir = Path.Combine(Path.GetTempPath(), "winguard-mig-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "old.db");
        try
        {
            // The schema as releases up to 0.1.4 created it: events without an id column.
            await using (var legacy = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString()))
            {
                await legacy.OpenAsync();
                await using var cmd = legacy.CreateCommand();
                cmd.CommandText = """
                    CREATE TABLE failed_logins (ip TEXT NOT NULL, source INTEGER NOT NULL, ts_utc TEXT NOT NULL, user TEXT, raw TEXT);
                    CREATE TABLE bans (ip TEXT PRIMARY KEY, source INTEGER NOT NULL, banned_at_utc TEXT NOT NULL, expires_utc TEXT NOT NULL,
                                       offense_count INTEGER NOT NULL DEFAULT 1, is_permanent INTEGER NOT NULL DEFAULT 0, note TEXT);
                    CREATE TABLE lists (value TEXT NOT NULL, kind INTEGER NOT NULL);
                    CREATE TABLE events (ts_utc TEXT NOT NULL, level INTEGER NOT NULL, source INTEGER, ip TEXT, message TEXT);
                    CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                    INSERT INTO events (ts_utc, level, source, ip, message) VALUES ('2026-01-01T00:00:00.0000000Z', 1, 0, '203.0.113.5', 'first');
                    INSERT INTO events (ts_utc, level, source, ip, message) VALUES ('2026-01-01T00:00:01.0000000Z', 1, 0, '203.0.113.5', 'second');
                    INSERT INTO failed_logins (ip, source, ts_utc, user, raw) VALUES ('203.0.113.5', 0, '2026-01-01T00:00:00.0000000Z', 'admin', 'raw line with a typed secret');
                    INSERT INTO lists (value, kind) VALUES ('198.51.100.0/24', 0);
                    """;
                await cmd.ExecuteNonQueryAsync();
            }

            await using (var store = new SqliteStore(path, NullLogger<SqliteStore>.Instance))
            {
                await store.InitializeAsync();

                var events = await store.GetEventsAsync(10);
                Assert.Equal(new[] { "second", "first" }, events.Select(e => e.Message));
                Assert.All(events, e => Assert.True(e.Id > 0));
                Assert.Equal(new[] { "198.51.100.0/24" }, await store.GetListAsync(ListKind.Whitelist));

                // Ids keep growing even after the table is emptied (the reason for the migration).
                var cursor = events.Max(e => e.Id);
                await store.PruneEventsAsync(DateTime.UtcNow.AddYears(10));
                await store.AddEventAsync(new LogEvent { TimestampUtc = DateTime.UtcNow, Message = "after prune" });
                var fresh = await store.GetEventsAsync(10, null, cursor);
                Assert.Single(fresh);
                Assert.True(fresh[0].Id > cursor);

                // v3: the statistics/history tables are usable right after the upgrade.
                await store.AddBanHistoryAsync(new BanHistoryEntry
                {
                    TimestampUtc = DateTime.UtcNow,
                    Action = BanHistoryAction.Banned,
                    IpAddress = "203.0.113.5",
                    Source = ProtocolSource.Rdp,
                    OffenseCount = 1,
                    Duration = TimeSpan.FromHours(24),
                });
                var history = await store.GetBanHistoryAsync(10);
                Assert.Single(history);
                Assert.Equal(BanHistoryAction.Banned, history[0].Action);
                Assert.Equal(TimeSpan.FromHours(24), history[0].Duration);

                await store.AddDailyStatsAsync(DateTime.UtcNow, ProtocolSource.Rdp, 5, 1);
                var stats = await store.GetDailyStatsAsync(DateTime.UtcNow.AddDays(-1));
                Assert.Single(stats);
                Assert.Equal(5, stats[0].Detections);
                Assert.Equal(1, stats[0].Bans);

                var offenders = await store.GetTopOffendersAsync(10);
                Assert.Single(offenders);
                Assert.Equal("203.0.113.5", offenders[0].IpAddress);
            }

            await using (var check = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString()))
            {
                await check.OpenAsync();
                await using var cmd = check.CreateCommand();
                cmd.CommandText = "PRAGMA user_version;";
                Assert.Equal(4L, (long)(await cmd.ExecuteScalarAsync())!);
                cmd.CommandText = "SELECT COUNT(*) FROM failed_logins WHERE raw IS NOT NULL;";
                Assert.Equal(0L, (long)(await cmd.ExecuteScalarAsync())!);
            }
        }
        finally
        {
            DeleteDirectory(dir);
        }
    }

    [Fact]
    public async Task A_version_3_database_gets_its_offense_counts_moved_out_of_the_settings_row()
    {
        var path = await CreateVersion3DatabaseAsync(
            """{"203.0.113.5":{"Count":3,"LastUtc":"2026-05-01T10:00:00.0000000Z"},"2001:db8:1:2::/64":{"Count":1,"LastUtc":"2026-05-02T10:00:00.0000000Z"},"203.0.113.6":{"Count":0,"LastUtc":"2026-05-02T10:00:00.0000000Z"}}""");
        try
        {
            await using (var store = new SqliteStore(path, NullLogger<SqliteStore>.Instance))
            {
                var counts = await store.GetOffenseCountsAsync();

                Assert.Equal(2, counts.Count);
                var entry = Assert.Single(counts, c => c.IpAddress == "203.0.113.5");
                Assert.Equal(3, entry.Count);
                Assert.Equal(new DateTime(2026, 5, 1, 10, 0, 0, DateTimeKind.Utc), entry.LastUtc);
                Assert.Contains(counts, c => c.IpAddress == "2001:db8:1:2::/64" && c.Count == 1);

                var settings = await store.GetAllSettingsAsync();
                Assert.False(settings.ContainsKey("offense_counts"));
                Assert.Equal("kept", settings["other"]);
            }

            // Opening it again changes nothing, and the rows are ordinary rows from now on.
            await using (var store = new SqliteStore(path, NullLogger<SqliteStore>.Instance))
            {
                Assert.Equal(2, (await store.GetOffenseCountsAsync()).Count);
            }

            Assert.Equal(4L, await ReadUserVersionAsync(path));
        }
        finally
        {
            DeleteDirectory(Path.GetDirectoryName(path)!);
        }
    }

    [Theory]
    [InlineData("{ this is not json")]
    [InlineData("[1, 2, 3]")]
    [InlineData("""{"203.0.113.5":{"Count":"many"}}""")]
    public async Task An_unreadable_offense_blob_costs_the_counts_not_the_service(string blob)
    {
        var path = await CreateVersion3DatabaseAsync(blob);
        try
        {
            await using var store = new SqliteStore(path, NullLogger<SqliteStore>.Instance);

            Assert.Empty(await store.GetOffenseCountsAsync());
            Assert.False((await store.GetAllSettingsAsync()).ContainsKey("offense_counts"));
            Assert.Equal(4L, await ReadUserVersionAsync(path));
        }
        finally
        {
            DeleteDirectory(Path.GetDirectoryName(path)!);
        }
    }

    [Fact]
    public async Task A_version_3_database_with_no_offense_blob_upgrades_cleanly()
    {
        var path = await CreateVersion3DatabaseAsync(blob: null);
        try
        {
            await using var store = new SqliteStore(path, NullLogger<SqliteStore>.Instance);

            Assert.Empty(await store.GetOffenseCountsAsync());
            Assert.Equal(4L, await ReadUserVersionAsync(path));
        }
        finally
        {
            DeleteDirectory(Path.GetDirectoryName(path)!);
        }
    }

    /// <summary>The schema as release 0.2.0 left it, with the offense counts in a settings row.</summary>
    private static async Task<string> CreateVersion3DatabaseAsync(string? blob)
    {
        var dir = Path.Combine(Path.GetTempPath(), "winguard-mig-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "old.db");

        await using var legacy = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString());
        await legacy.OpenAsync();
        await using var cmd = legacy.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE failed_logins (ip TEXT NOT NULL, source INTEGER NOT NULL, ts_utc TEXT NOT NULL, user TEXT, raw TEXT);
            CREATE TABLE bans (ip TEXT PRIMARY KEY, source INTEGER NOT NULL, banned_at_utc TEXT NOT NULL, expires_utc TEXT NOT NULL,
                               offense_count INTEGER NOT NULL DEFAULT 1, is_permanent INTEGER NOT NULL DEFAULT 0, note TEXT);
            CREATE TABLE lists (value TEXT NOT NULL, kind INTEGER NOT NULL);
            CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts_utc TEXT NOT NULL, level INTEGER NOT NULL, source INTEGER, ip TEXT, message TEXT);
            CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            INSERT INTO settings (key, value) VALUES ('other', 'kept');
            PRAGMA user_version = 3;
            """;
        await cmd.ExecuteNonQueryAsync();

        if (blob is not null)
        {
            cmd.CommandText = "INSERT INTO settings (key, value) VALUES ('offense_counts', $blob);";
            cmd.Parameters.AddWithValue("$blob", blob);
            await cmd.ExecuteNonQueryAsync();
        }

        return path;
    }

    private static async Task<long> ReadUserVersionAsync(string path)
    {
        await using var check = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString());
        await check.OpenAsync();
        await using var cmd = check.CreateCommand();
        cmd.CommandText = "PRAGMA user_version;";
        return (long)(await cmd.ExecuteScalarAsync())!;
    }

    private static void DeleteDirectory(string dir)
    {
        SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(dir, recursive: true);
        }
        catch (IOException)
        {
            // Best effort.
        }
    }
}
