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
            }

            await using (var check = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString()))
            {
                await check.OpenAsync();
                await using var cmd = check.CreateCommand();
                cmd.CommandText = "PRAGMA user_version;";
                Assert.Equal(2L, (long)(await cmd.ExecuteScalarAsync())!);
                cmd.CommandText = "SELECT COUNT(*) FROM failed_logins WHERE raw IS NOT NULL;";
                Assert.Equal(0L, (long)(await cmd.ExecuteScalarAsync())!);
            }
        }
        finally
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
}
