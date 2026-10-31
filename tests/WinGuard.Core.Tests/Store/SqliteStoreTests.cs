using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Model;
using WinGuard.Core.Store;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>Tests for the SQLite persistence layer (PLAN.md §3).</summary>
public sealed class SqliteStoreTests
{
    // ---------- schema ----------

    [Fact]
    public async Task Initialize_is_idempotent()
    {
        await WithStoreAsync(async store =>
        {
            await store.InitializeAsync();
            await store.InitializeAsync();

            await store.AddFailedLoginAsync(Failed("1.2.3.4", DateTime.UtcNow));
            Assert.Equal(1, await store.CountFailedLoginsSinceAsync(DateTime.MinValue));
        });
    }

    // ---------- failed_logins ----------

    [Fact]
    public async Task Failed_login_users_are_distinct_recent_and_cross_source()
    {
        await WithStoreAsync(async store =>
        {
            var now = DateTime.UtcNow;
            await store.AddFailedLoginAsync(Named("1.2.3.4", now.AddMinutes(-1), ProtocolSource.Rdp, "alice"));
            await store.AddFailedLoginAsync(Named("1.2.3.4", now.AddMinutes(-2), ProtocolSource.Ftp, "alice"));
            await store.AddFailedLoginAsync(Named("1.2.3.4", now.AddMinutes(-3), ProtocolSource.Ftp, "bob"));
            await store.AddFailedLoginAsync(Named("1.2.3.4", now.AddMinutes(-3), ProtocolSource.Rdp, null));
            await store.AddFailedLoginAsync(Named("1.2.3.4", now.AddMinutes(-30), ProtocolSource.Rdp, "old"));
            await store.AddFailedLoginAsync(Named("5.6.7.8", now.AddMinutes(-1), ProtocolSource.Rdp, "other"));

            var users = await store.GetFailedLoginUsersAsync("1.2.3.4", now.AddMinutes(-10));

            Assert.Equal(new[] { "alice", "bob" }, users.OrderBy(user => user, StringComparer.Ordinal));
        });
    }

    [Fact]
    public async Task Naming_a_failed_login_fills_the_newest_nameless_row_of_that_source()
    {
        await WithStoreAsync(async store =>
        {
            var now = DateTime.UtcNow;
            await store.AddFailedLoginAsync(Named("1.2.3.4", now.AddMinutes(-20), ProtocolSource.Rdp, null));
            await store.AddFailedLoginAsync(Named("1.2.3.4", now.AddSeconds(-3), ProtocolSource.Rdp, "named"));
            await store.AddFailedLoginAsync(Named("1.2.3.4", now.AddSeconds(-2), ProtocolSource.Rdp, null));
            await store.AddFailedLoginAsync(Named("1.2.3.4", now.AddSeconds(-1), ProtocolSource.Ftp, null));

            await store.SetFailedLoginUserAsync("1.2.3.4", ProtocolSource.Rdp, "alice", now.AddMinutes(-1));

            Assert.Equal(new[] { "alice", "named" }, (await store.GetFailedLoginUsersAsync("1.2.3.4", now.AddMinutes(-1))).OrderBy(user => user, StringComparer.Ordinal));
            Assert.Equal(4, await store.CountFailedLoginsSinceAsync(DateTime.MinValue));

            // Nothing nameless left in range: a no-op, not a rename of an older or named row.
            await store.SetFailedLoginUserAsync("1.2.3.4", ProtocolSource.Rdp, "bob", now.AddMinutes(-1));
            Assert.DoesNotContain("bob", await store.GetFailedLoginUsersAsync("1.2.3.4", DateTime.MinValue));
        });
    }

    private static FailedLogin Named(string ip, DateTime at, ProtocolSource source, string? user)
    {
        var failed = Failed(ip, at, source);
        failed.UserName = user;
        return failed;
    }

    [Fact]
    public async Task Count_failed_logins_respects_since_and_source()
    {
        await WithStoreAsync(async store =>
        {
            var now = DateTime.UtcNow;
            await store.AddFailedLoginAsync(Failed("1.2.3.4", now.AddMinutes(-30), ProtocolSource.Rdp));
            await store.AddFailedLoginAsync(Failed("1.2.3.4", now.AddMinutes(-1), ProtocolSource.Rdp));
            await store.AddFailedLoginAsync(Failed("1.2.3.4", now.AddMinutes(-20), ProtocolSource.Ftp));
            await store.AddFailedLoginAsync(Failed("5.6.7.8", now.AddMinutes(-1), ProtocolSource.Rdp));

            Assert.Equal(1, await store.CountFailedLoginsAsync("1.2.3.4", now.AddMinutes(-10)));
            Assert.Equal(3, await store.CountFailedLoginsAsync("1.2.3.4", now.AddMinutes(-60)));
            Assert.Equal(2, await store.CountFailedLoginsAsync("1.2.3.4", now.AddMinutes(-60), ProtocolSource.Rdp));
        });
    }

    [Fact]
    public async Task Add_and_count_returns_the_window_count_and_remove_latest_takes_one_back()
    {
        await WithStoreAsync(async store =>
        {
            var now = DateTime.UtcNow;
            await store.AddFailedLoginAsync(Failed("1.2.3.4", now.AddMinutes(-30), ProtocolSource.Rdp));
            await store.AddFailedLoginAsync(Failed("1.2.3.4", now.AddMinutes(-1), ProtocolSource.Ftp));

            var since = now.AddMinutes(-10);
            Assert.Equal(1, await store.AddFailedLoginAndCountAsync(Failed("1.2.3.4", now.AddMinutes(-2), ProtocolSource.Rdp), since));
            Assert.Equal(2, await store.AddFailedLoginAndCountAsync(Failed("1.2.3.4", now, ProtocolSource.Rdp), since));

            await store.RemoveLatestFailedLoginAsync("1.2.3.4", ProtocolSource.Rdp);
            Assert.Equal(1, await store.CountFailedLoginsAsync("1.2.3.4", since, ProtocolSource.Rdp));
            Assert.Equal(1, await store.CountFailedLoginsAsync("1.2.3.4", since, ProtocolSource.Ftp));

            await store.RemoveLatestFailedLoginAsync("9.9.9.9", ProtocolSource.Rdp); // no-op
        });
    }

    [Fact]
    public async Task Clear_failed_logins_removes_only_that_ip()
    {
        await WithStoreAsync(async store =>
        {
            var now = DateTime.UtcNow;
            await store.AddFailedLoginAsync(Failed("1.2.3.4", now));
            await store.AddFailedLoginAsync(Failed("1.2.3.4", now));
            await store.AddFailedLoginAsync(Failed("5.6.7.8", now));

            await store.ClearFailedLoginsAsync("1.2.3.4");

            Assert.Equal(0, await store.CountFailedLoginsAsync("1.2.3.4", DateTime.MinValue));
            Assert.Equal(1, await store.CountFailedLoginsSinceAsync(DateTime.MinValue));
        });
    }

    [Fact]
    public async Task Prune_failed_logins_drops_old_rows()
    {
        await WithStoreAsync(async store =>
        {
            var now = DateTime.UtcNow;
            await store.AddFailedLoginAsync(Failed("1.2.3.4", now.AddDays(-2)));
            await store.AddFailedLoginAsync(Failed("1.2.3.4", now));

            await store.PruneFailedLoginsAsync(now.AddDays(-1));

            Assert.Equal(1, await store.CountFailedLoginsSinceAsync(DateTime.MinValue));
            Assert.Equal(1, await store.CountFailedLoginsAsync("1.2.3.4", now.AddDays(-1)));
        });
    }

    // ---------- bans ----------

    [Fact]
    public async Task Upsert_get_remove_and_list_bans()
    {
        await WithStoreAsync(async store =>
        {
            var now = DateTime.UtcNow;
            var ban = new BanEntry
            {
                IpAddress = "203.0.113.5",
                Source = ProtocolSource.Rdp,
                BannedAtUtc = now,
                ExpiresUtc = now.AddHours(24),
                OffenseCount = 1,
                IsPermanent = false,
                Note = "first strike",
            };

            await store.UpsertBanAsync(ban);

            var got = await store.GetBanAsync("203.0.113.5");
            Assert.NotNull(got);
            Assert.Equal(ban.IpAddress, got!.IpAddress);
            Assert.Equal(ban.Source, got.Source);
            Assert.Equal(ban.BannedAtUtc.Ticks, got.BannedAtUtc.Ticks);
            Assert.Equal(ban.ExpiresUtc.Ticks, got.ExpiresUtc.Ticks);
            Assert.Equal(1, got.OffenseCount);
            Assert.False(got.IsPermanent);
            Assert.Equal("first strike", got.Note);

            Assert.Single(await store.GetActiveBansAsync());

            ban.OffenseCount = 2;
            ban.Note = null;
            await store.UpsertBanAsync(ban);
            var updated = await store.GetBanAsync("203.0.113.5");
            Assert.Equal(2, updated!.OffenseCount);
            Assert.Null(updated.Note);

            await store.RemoveBanAsync("203.0.113.5");
            Assert.Null(await store.GetBanAsync("203.0.113.5"));
            Assert.Empty(await store.GetActiveBansAsync());
        });
    }

    [Fact]
    public async Task Active_bans_excludes_expired_non_permanent_bans()
    {
        await WithStoreAsync(async store =>
        {
            var now = DateTime.UtcNow;
            await store.UpsertBanAsync(new BanEntry
            {
                IpAddress = "203.0.113.1",
                Source = ProtocolSource.Rdp,
                BannedAtUtc = now.AddDays(-2),
                ExpiresUtc = now.AddDays(-1),
                IsPermanent = false,
            });
            await store.UpsertBanAsync(new BanEntry
            {
                IpAddress = "203.0.113.2",
                Source = ProtocolSource.Rdp,
                BannedAtUtc = now.AddDays(-2),
                ExpiresUtc = DateTime.MaxValue,
                IsPermanent = true,
            });
            await store.UpsertBanAsync(new BanEntry
            {
                IpAddress = "203.0.113.3",
                Source = ProtocolSource.Rdp,
                BannedAtUtc = now,
                ExpiresUtc = now.AddHours(24),
                IsPermanent = false,
            });

            var active = await store.GetActiveBansAsync();
            Assert.Equal(2, active.Count);
            Assert.Contains(active, b => b.IpAddress == "203.0.113.2");
            Assert.Contains(active, b => b.IpAddress == "203.0.113.3");
            Assert.DoesNotContain(active, b => b.IpAddress == "203.0.113.1");
        });
    }

    // ---------- lists ----------

    [Fact]
    public async Task Lists_add_get_remove_by_kind()
    {
        await WithStoreAsync(async store =>
        {
            await store.AddToListAsync(ListKind.Whitelist, "10.0.0.1");
            await store.AddToListAsync(ListKind.Whitelist, "10.0.0.0/8");
            await store.AddToListAsync(ListKind.Whitelist, "10.0.0.1"); // duplicate is a no-op
            await store.AddToListAsync(ListKind.Blacklist, "203.0.113.9");

            var whitelist = await store.GetListAsync(ListKind.Whitelist);
            Assert.Equal(2, whitelist.Count);
            Assert.Contains("10.0.0.1", whitelist);
            Assert.Contains("10.0.0.0/8", whitelist);

            var blacklist = await store.GetListAsync(ListKind.Blacklist);
            Assert.Single(blacklist);
            Assert.Contains("203.0.113.9", blacklist);

            await store.RemoveFromListAsync(ListKind.Whitelist, "10.0.0.1");
            Assert.Single(await store.GetListAsync(ListKind.Whitelist));
        });
    }

    // ---------- events ----------

    [Fact]
    public async Task Events_are_returned_newest_first_and_limited()
    {
        await WithStoreAsync(async store =>
        {
            var now = DateTime.UtcNow;
            await store.AddEventAsync(Event(now.AddMinutes(-3), "first"));
            await store.AddEventAsync(Event(now.AddMinutes(-2), "second"));
            await store.AddEventAsync(Event(now.AddMinutes(-1), "third"));

            var events = await store.GetEventsAsync(2);
            Assert.Equal(2, events.Count);
            Assert.Equal("third", events[0].Message);
            Assert.Equal("second", events[1].Message);

            var all = await store.GetEventsAsync(10);
            Assert.Equal(3, all.Count);

            var since = await store.GetEventsAsync(10, now.AddMinutes(-1.5));
            Assert.Single(since);
            Assert.Equal("third", since[0].Message);
        });
    }

    [Fact]
    public async Task Events_can_be_walked_forward_a_page_at_a_time_without_missing_any()
    {
        await WithStoreAsync(async store =>
        {
            var now = DateTime.UtcNow;

            // Timestamps run backwards: the walk follows ids, which is the order they were written.
            for (var i = 0; i < 7; i++)
            {
                await store.AddEventAsync(Event(now.AddMinutes(-i), "event " + i));
            }

            var seen = new List<LogEvent>();
            long after = 0;
            while (await store.GetEventsAfterAsync(after, 3) is { Count: > 0 } page)
            {
                seen.AddRange(page);
                after = page[^1].Id;
            }

            Assert.Equal(Enumerable.Range(0, 7).Select(i => "event " + i), seen.Select(e => e.Message));
            Assert.Equal(seen.Select(e => e.Id).Order(), seen.Select(e => e.Id));
            Assert.Empty(await store.GetEventsAfterAsync(after, 3));
        });
    }

    // ---------- settings ----------

    [Fact]
    public async Task Settings_round_trip_full_json_blob_under_engine_key()
    {
        await WithStoreAsync(async store =>
        {
            var settings = new WinGuardSettings
            {
                FailedLoginThreshold = 7,
                CountWindow = TimeSpan.FromMinutes(3),
                ExpireTime = TimeSpan.FromHours(12),
                BanTiers = new[] { TimeSpan.FromHours(1), TimeSpan.FromDays(2) },
                ProcessInternalIPs = true,
            };
            settings.Rdp.ExclusionRules = new[] { "TargetUserName=backup-svc" };
            settings.MsSql.IgnoreMessagePatterns = new[] { "custom ignore" };
            settings.Ftp.Sources.Add(new FtpLogSource
            {
                Name = "iis",
                Kind = FtpServerKind.IisFtp,
                Path = @"C:\logs",
            });
            settings.CustomSources.Add(new CustomLogSource
            {
                Name = "app",
                PathGlob = @"C:\app\*.log",
                Regex = "ip=(?<ipaddress>\\S+)",
            });

            var json = JsonSerializer.Serialize(settings);
            await store.SetSettingAsync("engine", json);

            var all = await store.GetAllSettingsAsync();
            Assert.True(all.ContainsKey("engine"));

            var roundTripped = JsonSerializer.Deserialize<WinGuardSettings>(all["engine"]);
            Assert.NotNull(roundTripped);
            Assert.Equal(7, roundTripped!.FailedLoginThreshold);
            Assert.Equal(TimeSpan.FromMinutes(3), roundTripped.CountWindow);
            Assert.Equal(TimeSpan.FromHours(12), roundTripped.ExpireTime);
            Assert.Equal(
                new[] { TimeSpan.FromHours(1), TimeSpan.FromDays(2) },
                roundTripped.BanTiers);
            Assert.True(roundTripped.ProcessInternalIPs);
            Assert.Equal(new[] { "TargetUserName=backup-svc" }, roundTripped.Rdp.ExclusionRules);
            Assert.Equal(new[] { "custom ignore" }, roundTripped.MsSql.IgnoreMessagePatterns);
            Assert.Single(roundTripped.Ftp.Sources);
            Assert.Equal(@"C:\logs", roundTripped.Ftp.Sources[0].Path);
            Assert.Single(roundTripped.CustomSources);
            Assert.Equal("ip=(?<ipaddress>\\S+)", roundTripped.CustomSources[0].Regex);
        });
    }

    [Fact]
    public async Task Set_setting_upserts_the_same_key()
    {
        await WithStoreAsync(async store =>
        {
            await store.SetSettingAsync("engine", "{\"FailedLoginThreshold\":3}");
            await store.SetSettingAsync("engine", "{\"FailedLoginThreshold\":9}");
            await store.SetSettingAsync("other", "value");

            var all = await store.GetAllSettingsAsync();
            Assert.Equal(2, all.Count);
            Assert.Contains("\"FailedLoginThreshold\":9", all["engine"]);
            Assert.Equal("value", all["other"]);
        });
    }

    // ---------- helpers ----------

    private static FailedLogin Failed(string ip, DateTime ts, ProtocolSource source = ProtocolSource.Rdp) => new()
    {
        IpAddress = ip,
        UserName = "tester",
        Source = source,
        TimestampUtc = ts,
        RawLog = "raw",
    };

    private static LogEvent Event(DateTime ts, string message) => new()
    {
        TimestampUtc = ts,
        Level = LogEventLevel.Info,
        Source = ProtocolSource.Rdp,
        IpAddress = "203.0.113.5",
        Message = message,
    };

    private static async Task WithStoreAsync(Func<SqliteStore, Task> body)
    {
        var path = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(),
            "winguard-tests",
            Guid.NewGuid().ToString("N") + ".db");
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);

        var store = new SqliteStore(path, NullLogger<SqliteStore>.Instance);
        try
        {
            await store.InitializeAsync();
            await body(store);
        }
        finally
        {
            await store.DisposeAsync();
            TryDelete(path);
        }
    }

    private static void TryDelete(string path)
    {
        foreach (var suffix in new[] { string.Empty, "-wal", "-shm" })
        {
            try
            {
                var file = path + suffix;
                if (File.Exists(file))
                {
                    File.Delete(file);
                }
            }
            catch (IOException)
            {
                // Best effort cleanup only.
            }
            catch (UnauthorizedAccessException)
            {
                // Best effort cleanup only.
            }
        }
    }
}