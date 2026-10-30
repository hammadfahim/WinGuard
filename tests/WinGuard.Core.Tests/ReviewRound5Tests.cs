using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Engine;
using WinGuard.Core.Ipc;
using WinGuard.Core.Model;
using WinGuard.Core.Store;
using WinGuard.Core.Tests.Fakes;
using WinGuard.Service;
using WinGuard.Service.Ipc;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>
/// Regression tests for the second pass over the engine, store, firewall reconcile and settings:
/// ranges stay enforced across a restart, escalation has its own memory and table, history is
/// bounded, manual bans have their own source, report-only never touches the firewall.
/// </summary>
public sealed class ReviewRound5Tests
{
    private static readonly DateTimeOffset T0 = new(2026, 4, 1, 12, 0, 0, TimeSpan.Zero);

    private const ProtocolSource NonRdp = ProtocolSource.MsSql;
    private const string Attacker = "203.0.113.50";
    private const string Range = "198.51.100.0/24";

    // ---------- internal addresses ----------

    [Theory]
    [InlineData("100.64.1.1")]
    [InlineData("198.18.0.1")]
    [InlineData("64:ff9b::a00:1")]
    public async Task Carrier_nat_benchmarking_and_translated_private_peers_are_never_banned(string ip)
    {
        await using var h = await EngineHarness.StartAsync(T0);

        for (var i = 0; i < 5; i++)
        {
            await h.ProcessAsync(h.Fail(ip, NonRdp));
        }

        Assert.Empty(h.Firewall.BlockCalls);
    }

    [Fact]
    public async Task An_attacker_behind_nat64_is_banned()
    {
        await using var h = await EngineHarness.StartAsync(T0);

        for (var i = 0; i < 5; i++)
        {
            await h.ProcessAsync(h.Fail("64:ff9b::808:808", NonRdp));
        }

        Assert.Equal("64:ff9b::808:808", Assert.Single(h.Firewall.BlockCalls));
    }

    // ---------- settings bounds ----------

    [Fact]
    public async Task Extreme_durations_are_clamped_so_housekeeping_and_bans_keep_working()
    {
        await using var h = await EngineHarness.StartAsync(
            T0,
            s =>
            {
                s.ExpireTime = TimeSpan.MaxValue;
                s.CountWindow = TimeSpan.MaxValue;
                s.MsSql.CountWindow = TimeSpan.MaxValue;
                s.OffenseMemory = TimeSpan.MaxValue;
                s.Normalize();
            });

        await SendThresholdAsync(h);
        await h.Engine.HousekeepOnceAsync();

        Assert.Contains(Attacker, h.Firewall.Blocked);
        Assert.Equal(TimeSpan.FromDays(3650), h.Settings.ExpireTime);
        Assert.Equal(TimeSpan.FromDays(3650), h.Settings.CountWindow);
        Assert.Equal(TimeSpan.FromDays(3650), h.Settings.MsSql.CountWindow);
    }

    [Fact]
    public void Expire_time_cannot_cut_a_count_window_short()
    {
        var settings = new WinGuardSettings { ExpireTime = TimeSpan.FromMinutes(1), CountWindow = TimeSpan.FromMinutes(10) };
        settings.Normalize();
        Assert.Equal(TimeSpan.FromMinutes(10), settings.ExpireTime);

        settings.Ftp.CountWindow = TimeSpan.FromHours(3);
        settings.Normalize();
        Assert.Equal(TimeSpan.FromHours(3), settings.ExpireTime);
    }

    [Fact]
    public void An_expire_time_longer_than_every_window_is_left_alone()
    {
        var settings = new WinGuardSettings { ExpireTime = TimeSpan.FromDays(2) };

        settings.Normalize();

        Assert.Equal(TimeSpan.FromDays(2), settings.ExpireTime);
    }

    [Fact]
    public void A_per_protocol_window_that_means_nothing_falls_back_to_the_global_one()
    {
        var settings = new WinGuardSettings();
        settings.Rdp.CountWindow = TimeSpan.Zero;
        settings.MsSql.CountWindow = TimeSpan.FromMinutes(-5);

        settings.Normalize();

        Assert.Equal(settings.CountWindow, settings.CountWindowFor(ProtocolSource.Rdp));
        Assert.Equal(settings.CountWindow, settings.CountWindowFor(ProtocolSource.MsSql));
    }

    [Fact]
    public async Task A_timer_interval_cannot_exceed_what_a_timer_can_wait_for()
    {
        var settings = new WinGuardSettings { HousekeepingInterval = TimeSpan.MaxValue };
        settings.Ftp.PollInterval = TimeSpan.MaxValue;

        settings.Normalize();

        // Task.Delay throws for anything it cannot represent, which would end the polling loop.
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Task.Delay(settings.HousekeepingInterval, cancelled.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Task.Delay(settings.Ftp.PollInterval, cancelled.Token));
    }

    [Fact]
    public void Ban_history_retention_is_normalized()
    {
        var zero = new WinGuardSettings { BanHistoryRetentionDays = 0 };
        zero.Normalize();
        Assert.Equal(365, zero.BanHistoryRetentionDays);

        var huge = new WinGuardSettings { BanHistoryRetentionDays = 100000 };
        huge.Normalize();
        Assert.Equal(3650, huge.BanHistoryRetentionDays);
    }

    [Fact]
    public void Blocked_ports_the_firewall_would_refuse_are_dropped()
    {
        var settings = new WinGuardSettings { BlockedPorts = ["3389", " 21-22 ", "70000", "500-100", "1-2-3", "-5", "5-", "ftp", "0", "65535"] };

        settings.Normalize();

        Assert.Equal(["3389", "21-22", "0", "65535"], settings.BlockedPorts);
    }

    // ---------- helpers ----------

    private static BanEntry ActiveBan(string ip, ProtocolSource source = NonRdp) => new()
    {
        IpAddress = ip,
        Source = source,
        BannedAtUtc = T0.UtcDateTime,
        ExpiresUtc = T0.UtcDateTime.AddDays(1),
    };

    private static BanHistoryEntry History(string ip, DateTime atUtc, int offense = 1) => new()
    {
        TimestampUtc = atUtc,
        Action = BanHistoryAction.Banned,
        IpAddress = ip,
        Source = NonRdp,
        OffenseCount = offense,
    };

    private static void AssertFirewallUntouched(EngineHarness h)
    {
        Assert.Empty(h.Firewall.BlockCalls);
        Assert.Empty(h.Firewall.UnblockCalls);
        Assert.Empty(h.Firewall.SyncRulesCalls);
        Assert.Equal(0, h.Firewall.ClearAllCallCount);
    }

    private static async Task SendThresholdAsync(EngineHarness h, string ip = Attacker)
    {
        for (var i = 0; i < h.Settings.FailedLoginThreshold; i++)
        {
            await h.ProcessAsync(h.Fail(ip, NonRdp));
        }
    }

    private static async Task BanSeveralAsync(EngineHarness h)
    {
        foreach (var ip in new[] { "203.0.113.61", "203.0.113.62", "203.0.113.63" })
        {
            await SendThresholdAsync(h, ip);
        }
    }

    private static async Task ExpireAsync(EngineHarness h, TimeSpan after, bool expectRemoved = true)
    {
        h.Time.Advance(after);
        await h.Engine.HousekeepOnceAsync();
        if (expectRemoved)
        {
            Assert.Null(await h.Store.GetBanAsync(Attacker));
        }
    }

    private static async Task WithSqliteStoreAsync(Func<SqliteStore, string, Task> test)
    {
        var dir = Path.Combine(Path.GetTempPath(), "winguard-r5-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "test.db");
        try
        {
            await using var store = new SqliteStore(path, NullLogger<SqliteStore>.Instance);
            await store.InitializeAsync();
            await test(store, path);
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

    /// <summary>The request handler over fakes, in a chosen local time zone.</summary>
    private sealed class IpcHarness : IAsyncDisposable
    {
        private long _nextId;

        private IpcHarness(DateTimeOffset now, TimeSpan utcOffset)
        {
            Time = new FakeTimeProvider(now)
            {
                LocalZone = TimeZoneInfo.CreateCustomTimeZone("test", utcOffset, "test", "test"),
            };
        }

        public FakeStore Store { get; } = new();

        public FakeFirewall Firewall { get; } = new();

        public FakeTimeProvider Time { get; }

        public BanEngine Engine { get; private set; } = null!;

        public IpcRequestHandler Handler { get; private set; } = null!;

        public static async Task<IpcHarness> StartAsync(DateTimeOffset now, TimeSpan utcOffset)
        {
            var h = new IpcHarness(now, utcOffset);
            var holder = new SettingsHolder(h.Store, NullLogger<SettingsHolder>.Instance);
            await holder.ApplyAsync(new WinGuardSettings { HousekeepingInterval = TimeSpan.FromHours(6) });

            h.Engine = new BanEngine(h.Store, h.Firewall, () => holder.Current, NullLogger<BanEngine>.Instance, h.Time);
            await h.Engine.StartAsync(CancellationToken.None);
            h.Handler = new IpcRequestHandler(
                h.Store,
                h.Engine,
                holder,
                h.Firewall,
                new DetectorRuntimeState(),
                h.Time,
                NullLogger<IpcRequestHandler>.Instance);
            return h;
        }

        public async Task<T> GetAsync<T>(string method, object? parameters = null)
        {
            var response = await CallAsync(method, parameters);
            Assert.True(response.Ok, response.Error);
            return response.Result!.Value.Deserialize<T>(IpcJson.Options)!;
        }

        public async Task SendAsync(string method, object parameters)
        {
            var response = await CallAsync(method, parameters);
            Assert.True(response.Ok, response.Error);
        }

        public ValueTask DisposeAsync() => new(Engine.StopAsync(CancellationToken.None));

        private async Task<IpcResponse> CallAsync(string method, object? parameters)
        {
            var request = new IpcRequest
            {
                Id = ++_nextId,
                Method = method,
                Params = parameters is null ? null : JsonSerializer.SerializeToElement(parameters, IpcJson.Options),
            };

            var line = await Handler.HandleLineAsync(JsonSerializer.Serialize(request, IpcJson.Options), CancellationToken.None);
            return JsonSerializer.Deserialize<IpcResponse>(line!, IpcJson.Options)!;
        }
    }
}
