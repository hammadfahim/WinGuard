using Microsoft.Extensions.Logging.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Engine;
using WinGuard.Core.Model;
using WinGuard.Core.Tests.Fakes;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>
/// Tests for the fail2ban core: counting, thresholds, rolling window, whitelist/blacklist
/// precedence, tier escalation, de-dup, expiry and manual operations (PLAN.md §5).
/// </summary>
public sealed class BanEngineTests
{
    private static readonly DateTimeOffset T0 = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private const ProtocolSource NonRdp = ProtocolSource.MsSql; // no 4625/140 de-dup applies

    // ---------- threshold crossing ----------

    [Fact]
    public async Task Fifth_failure_blocks_once_and_stores_ban()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        const string ip = "203.0.113.45";

        for (var i = 0; i < 4; i++)
        {
            await h.ProcessAsync(h.Fail(ip, NonRdp));
        }

        Assert.Empty(h.Firewall.BlockCalls);
        Assert.Null(await h.Store.GetBanAsync(ip));

        await h.ProcessAsync(h.Fail(ip, NonRdp));

        Assert.Single(h.Firewall.BlockCalls);
        Assert.Equal(ip, h.Firewall.BlockCalls[0]);

        var ban = await h.Store.GetBanAsync(ip);
        Assert.NotNull(ban);
        Assert.Equal(1, ban!.OffenseCount);
        Assert.False(ban.IsPermanent);
        Assert.Equal(h.Time.UtcNow.UtcDateTime.AddHours(24).Ticks, ban.ExpiresUtc.Ticks);

        // Counter is cleared after the ban fires.
        Assert.Equal(0, await h.Store.CountFailedLoginsAsync(ip, DateTime.MinValue));

        Assert.Contains(h.Store.Events, e => e.Message.StartsWith($"BLOCKED {ip}", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Threshold_is_configurable()
    {
        await using var h = await EngineHarness.StartAsync(T0, s => s.FailedLoginThreshold = 2);
        const string ip = "203.0.113.46";

        await h.ProcessAsync(h.Fail(ip, NonRdp));
        Assert.Empty(h.Firewall.BlockCalls);

        await h.ProcessAsync(h.Fail(ip, NonRdp));
        Assert.Single(h.Firewall.BlockCalls);
    }

    // ---------- rolling window ----------

    [Fact]
    public async Task Fifth_failure_outside_count_window_does_not_block()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        const string ip = "203.0.113.80";

        for (var i = 0; i < 4; i++)
        {
            await h.ProcessAsync(h.Fail(ip, NonRdp));
        }

        Assert.Empty(h.Firewall.BlockCalls);

        h.Time.Advance(h.Settings.CountWindow + TimeSpan.FromMinutes(1));
        await h.ProcessAsync(h.Fail(ip, NonRdp));

        Assert.Empty(h.Firewall.BlockCalls);
        Assert.Null(await h.Store.GetBanAsync(ip));
    }

    // ---------- tier escalation ----------

    [Fact]
    public async Task Tier_escalation_24h_7d_30d_then_cap()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        const string ip = "203.0.113.70";

        await SendThresholdAsync(h, ip);
        AssertTier(await h.Store.GetBanAsync(ip), offense: 1, expected: TimeSpan.FromHours(24));

        await ExpireAndHousekeepAsync(h, ip);
        await SendThresholdAsync(h, ip);
        AssertTier(await h.Store.GetBanAsync(ip), offense: 2, expected: TimeSpan.FromDays(7));

        await ExpireAndHousekeepAsync(h, ip);
        await SendThresholdAsync(h, ip);
        AssertTier(await h.Store.GetBanAsync(ip), offense: 3, expected: TimeSpan.FromDays(30));

        await ExpireAndHousekeepAsync(h, ip);
        await SendThresholdAsync(h, ip);
        AssertTier(await h.Store.GetBanAsync(ip), offense: 4, expected: TimeSpan.FromDays(30));

        await ExpireAndHousekeepAsync(h, ip);
        await SendThresholdAsync(h, ip);
        AssertTier(await h.Store.GetBanAsync(ip), offense: 5, expected: TimeSpan.FromDays(30));
    }

    // ---------- whitelist / blacklist precedence ----------

    [Fact]
    public async Task Whitelisted_ip_is_skipped_and_not_counted()
    {
        const string ip = "203.0.113.200";
        await using var h = await EngineHarness.StartAsync(
            T0,
            seed: s => s.AddToListAsync(ListKind.Whitelist, ip));

        await SendThresholdAsync(h, ip);

        Assert.Empty(h.Firewall.BlockCalls);
        Assert.Empty(h.Store.FailedLogins);
        Assert.Null(await h.Store.GetBanAsync(ip));
        Assert.Contains(h.Store.Events, e => e.Message.StartsWith($"SKIPPED {ip}", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Whitelist_wins_when_ip_is_on_both_lists()
    {
        const string ip = "203.0.113.201";
        await using var h = await EngineHarness.StartAsync(T0, seed: async s =>
        {
            await s.AddToListAsync(ListKind.Whitelist, ip);
            await s.AddToListAsync(ListKind.Blacklist, ip);
        });

        await SendThresholdAsync(h, ip);

        Assert.Empty(h.Firewall.BlockCalls);
        Assert.Null(await h.Store.GetBanAsync(ip));
    }

    [Fact]
    public async Task Blacklisted_ip_is_blocked_permanently_immediately()
    {
        const string ip = "203.0.113.202";
        await using var h = await EngineHarness.StartAsync(
            T0,
            seed: s => s.AddToListAsync(ListKind.Blacklist, ip));

        await h.ProcessAsync(h.Fail(ip, NonRdp));

        var ban = await h.Store.GetBanAsync(ip);
        Assert.NotNull(ban);
        Assert.True(ban!.IsPermanent);
        Assert.Equal(DateTime.MaxValue, ban.ExpiresUtc);
        Assert.Contains(ip, h.Firewall.ListBlocked());
    }

    // ---------- already banned ----------

    [Fact]
    public async Task Already_banned_ip_is_not_blocked_again()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        const string ip = "203.0.113.60";

        await SendThresholdAsync(h, ip);
        Assert.Single(h.Firewall.BlockCalls);

        for (var i = 0; i < 3; i++)
        {
            await h.ProcessAsync(h.Fail(ip, NonRdp));
        }

        Assert.Single(h.Firewall.BlockCalls);
        Assert.Equal(1, (await h.Store.GetBanAsync(ip))!.OffenseCount);
        Assert.Equal(1, await h.Engine.GetActiveBanCountAsync());
    }

    // ---------- internal IPs ----------

    [Fact]
    public async Task Internal_ip_is_skipped_when_ProcessInternalIPs_is_false()
    {
        const string ip = "10.66.66.66";
        await using var h = await EngineHarness.StartAsync(T0, s => s.ProcessInternalIPs = false);

        await SendThresholdAsync(h, ip);

        Assert.Empty(h.Firewall.BlockCalls);
        Assert.Null(await h.Store.GetBanAsync(ip));
    }

    [Fact]
    public async Task Internal_ip_is_processed_when_ProcessInternalIPs_is_true()
    {
        const string ip = "10.66.66.66";
        await using var h = await EngineHarness.StartAsync(T0, s => s.ProcessInternalIPs = true);

        await SendThresholdAsync(h, ip);

        Assert.Single(h.Firewall.BlockCalls);
        Assert.NotNull(await h.Store.GetBanAsync(ip));
    }

    // ---------- RDP de-dup (4625 + 140) ----------

    [Fact]
    public async Task Rdp_failures_one_second_apart_are_counted_once()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        const string ip = "203.0.113.61";

        await h.ProcessAsync(h.Fail(ip, ProtocolSource.Rdp));
        h.Time.Advance(TimeSpan.FromSeconds(1));
        await h.ProcessAsync(h.Fail(ip, ProtocolSource.Rdp));

        Assert.Single(h.Store.FailedLogins);
    }

    [Fact]
    public async Task Rdp_failures_three_seconds_apart_are_counted_twice()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        const string ip = "203.0.113.62";

        await h.ProcessAsync(h.Fail(ip, ProtocolSource.Rdp));
        h.Time.Advance(TimeSpan.FromSeconds(3));
        await h.ProcessAsync(h.Fail(ip, ProtocolSource.Rdp));

        Assert.Equal(2, h.Store.FailedLogins.Count);
    }

    [Fact]
    public async Task Non_rdp_failures_are_never_deduplicated()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        const string ip = "203.0.113.63";

        await h.ProcessAsync(h.Fail(ip, NonRdp));
        await h.ProcessAsync(h.Fail(ip, NonRdp));

        Assert.Equal(2, h.Store.FailedLogins.Count);
    }

    // ---------- expiry / housekeeping ----------

    [Fact]
    public async Task Expired_ban_is_unblocked_and_removed()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        const string ip = "203.0.113.90";

        await SendThresholdAsync(h, ip);
        Assert.Single(h.Firewall.BlockCalls);

        // Still active one hour in.
        h.Time.Advance(TimeSpan.FromHours(1));
        await h.Engine.HousekeepOnceAsync();
        Assert.NotNull(await h.Store.GetBanAsync(ip));

        // Past the 24h tier.
        h.Time.Advance(TimeSpan.FromHours(24));
        await h.Engine.HousekeepOnceAsync();

        Assert.Null(await h.Store.GetBanAsync(ip));
        Assert.Contains(ip, h.Firewall.UnblockCalls);
        Assert.Contains(h.Store.Events, e => e.Message.StartsWith($"UNBANNED {ip}", StringComparison.Ordinal));
    }

    // ---------- manual operations ----------

    [Fact]
    public async Task Manual_permanent_ban_never_expires()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        const string ip = "203.0.113.91";

        await h.Engine.BanNowAsync(ip, null, permanent: true, note: "manual test");

        var ban = await h.Store.GetBanAsync(ip);
        Assert.NotNull(ban);
        Assert.True(ban!.IsPermanent);
        Assert.Equal(DateTime.MaxValue, ban.ExpiresUtc);
        Assert.Equal("manual test", ban.Note);
        Assert.Contains(ip, h.Firewall.ListBlocked());
        Assert.Contains(h.Store.Events, e => e.Message.StartsWith("MANUAL BLOCK", StringComparison.Ordinal));

        h.Time.Advance(TimeSpan.FromDays(1000));
        await h.Engine.HousekeepOnceAsync();

        Assert.NotNull(await h.Store.GetBanAsync(ip));
    }

    [Fact]
    public async Task Manual_timed_ban_expires_and_manual_unban_removes_ban()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        const string ip = "203.0.113.92";

        await h.Engine.BanNowAsync(ip, TimeSpan.FromHours(2), permanent: false, note: null);

        var ban = await h.Store.GetBanAsync(ip);
        Assert.NotNull(ban);
        Assert.False(ban!.IsPermanent);
        Assert.Equal(h.Time.UtcNow.UtcDateTime.AddHours(2).Ticks, ban.ExpiresUtc.Ticks);

        await h.Engine.UnbanAsync(ip);

        Assert.Null(await h.Store.GetBanAsync(ip));
        Assert.Contains(ip, h.Firewall.UnblockCalls);
        Assert.Contains(h.Store.Events, e => e.Message.StartsWith("MANUAL UNBLOCK", StringComparison.Ordinal));
    }

    // ---------- helpers ----------

    private static async Task SendThresholdAsync(EngineHarness h, string ip)
    {
        for (var i = 0; i < h.Settings.FailedLoginThreshold; i++)
        {
            await h.ProcessAsync(h.Fail(ip, NonRdp));
        }
    }

    private static async Task ExpireAndHousekeepAsync(EngineHarness h, string ip)
    {
        h.Time.Advance(TimeSpan.FromDays(31));
        await h.Engine.HousekeepOnceAsync();
        Assert.Null(await h.Store.GetBanAsync(ip));
    }

    private static void AssertTier(BanEntry? ban, int offense, TimeSpan expected)
    {
        Assert.NotNull(ban);
        Assert.Equal(offense, ban!.OffenseCount);
        Assert.Equal(expected.Ticks, (ban.ExpiresUtc - ban.BannedAtUtc).Ticks);
    }
}

/// <summary>Wires a <see cref="BanEngine"/> to its fakes and disposes it at test end.</summary>
internal sealed class EngineHarness : IAsyncDisposable
{
    private EngineHarness(DateTimeOffset now, WinGuardSettings settings)
    {
        Time = new FakeTimeProvider(now);
        Settings = settings;
    }

    public FakeStore Store { get; } = new();

    public FakeFirewall Firewall { get; } = new();

    public FakeTimeProvider Time { get; }

    public WinGuardSettings Settings { get; }

    public BanEngine Engine { get; private set; } = null!;

    public static async Task<EngineHarness> StartAsync(
        DateTimeOffset now,
        Action<WinGuardSettings>? configure = null,
        Func<FakeStore, Task>? seed = null)
    {
        var settings = new WinGuardSettings
        {
            // Keep the engine's periodic timer from firing during the test; expiry is
            // exercised explicitly through HousekeepOnceAsync.
            HousekeepingInterval = TimeSpan.FromHours(6),
        };
        configure?.Invoke(settings);

        var harness = new EngineHarness(now, settings);
        if (seed is not null)
        {
            await seed(harness.Store);
        }

        harness.Engine = new BanEngine(
            harness.Store,
            harness.Firewall,
            () => harness.Settings,
            NullLogger<BanEngine>.Instance,
            harness.Time);

        await harness.Engine.StartAsync(CancellationToken.None);
        return harness;
    }

    public FailedLogin Fail(
        string ip,
        ProtocolSource source = ProtocolSource.MsSql,
        string? user = "test-user",
        DateTime? at = null) => new()
        {
            IpAddress = ip,
            Source = source,
            UserName = user,
            TimestampUtc = at ?? Time.UtcNow.UtcDateTime,
            RawLog = $"failed login for {ip}",
        };

    public Task ProcessAsync(FailedLogin failed) => Engine.ProcessAsync(failed, CancellationToken.None);

    public ValueTask DisposeAsync() => new(Engine.StopAsync(CancellationToken.None));
}