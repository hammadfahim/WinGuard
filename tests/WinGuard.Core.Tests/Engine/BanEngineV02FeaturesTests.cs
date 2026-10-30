using Microsoft.Extensions.Logging.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Engine;
using WinGuard.Core.Model;
using WinGuard.Core.Tests.Fakes;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>
/// Tests for the v0.2 engine features: report-only mode, IPv6 aggregate banning, ban history,
/// daily statistics and whole-subnet enforcement of blacklisted ranges.
/// </summary>
public sealed class BanEngineV02FeaturesTests
{
    private static readonly DateTimeOffset T0 = new(2026, 2, 1, 0, 0, 0, TimeSpan.Zero);

    private const ProtocolSource NonRdp = ProtocolSource.MsSql;

    // ---------- report-only mode ----------

    [Fact]
    public async Task Report_only_records_the_ban_but_never_touches_the_firewall()
    {
        await using var h = await EngineHarness.StartAsync(T0, s => s.ReportOnly = true);
        const string ip = "203.0.113.101";

        for (var i = 0; i < 5; i++)
        {
            await h.ProcessAsync(h.Fail(ip, NonRdp));
        }

        Assert.Empty(h.Firewall.BlockCalls);
        var ban = await h.Store.GetBanAsync(ip);
        Assert.NotNull(ban);

        var message = Assert.Single(h.Store.Events, e => e.Message.StartsWith($"BLOCKED {ip}", StringComparison.Ordinal)).Message;
        Assert.Contains("report-only", message, StringComparison.Ordinal);

        // The would-be ban is still in the history and in the day's statistics.
        Assert.Contains(h.Store.BanHistory, entry => entry.Action == BanHistoryAction.Banned && entry.IpAddress == ip);
    }

    [Fact]
    public async Task Report_only_reconcile_does_not_re_block_missing_rules()
    {
        await using var h = await EngineHarness.StartAsync(T0, s => s.ReportOnly = true);
        const string ip = "203.0.113.102";

        // The ban is recorded but never appears in the (fake) firewall.
        await h.Engine.BanNowAsync(ip, TimeSpan.FromHours(1), permanent: false, null);
        Assert.Empty(h.Firewall.BlockCalls);

        // A housekeeping pass with forceReconcile still never writes to the firewall.
        await h.Engine.HousekeepOnceAsync();
        Assert.Empty(h.Firewall.BlockCalls);
    }

    [Fact]
    public async Task Turning_report_only_back_on_enforces_recorded_bans()
    {
        await using var h = await EngineHarness.StartAsync(T0, s => s.ReportOnly = true);
        const string ip = "203.0.113.103";

        for (var i = 0; i < 5; i++)
        {
            await h.ProcessAsync(h.Fail(ip, NonRdp));
        }

        Assert.Empty(h.Firewall.BlockCalls);

        h.Settings.ReportOnly = false;
        await h.Engine.HousekeepOnceAsync();

        Assert.Contains(ip, h.Firewall.Blocked);
    }

    // ---------- IPv6 aggregate banning ----------

    [Fact]
    public async Task IPv6_addresses_in_the_same_prefix_count_and_ban_together()
    {
        await using var h = await EngineHarness.StartAsync(T0, s => s.Ipv6AggregatePrefixLength = 64);
        var ips = new[]
        {
            "2001:db8:1:2::1001",
            "2001:db8:1:2::1002",
            "2001:db8:1:2::1003",
            "2001:db8:1:2::1004",
            "2001:db8:1:2::1005",
        };

        for (var i = 0; i < ips.Length; i++)
        {
            await h.ProcessAsync(h.Fail(ips[i], NonRdp));
        }

        // The ban (and the firewall call) is for the /64 prefix, not any single address.
        var ban = Assert.Single((await h.Store.GetActiveBansAsync()), b => b.IpAddress.Contains('/'));
        Assert.Equal("2001:db8:1:2::/64", ban.IpAddress);
        Assert.Equal("2001:db8:1:2::/64", Assert.Single(h.Firewall.BlockCalls));
    }

    [Fact]
    public async Task IPv6_addresses_in_different_prefixes_count_separately()
    {
        await using var h = await EngineHarness.StartAsync(T0, s => s.Ipv6AggregatePrefixLength = 64);

        for (var i = 0; i < 4; i++)
        {
            await h.ProcessAsync(h.Fail($"2001:db8:1:2::{i + 10:x}", NonRdp));
            await h.ProcessAsync(h.Fail($"2001:db8:9:a::{i + 10:x}", NonRdp));
        }

        Assert.Empty(h.Firewall.BlockCalls);
    }

    [Fact]
    public async Task Without_aggregation_IPv6_addresses_count_individually()
    {
        await using var h = await EngineHarness.StartAsync(T0);

        for (var i = 0; i < 4; i++)
        {
            await h.ProcessAsync(h.Fail($"2001:db8:1:2::{i + 10:x}", NonRdp));
        }

        Assert.Empty(h.Firewall.BlockCalls);
        Assert.DoesNotContain((await h.Store.GetActiveBansAsync()), b => b.IpAddress.Contains('/'));
    }

    [Fact]
    public async Task A_whitelisted_prefix_is_not_aggregate_banned()
    {
        await using var h = await EngineHarness.StartAsync(
            T0,
            s => s.Ipv6AggregatePrefixLength = 64,
            seed: async store => await store.AddToListAsync(ListKind.Whitelist, "2001:db8:1:2::/64"));

        for (var i = 0; i < 10; i++)
        {
            await h.ProcessAsync(h.Fail($"2001:db8:1:2::{i + 10:x}", NonRdp));
        }

        Assert.Empty(h.Firewall.BlockCalls);
    }

    [Fact]
    public async Task Blacklisting_still_bans_the_full_address_when_aggregation_is_on()
    {
        await using var h = await EngineHarness.StartAsync(
            T0,
            s => s.Ipv6AggregatePrefixLength = 64,
            seed: async store => await store.AddToListAsync(ListKind.Blacklist, "2001:db8:1:2::/64"));

        await h.ProcessAsync(h.Fail("2001:db8:1:2::4242", NonRdp));

        var ban = Assert.Single(await h.Store.GetActiveBansAsync());
        Assert.True(ban.IsPermanent);
        Assert.Equal("2001:db8:1:2::4242", ban.IpAddress);
    }

    // ---------- ban history ----------

    [Fact]
    public async Task Threshold_bans_are_written_to_the_history_with_duration()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        const string ip = "203.0.113.110";

        for (var i = 0; i < 5; i++)
        {
            await h.ProcessAsync(h.Fail(ip, NonRdp));
        }

        var row = Assert.Single(h.Store.BanHistory, entry => entry.Action == BanHistoryAction.Banned);
        Assert.Equal(ip, row.IpAddress);
        Assert.Equal(1, row.OffenseCount);
        Assert.Equal(TimeSpan.FromHours(24), row.Duration);
        Assert.Equal(NonRdp, row.Source);
    }

    [Fact]
    public async Task Expiry_and_manual_unban_append_history_rows()
    {
        await using var h = await EngineHarness.StartAsync(T0, s => s.BanTiers = [TimeSpan.FromMinutes(10)]);
        const string ip = "203.0.113.111";

        for (var i = 0; i < 5; i++)
        {
            await h.ProcessAsync(h.Fail(ip, NonRdp));
        }

        h.Time.Advance(TimeSpan.FromMinutes(11));
        await h.Engine.HousekeepOnceAsync();

        Assert.Contains(h.Store.BanHistory, entry => entry.Action == BanHistoryAction.Expired && entry.IpAddress == ip);

        // A second, manually blocked IP that is unbanned manually.
        const string manual = "203.0.113.112";
        await h.Engine.BanNowAsync(manual, TimeSpan.FromHours(1), permanent: false, "note");
        await h.Engine.UnbanAsync(manual);

        Assert.Contains(h.Store.BanHistory, entry => entry.Action == BanHistoryAction.Banned && entry.IpAddress == manual);
        Assert.Contains(h.Store.BanHistory, entry => entry.Action == BanHistoryAction.Unbanned && entry.IpAddress == manual);
    }

    // ---------- daily statistics ----------

    [Fact]
    public async Task Detections_and_bans_are_buffered_and_flushed_by_housekeeping()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        const string ip = "203.0.113.120";

        // Four attempts (no ban yet) then the fifth crosses the threshold.
        for (var i = 0; i < 5; i++)
        {
            await h.ProcessAsync(h.Fail(ip, NonRdp));
        }

        // Nothing is written until housekeeping flushes the buffer.
        Assert.Empty(h.Store.DailyStats);

        await h.Engine.HousekeepOnceAsync();

        // The engine buckets by LOCAL day; derive the expected day from the same clock.
        var day = DateOnly.FromDateTime(h.Time.GetLocalNow().LocalDateTime);
        var entry = Assert.Single(h.Store.DailyStats);
        Assert.Equal(day.ToDateTime(TimeOnly.MinValue), entry.Key.Day);
        Assert.Equal(NonRdp, entry.Key.Source);
        Assert.Equal(5, entry.Value.Detections);
        Assert.Equal(1, entry.Value.Bans);
    }

    // ---------- blacklisted ranges as firewall range rules ----------

    [Fact]
    public async Task A_blacklisted_subnet_is_enforced_as_one_range_rule()
    {
        await using var h = await EngineHarness.StartAsync(
            T0,
            seed: async store => await store.AddToListAsync(ListKind.Blacklist, "203.0.113.0/24"));

        // Range enforcement happens in the reconcile pass of housekeeping.
        await h.Engine.HousekeepOnceAsync();

        Assert.Contains("203.0.113.0/24", h.Firewall.Blocked);
    }

    [Fact]
    public async Task Removing_the_blacklist_entry_lifts_the_range_rule()
    {
        await using var h = await EngineHarness.StartAsync(
            T0,
            seed: async store => await store.AddToListAsync(ListKind.Blacklist, "203.0.113.0/24"));

        await h.Engine.HousekeepOnceAsync();
        Assert.Contains("203.0.113.0/24", h.Firewall.Blocked);

        await h.Store.RemoveFromListAsync(ListKind.Blacklist, "203.0.113.0/24");
        await h.Engine.HousekeepOnceAsync();

        Assert.DoesNotContain("203.0.113.0/24", h.Firewall.Blocked);
    }

    [Fact]
    public async Task In_report_only_mode_ranges_are_not_enforced()
    {
        await using var h = await EngineHarness.StartAsync(
            T0,
            s => s.ReportOnly = true,
            seed: async store => await store.AddToListAsync(ListKind.Blacklist, "203.0.113.0/24"));

        await h.Engine.HousekeepOnceAsync();

        Assert.DoesNotContain("203.0.113.0/24", h.Firewall.Blocked);
    }
}
