using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Detection;
using WinGuard.Core.Engine;
using WinGuard.Core.Ipc;
using WinGuard.Core.Model;
using WinGuard.Core.Tests.Fakes;
using WinGuard.Service;
using WinGuard.Service.Ipc;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>
/// Regression tests for the v0.2.0 review: the whitelist beats range blocks, backlog replay does
/// not re-count, aggregate bans can be lifted, attacker-chosen user names cannot pick the banned
/// address, and a database failure does not stop blocking.
/// </summary>
public sealed class ReviewRound4Tests
{
    private static readonly DateTimeOffset T0 = new(2026, 4, 1, 12, 0, 0, TimeSpan.Zero);

    private const ProtocolSource NonRdp = ProtocolSource.MsSql;

    // ---------- the whitelist beats range blocks ----------

    [Theory]
    [InlineData("203.0.113.0/24", "203.0.113.5", 8)]
    [InlineData("203.0.113.0/30", "203.0.113.1", 2)]
    [InlineData("2001:db8::/126", "2001:db8::1", 2)]
    public void SubtractWhitelist_covers_everything_but_the_whitelisted_address(string range, string whitelisted, int pieces)
    {
        var matcher = new IpMatcher([whitelisted], []);

        var targets = matcher.SubtractWhitelist(range);

        Assert.Equal(pieces, targets.Count);
        Assert.DoesNotContain(targets, target => Covers(target, whitelisted));

        var network = IPNetwork.Parse(range);
        var bytes = network.BaseAddress.GetAddressBytes();
        var hostCount = 1 << ((bytes.Length * 8) - network.PrefixLength);
        for (var i = 0; i < hostCount; i++)
        {
            var address = (byte[])bytes.Clone();
            address[^1] = (byte)(address[^1] + i);
            var text = new IPAddress(address).ToString();
            Assert.Equal(text != whitelisted, targets.Any(target => Covers(target, text)));
        }
    }

    [Fact]
    public void SubtractWhitelist_leaves_an_untouched_range_whole_and_drops_a_fully_whitelisted_one()
    {
        Assert.Equal(["203.0.113.0/24"], new IpMatcher(["198.51.100.1"], []).SubtractWhitelist("203.0.113.0/24"));
        Assert.Empty(new IpMatcher(["203.0.113.0/16"], []).SubtractWhitelist("203.0.113.0/24"));
    }

    [Fact]
    public void OverlapsWhitelist_sees_entries_on_both_sides_of_the_range()
    {
        Assert.True(new IpMatcher(["2001:db8:1:2::5"], []).OverlapsWhitelist("2001:db8:1:2::/64"));
        Assert.True(new IpMatcher(["2001:db8::/32"], []).OverlapsWhitelist("2001:db8:1:2::/64"));
        Assert.False(new IpMatcher(["2001:db8:1:3::5", "203.0.113.5"], []).OverlapsWhitelist("2001:db8:1:2::/64"));
    }

    [Fact]
    public async Task A_blacklisted_range_is_cut_around_a_whitelisted_host()
    {
        await using var h = await EngineHarness.StartAsync(
            T0,
            seed: async store =>
            {
                await store.AddToListAsync(ListKind.Whitelist, "203.0.113.5");
                await store.AddToListAsync(ListKind.Blacklist, "203.0.113.0/24");
            });

        await h.Engine.HousekeepOnceAsync();

        Assert.DoesNotContain(h.Firewall.Blocked, target => Covers(target, "203.0.113.5"));
        Assert.Contains(h.Firewall.Blocked, target => Covers(target, "203.0.113.4"));
        Assert.Contains(h.Firewall.Blocked, target => Covers(target, "203.0.113.200"));
    }

    [Fact]
    public async Task Whitelisting_a_host_inside_an_enforced_range_opens_it_up()
    {
        await using var h = await EngineHarness.StartAsync(
            T0,
            seed: async store => await store.AddToListAsync(ListKind.Blacklist, "203.0.113.0/24"));
        await h.Engine.HousekeepOnceAsync();
        Assert.Contains("203.0.113.0/24", h.Firewall.Blocked);

        await h.Store.AddToListAsync(ListKind.Whitelist, "203.0.113.5");
        await h.Engine.HousekeepOnceAsync();

        Assert.DoesNotContain(h.Firewall.Blocked, target => Covers(target, "203.0.113.5"));
        Assert.Contains(h.Firewall.Blocked, target => Covers(target, "203.0.113.4"));
    }

    [Fact]
    public async Task A_prefix_holding_a_whitelisted_host_stays_on_per_address_bans()
    {
        await using var h = await EngineHarness.StartAsync(
            T0,
            s => s.Ipv6AggregatePrefixLength = 64,
            seed: async store => await store.AddToListAsync(ListKind.Whitelist, "2001:db8:1:2::5"));

        for (var i = 0; i < 5; i++)
        {
            await h.ProcessAsync(h.Fail("2001:db8:1:2::abcd", NonRdp));
        }

        Assert.Equal(["2001:db8:1:2::abcd"], h.Firewall.Blocked);
    }

    [Fact]
    public async Task An_existing_aggregate_ban_is_lifted_once_it_overlaps_the_whitelist()
    {
        await using var h = await EngineHarness.StartAsync(T0, s => s.Ipv6AggregatePrefixLength = 64);
        await BanAggregateAsync(h);

        await h.Store.AddToListAsync(ListKind.Whitelist, "2001:db8:1:2::5");
        await h.Engine.HousekeepOnceAsync();

        Assert.Empty(await h.Store.GetActiveBansAsync());
        Assert.Empty(h.Firewall.Blocked);
        Assert.Contains(h.Store.BanHistory, entry => entry.Action == BanHistoryAction.Unbanned && entry.IpAddress == "2001:db8:1:2::/64");
    }

    // ---------- backlog replay ----------

    [Fact]
    public async Task Replay_does_not_count_what_the_previous_run_already_processed()
    {
        const string ip = "203.0.113.20";
        var store = new FakeStore();
        var attempts = new List<DateTime>();

        await using (var first = await EngineHarness.StartAsync(T0, store: store))
        {
            for (var i = 0; i < 3; i++)
            {
                attempts.Add(first.Time.UtcNow.UtcDateTime);
                await first.ProcessAsync(first.Fail(ip, NonRdp));
                first.Time.Advance(TimeSpan.FromSeconds(10));
            }
        }

        await using var second = await EngineHarness.StartAsync(T0.AddMinutes(2), store: store);
        foreach (var at in attempts)
        {
            await second.ProcessAsync(Replayed(second.Fail(ip, NonRdp, at: at)));
        }

        Assert.Null(await store.GetBanAsync(ip));
        Assert.Equal(3, store.FailedLogins.Count);
    }

    [Fact]
    public async Task Replay_counts_what_was_logged_while_the_service_was_down()
    {
        const string ip = "203.0.113.21";
        var store = new FakeStore();
        await using (await EngineHarness.StartAsync(T0, store: store))
        {
        }

        await using var second = await EngineHarness.StartAsync(T0.AddMinutes(5), store: store);
        for (var i = 1; i <= 5; i++)
        {
            await second.ProcessAsync(Replayed(second.Fail(ip, NonRdp, at: T0.AddMinutes(i - 1).AddSeconds(1).UtcDateTime)));
        }

        Assert.NotNull(await store.GetBanAsync(ip));
    }

    [Fact]
    public async Task A_manual_unban_survives_a_restart()
    {
        const string ip = "203.0.113.22";
        var store = new FakeStore();
        var attempts = new List<DateTime>();

        await using (var first = await EngineHarness.StartAsync(T0, store: store))
        {
            for (var i = 0; i < 5; i++)
            {
                attempts.Add(first.Time.UtcNow.UtcDateTime);
                await first.ProcessAsync(first.Fail(ip, NonRdp));
            }

            await first.Engine.UnbanAsync(ip);
        }

        await using var second = await EngineHarness.StartAsync(T0.AddMinutes(1), store: store);
        foreach (var at in attempts)
        {
            await second.ProcessAsync(Replayed(second.Fail(ip, NonRdp, at: at)));
        }

        Assert.Null(await store.GetBanAsync(ip));
    }

    [Fact]
    public async Task Housekeeping_keeps_the_replay_position_current_for_a_crash()
    {
        const string ip = "203.0.113.23";
        var store = new FakeStore();

        // Never stopped: the only saved position is the one housekeeping wrote.
        var crashed = await EngineHarness.StartAsync(T0, store: store);
        var before = crashed.Time.UtcNow.UtcDateTime;
        await crashed.ProcessAsync(crashed.Fail(ip, NonRdp));
        crashed.Time.Advance(TimeSpan.FromSeconds(15));
        await crashed.Engine.HousekeepOnceAsync();

        await using var second = await EngineHarness.StartAsync(T0.AddMinutes(1), store: store);
        await second.ProcessAsync(Replayed(second.Fail(ip, NonRdp, at: before)));

        Assert.Single(store.FailedLogins);
        await crashed.DisposeAsync();
    }

    [Fact]
    public async Task The_first_start_replays_nothing_because_it_cannot_tell_what_is_new()
    {
        const string ip = "203.0.113.24";
        await using var h = await EngineHarness.StartAsync(T0);

        for (var i = 1; i <= 5; i++)
        {
            await h.ProcessAsync(Replayed(h.Fail(ip, NonRdp, at: T0.AddMinutes(-i).UtcDateTime)));
        }

        Assert.Empty(h.Store.FailedLogins);
        Assert.Null(await h.Store.GetBanAsync(ip));
    }

    [Fact]
    public async Task Replayed_4625_and_140_merge_even_when_one_channel_is_read_after_the_other()
    {
        const string ip = "203.0.113.25";
        var store = new FakeStore();
        await using (await EngineHarness.StartAsync(T0, store: store))
        {
        }

        await using var second = await EngineHarness.StartAsync(T0.AddMinutes(5), store: store);
        var attempts = Enumerable.Range(1, 3).Select(i => T0.AddSeconds(i * 30).UtcDateTime).ToList();
        foreach (var detector in new[] { "4625", "140" })
        {
            foreach (var at in attempts)
            {
                await second.ProcessAsync(Replayed(second.Fail(ip, ProtocolSource.Rdp, at: at, detector: detector)));
            }
        }

        Assert.Equal(3, store.FailedLogins.Count);
        Assert.Null(await store.GetBanAsync(ip));
    }

    // ---------- lifting aggregate bans ----------

    [Fact]
    public async Task An_aggregate_ban_can_be_unblocked()
    {
        await using var h = await IpcHarness.StartAsync();
        await BanAggregateAsync(h.Engine, h);

        await h.SendAsync(IpcMethods.Unblock, new UnblockParams { Ip = "2001:db8:1:2::/64" });

        Assert.Empty(await h.Store.GetActiveBansAsync());
        Assert.Empty(h.Firewall.Blocked);
    }

    [Fact]
    public async Task An_aggregate_ban_can_be_unblocked_and_whitelisted()
    {
        await using var h = await IpcHarness.StartAsync();
        await BanAggregateAsync(h.Engine, h);

        await h.SendAsync(IpcMethods.Unblock, new UnblockParams { Ip = "2001:db8:1:2::/64", AlsoWhitelist = true });

        Assert.Empty(await h.Store.GetActiveBansAsync());
        Assert.Contains("2001:db8:1:2::/64", await h.Store.GetListAsync(ListKind.Whitelist));
    }

    [Fact]
    public async Task An_aggregate_ban_can_be_promoted_but_a_new_range_cannot_be_blocked()
    {
        await using var h = await IpcHarness.StartAsync();
        await BanAggregateAsync(h.Engine, h);

        await h.SendAsync(IpcMethods.BlockNow, new BlockNowParams { Ip = "2001:db8:1:2::/64", Permanent = true });
        var refused = await h.CallAsync(IpcMethods.BlockNow, new BlockNowParams { Ip = "2001:db8:9:9::/64", Permanent = true });

        Assert.True((await h.Store.GetBanAsync("2001:db8:1:2::/64"))!.IsPermanent);
        Assert.False(refused.Ok);
    }

    [Fact]
    public async Task Whitelisting_a_range_lifts_the_aggregate_ban_inside_it()
    {
        await using var h = await IpcHarness.StartAsync();
        await BanAggregateAsync(h.Engine, h);

        await h.SendAsync(IpcMethods.WhitelistAdd, new ListValueParams { Value = "2001:db8:1::/48" });

        Assert.Empty(await h.Store.GetActiveBansAsync());
        Assert.Empty(h.Firewall.Blocked);
    }

    [Theory]
    [InlineData("203.0.113.9", "203.0.113.9")]
    [InlineData("203.0.113.9/32", "203.0.113.9")]
    [InlineData("2001:DB8:1:2::1/64", "2001:db8:1:2::/64")]
    public void Ban_targets_normalize_to_one_identity(string value, string expected)
    {
        Assert.True(IpMatcher.TryNormalizeBanTarget(value, out var target));
        Assert.Equal(expected, target);
    }

    [Theory]
    [InlineData("0.0.0.0/0")]
    [InlineData("LocalSubnet")]
    [InlineData("example.com")]
    public void Over_broad_and_non_address_targets_are_refused(string value)
    {
        Assert.False(IpMatcher.TryNormalizeBanTarget(value, out _));
    }

    // ---------- attacker-chosen user names ----------

    [Theory]
    [InlineData("Failed password for invalid user foo from 198.51.100.9 port 1 ssh2 from 203.0.113.44 port 5022 ssh2")]
    [InlineData("Failed password for foo from 198.51.100.9 port 1 from 203.0.113.44 port 5022 ssh2")]
    public void The_openssh_recipe_takes_the_address_sshd_wrote_not_the_one_in_the_user_name(string line)
    {
        Assert.True(CustomLogDetector.TryParseLine(line, CustomSourceRecipes.WindowsOpenSsh.Regex, out var failed));
        Assert.Equal("203.0.113.44", failed!.IpAddress);
    }

    [Theory]
    [InlineData("1234 2026-10-04 09:05:20.123 Failed password for bob from 203.0.113.44 port 5022 ssh2", "bob")]
    [InlineData("Failed password for invalid user root from 2001:db8::1 port 22 ssh2", "root")]
    public void The_openssh_recipe_still_parses_ordinary_lines(string line, string user)
    {
        Assert.True(CustomLogDetector.TryParseLine(line, CustomSourceRecipes.WindowsOpenSsh.Regex, out var failed));
        Assert.Equal(user, failed!.UserName);
    }

    [Fact]
    public void Settings_saved_from_the_old_openssh_recipe_are_upgraded_when_loaded()
    {
        var settings = new WinGuardSettings();
        settings.CustomSources.Add(new CustomLogSource
        {
            Name = "ssh",
            Regex = @"Failed password for (invalid user )?(?<username>\S+) from (?<ipaddress>[0-9a-fA-F:.]+) port \d+",
        });
        settings.CustomSources.Add(new CustomLogSource { Name = "mine", Regex = @"bad login (?<ipaddress>\S+)" });

        settings.Normalize();

        Assert.Equal(CustomSourceRecipes.WindowsOpenSsh.Regex, settings.CustomSources[0].Regex);
        Assert.Equal(@"bad login (?<ipaddress>\S+)", settings.CustomSources[1].Regex);
    }

    [Theory]
    [InlineData("(000012) 2026-10-04 09:05:20 - x (198.51.100.9)> y (203.0.113.44)> 530 Login or password incorrect!")]
    [InlineData("(000012) 2026-10-04 09:05:20 - (not logged in) (203.0.113.44)> USER x (198.51.100.9)> 530 Login or password incorrect!")]
    public void A_filezilla_line_of_any_other_shape_is_never_attributed_to_an_address(string line)
    {
        Assert.False(FtpLogDetector.TryParseFileZillaLine(line, out _));
    }

    [Fact]
    public void Client_text_after_the_response_cannot_pick_the_filezilla_address()
    {
        const string line = "2024-03-01T10:15:20.123Z [FTP Session 12 203.0.113.5] USER 530 Login (198.51.100.9)";

        Assert.True(FtpLogDetector.TryParseFileZillaLine(line, out var failed));
        Assert.Equal("203.0.113.5", failed!.IpAddress);
    }

    // ---------- a database failure does not stop blocking ----------

    [Fact]
    public async Task An_attacker_is_blocked_while_the_store_refuses_writes()
    {
        const string ip = "203.0.113.30";
        await using var h = await EngineHarness.StartAsync(T0);
        h.Store.FailWrites = true;

        for (var i = 0; i < 4; i++)
        {
            await h.ProcessAsync(h.Fail(ip, NonRdp));
        }

        Assert.Empty(h.Firewall.Blocked);

        await h.ProcessAsync(h.Fail(ip, NonRdp));

        Assert.Equal([ip], h.Firewall.Blocked);
    }

    [Fact]
    public async Task An_outage_in_the_middle_of_an_attack_does_not_reset_the_count()
    {
        const string ip = "203.0.113.31";
        await using var h = await EngineHarness.StartAsync(T0);
        for (var i = 0; i < 4; i++)
        {
            await h.ProcessAsync(h.Fail(ip, NonRdp));
        }

        h.Store.FailWrites = true;
        await h.ProcessAsync(h.Fail(ip, NonRdp));

        Assert.Equal([ip], h.Firewall.Blocked);
    }

    [Fact]
    public async Task Failures_seen_during_an_outage_still_count_after_it()
    {
        const string ip = "203.0.113.37";
        await using var h = await EngineHarness.StartAsync(T0);
        h.Store.FailWrites = true;
        for (var i = 0; i < 4; i++)
        {
            await h.ProcessAsync(h.Fail(ip, NonRdp));
        }

        h.Store.FailWrites = false;
        await h.ProcessAsync(h.Fail(ip, NonRdp));

        Assert.Equal([ip], h.Firewall.Blocked);
    }

    [Fact]
    public async Task An_unsaved_ban_is_not_lifted_as_an_orphan_and_is_saved_when_the_store_recovers()
    {
        const string ip = "203.0.113.32";
        await using var h = await EngineHarness.StartAsync(T0);
        h.Store.FailWrites = true;
        for (var i = 0; i < 5; i++)
        {
            await h.ProcessAsync(h.Fail(ip, NonRdp));
        }

        await h.Engine.HousekeepOnceAsync();
        Assert.Contains(ip, h.Firewall.Blocked);
        Assert.Null(await h.Store.GetBanAsync(ip));

        h.Store.FailWrites = false;
        await h.Engine.HousekeepOnceAsync();

        Assert.Contains(ip, h.Firewall.Blocked);
        Assert.NotNull(await h.Store.GetBanAsync(ip));
    }

    [Fact]
    public async Task A_later_attempt_does_not_re_ban_an_unsaved_ban()
    {
        const string ip = "203.0.113.33";
        await using var h = await EngineHarness.StartAsync(T0);
        h.Store.FailWrites = true;
        for (var i = 0; i < 8; i++)
        {
            await h.ProcessAsync(h.Fail(ip, NonRdp));
        }

        Assert.Equal([ip], h.Firewall.BlockCalls);
    }

    [Fact]
    public async Task An_unsaved_ban_still_expires()
    {
        const string ip = "203.0.113.34";
        await using var h = await EngineHarness.StartAsync(T0);
        h.Store.FailWrites = true;
        for (var i = 0; i < 5; i++)
        {
            await h.ProcessAsync(h.Fail(ip, NonRdp));
        }

        h.Time.Advance(TimeSpan.FromHours(25));
        await h.Engine.HousekeepOnceAsync();

        Assert.Empty(h.Firewall.Blocked);
    }

    [Fact]
    public async Task An_unsaved_ban_can_be_lifted_by_hand()
    {
        const string ip = "203.0.113.35";
        await using var h = await EngineHarness.StartAsync(T0);
        h.Store.FailWrites = true;
        for (var i = 0; i < 5; i++)
        {
            await h.ProcessAsync(h.Fail(ip, NonRdp));
        }

        await h.Engine.UnbanAsync(ip);
        await h.Engine.HousekeepOnceAsync();

        Assert.Empty(h.Firewall.Blocked);
    }

    [Fact]
    public async Task Report_only_stays_off_the_firewall_during_a_store_failure()
    {
        await using var h = await EngineHarness.StartAsync(T0, s => s.ReportOnly = true);
        h.Store.FailWrites = true;
        for (var i = 0; i < 5; i++)
        {
            await h.ProcessAsync(h.Fail("203.0.113.36", NonRdp));
        }

        Assert.Empty(h.Firewall.BlockCalls);
    }

    // ---------- helpers ----------

    private static FailedLogin Replayed(FailedLogin failed)
    {
        failed.IsReplayed = true;
        return failed;
    }

    private static bool Covers(string target, string address) =>
        IPNetwork.Parse(target.Contains('/') ? target : target + (target.Contains(':') ? "/128" : "/32"))
            .Contains(IPAddress.Parse(address));

    private static async Task BanAggregateAsync(EngineHarness h)
    {
        for (var i = 0; i < 5; i++)
        {
            await h.ProcessAsync(h.Fail($"2001:db8:1:2::{i + 0x100:x}", NonRdp));
        }

        Assert.Equal("2001:db8:1:2::/64", Assert.Single(await h.Store.GetActiveBansAsync()).IpAddress);
    }

    private static async Task BanAggregateAsync(BanEngine engine, IpcHarness h)
    {
        for (var i = 0; i < 5; i++)
        {
            await engine.ProcessAsync(new FailedLogin
            {
                IpAddress = $"2001:db8:1:2::{i + 0x100:x}",
                Source = NonRdp,
                TimestampUtc = h.Time.UtcNow.UtcDateTime,
            });
        }

        Assert.Equal("2001:db8:1:2::/64", Assert.Single(await h.Store.GetActiveBansAsync()).IpAddress);
    }

    /// <summary>The request handler over fakes with IPv6 aggregation switched on.</summary>
    private sealed class IpcHarness : IAsyncDisposable
    {
        private long _nextId;

        public FakeStore Store { get; } = new();

        public FakeFirewall Firewall { get; } = new();

        public FakeTimeProvider Time { get; } = new(T0);

        public BanEngine Engine { get; private set; } = null!;

        public IpcRequestHandler Handler { get; private set; } = null!;

        public static async Task<IpcHarness> StartAsync()
        {
            var h = new IpcHarness();
            var holder = new SettingsHolder(h.Store, NullLogger<SettingsHolder>.Instance);
            await holder.ApplyAsync(new WinGuardSettings
            {
                HousekeepingInterval = TimeSpan.FromHours(6),
                Ipv6AggregatePrefixLength = 64,
            });

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

        public async Task<IpcResponse> CallAsync(string method, object parameters)
        {
            var request = new IpcRequest
            {
                Id = ++_nextId,
                Method = method,
                Params = JsonSerializer.SerializeToElement(parameters, IpcJson.Options),
            };

            var line = await Handler.HandleLineAsync(JsonSerializer.Serialize(request, IpcJson.Options), CancellationToken.None);
            return JsonSerializer.Deserialize<IpcResponse>(line!, IpcJson.Options)!;
        }

        public async Task SendAsync(string method, object parameters)
        {
            var response = await CallAsync(method, parameters);
            Assert.True(response.Ok, response.Error);
        }

        public ValueTask DisposeAsync() => new(Engine.StopAsync(CancellationToken.None));
    }
}
