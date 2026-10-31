using System.Reflection;
using WinGuard.Core.Config;
using WinGuard.Core.Engine;
using WinGuard.Core.Model;
using WinGuard.Core.Tests.Fakes;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>
/// The engine keeps its promises when things go wrong: a database that cannot be read or written,
/// lists that are unreadable at start-up, a backlog older than the count window, a shutdown in the
/// middle of a ban, and the addresses that only look like one client.
/// </summary>
public sealed class BanEngineResilienceTests
{
    private static readonly DateTimeOffset T0 = new(2026, 5, 1, 12, 0, 0, TimeSpan.Zero);
    private const string Attacker = "203.0.113.50";

    private static readonly PortSet Rdp = PortSet.Parse(["3389"]);
    private static readonly PortSet Sql = PortSet.Parse(["1433"]);

    private static void Profiles(WinGuardSettings s)
    {
        s.Rdp.BlockedPorts = ["3389"];
        s.MsSql.BlockedPorts = ["1433"];
    }

    private static async Task Threshold(EngineHarness h, string ip, ProtocolSource source, string? detector = null)
    {
        for (var i = 0; i < 5; i++)
        {
            await h.ProcessAsync(h.Fail(ip, source, detector: detector));
        }
    }

    /// <summary>Everything the engine needs from the database fails, as with a locked file.</summary>
    private static void Locked(EngineHarness h, bool on)
    {
        h.Store.FailWrites = on;
        h.Store.FailBanRead = on;
        h.Store.FailActiveBansRead = on;
        h.Store.FailFailureReads = on;
        h.Store.FailBanRemoval = on;
        h.Store.FailListRead = on;
    }

    /// <summary>A pass of the timer loop: unlike HousekeepOnceAsync it reconciles at most once a minute.</summary>
    private static Task PassLikeTheTimer(EngineHarness h)
    {
        var core = typeof(BanEngine).GetMethod("HousekeepCoreAsync", BindingFlags.Instance | BindingFlags.NonPublic)!;
        return (Task)core.Invoke(h.Engine, [false, CancellationToken.None])!;
    }

    // ---------- a failed ban read is not "no ban" ----------

    [Fact]
    public async Task A_locked_database_does_not_open_the_rdp_port_of_a_scoped_ban()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        await Threshold(h, Attacker, ProtocolSource.Rdp, "4625");
        Assert.Equal(Rdp, h.Firewall.PortsOf(Attacker));

        Locked(h, true);
        await Threshold(h, Attacker, ProtocolSource.MsSql);

        // RDP was banned first and must stay covered.
        Assert.True(h.Firewall.PortsOf(Attacker)!.Covers(Rdp), $"firewall now holds {h.Firewall.PortsOf(Attacker)}");
    }

    [Fact]
    public async Task After_the_outage_the_stored_ban_covers_both_engines()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        await Threshold(h, Attacker, ProtocolSource.Rdp, "4625");
        var bannedAt = (await h.Store.GetBanAsync(Attacker))!.BannedAtUtc;

        h.Time.Advance(TimeSpan.FromMinutes(1));
        Locked(h, true);
        await Threshold(h, Attacker, ProtocolSource.MsSql);
        Locked(h, false);
        await h.Engine.HousekeepOnceAsync();

        var row = (await h.Store.GetBanAsync(Attacker))!;
        Assert.Equal(Rdp.Union(Sql), PortProfiles.Resolve(row.PortScope, h.Settings));
        Assert.Equal(Rdp.Union(Sql), h.Firewall.PortsOf(Attacker));
        Assert.Equal(ProtocolSource.Rdp, row.Source);
        Assert.Equal(bannedAt, row.BannedAtUtc);
        Assert.Equal(2, row.OffenseCount);
    }

    [Fact]
    public async Task A_permanent_ban_survives_an_outage_in_report_only()
    {
        await using var h = await EngineHarness.StartAsync(T0, s => s.ReportOnly = true);
        await h.Engine.BanNowAsync(Attacker, null, permanent: true, "keep out");

        Locked(h, true);
        await Threshold(h, Attacker, ProtocolSource.MsSql);
        Locked(h, false);
        await h.Engine.HousekeepOnceAsync();

        var row = (await h.Store.GetBanAsync(Attacker))!;
        Assert.True(row.IsPermanent, $"row now expires {row.ExpiresUtc:u}, note '{row.Note}'");
        Assert.Equal("keep out", row.Note);
    }

    [Fact]
    public async Task A_new_attacker_during_an_outage_goes_on_all_ports_then_back_to_its_engine()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);

        Locked(h, true);
        await Threshold(h, Attacker, ProtocolSource.MsSql);
        Assert.Equal(PortSet.All, h.Firewall.PortsOf(Attacker));

        Locked(h, false);
        await h.Engine.HousekeepOnceAsync();

        Assert.Equal("MsSql", (await h.Store.GetBanAsync(Attacker))!.PortScope);
        Assert.Equal(Sql, h.Firewall.PortsOf(Attacker));
    }

    [Fact]
    public async Task A_row_that_cannot_be_read_is_not_written_over_even_if_writes_work()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        await Threshold(h, Attacker, ProtocolSource.Rdp, "4625");

        h.Store.FailBanRead = true;
        await Threshold(h, Attacker, ProtocolSource.MsSql);
        h.Store.FailBanRead = false;

        Assert.Equal("Rdp", (await h.Store.GetBanAsync(Attacker))!.PortScope);

        await h.Engine.HousekeepOnceAsync();

        Assert.Equal(Rdp.Union(Sql), PortProfiles.Resolve((await h.Store.GetBanAsync(Attacker))!.PortScope, h.Settings));
    }

    [Fact]
    public async Task A_blind_ban_that_runs_out_stays_until_the_store_says_what_it_holds()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        await h.Engine.BanNowAsync(Attacker, null, permanent: true, null);

        Locked(h, true);
        await Threshold(h, Attacker, ProtocolSource.MsSql);
        h.Time.Advance(TimeSpan.FromDays(40));
        await h.Engine.HousekeepOnceAsync();
        Assert.Contains(Attacker, h.Firewall.Blocked);

        Locked(h, false);
        await h.Engine.HousekeepOnceAsync();

        Assert.Contains(Attacker, h.Firewall.Blocked);
        Assert.True((await h.Store.GetBanAsync(Attacker))!.IsPermanent);
    }

    [Fact]
    public async Task An_attacker_on_a_second_engine_during_an_outage_stays_on_all_ports()
    {
        await using var h = await EngineHarness.StartAsync(T0, Profiles);
        await Threshold(h, Attacker, ProtocolSource.Ftp);

        Locked(h, true);
        await Threshold(h, Attacker, ProtocolSource.MsSql);
        await Threshold(h, Attacker, ProtocolSource.Rdp, "4625");
        Assert.Equal(PortSet.All, h.Firewall.PortsOf(Attacker));

        Locked(h, false);
        await h.Engine.HousekeepOnceAsync();

        var row = (await h.Store.GetBanAsync(Attacker))!;
        Assert.Equal("Ftp\nMsSql\nRdp", row.PortScope);
    }

    [Fact]
    public async Task A_blind_ban_can_be_lifted_by_hand()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        Locked(h, true);
        await Threshold(h, Attacker, ProtocolSource.MsSql);

        await h.Engine.UnbanAsync(Attacker);
        Locked(h, false);
        await h.Engine.HousekeepOnceAsync();

        Assert.Empty(h.Firewall.Blocked);
        Assert.Null(await h.Store.GetBanAsync(Attacker));
    }

    [Fact]
    public async Task A_manual_ban_without_duration_does_not_demote_a_row_it_cannot_read()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        await h.Engine.BanNowAsync(Attacker, null, permanent: true, "keep out");

        Locked(h, true);
        await h.Engine.BanNowAsync(Attacker, null, permanent: false, null);
        Locked(h, false);
        await h.Engine.HousekeepOnceAsync();

        Assert.True((await h.Store.GetBanAsync(Attacker))!.IsPermanent);
    }

    [Fact]
    public async Task An_explicit_manual_ban_stands_whatever_the_unread_row_says()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        await h.Engine.BanNowAsync(Attacker, null, permanent: true, null);

        h.Store.FailBanRead = true;
        await h.Engine.BanNowAsync(Attacker, TimeSpan.FromHours(1), permanent: false, null);
        h.Store.FailBanRead = false;

        var row = (await h.Store.GetBanAsync(Attacker))!;
        Assert.False(row.IsPermanent);
        Assert.Equal(T0.UtcDateTime.AddHours(1), row.ExpiresUtc);
    }

    [Fact]
    public async Task A_logon_earns_no_trust_while_the_ban_cannot_be_read()
    {
        await using var h = await EngineHarness.StartAsync(T0, s => s.Rules.TrustAdminIpHours = 2);
        await h.Store.UpsertBanAsync(new BanEntry
        {
            IpAddress = Attacker,
            Source = ProtocolSource.MsSql,
            BannedAtUtc = T0.UtcDateTime,
            ExpiresUtc = T0.UtcDateTime.AddDays(1),
            OffenseCount = 1,
        });

        h.Store.FailBanRead = true;
        await h.ProcessAsync(new FailedLogin
        {
            IpAddress = Attacker,
            UserName = "alice",
            Source = ProtocolSource.Rdp,
            Detector = "4624",
            TimestampUtc = T0.UtcDateTime,
            IsSuccess = true,
            LogonType = 10,
        });

        Assert.DoesNotContain(h.Store.Events, e => e.Message.StartsWith("TEMPORARILY TRUSTED", StringComparison.Ordinal));
    }

    // ---------- a re-ban without a duration ----------

    [Fact]
    public async Task A_manual_ban_without_duration_does_not_shorten_a_permanent_ban()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        await h.Engine.BanNowAsync(Attacker, null, permanent: true, "keep out");

        await h.Engine.BanNowAsync(Attacker, null, permanent: false, null);

        var row = (await h.Store.GetBanAsync(Attacker))!;
        Assert.True(row.IsPermanent);
        Assert.Equal(DateTime.MaxValue, row.ExpiresUtc);
        Assert.Equal("keep out", row.Note);
    }

    [Fact]
    public async Task A_manual_ban_without_duration_keeps_a_longer_running_ban()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        await h.Engine.BanNowAsync(Attacker, TimeSpan.FromDays(3), permanent: false, null);

        await h.Engine.BanNowAsync(Attacker, null, permanent: false, null);

        var row = (await h.Store.GetBanAsync(Attacker))!;
        Assert.Equal(T0.UtcDateTime.AddDays(3), row.ExpiresUtc);
        Assert.Equal(TimeSpan.FromDays(3), h.Store.BanHistory.Last().Duration);
    }

    [Fact]
    public async Task A_manual_ban_without_duration_still_extends_a_shorter_ban()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        await h.Engine.BanNowAsync(Attacker, TimeSpan.FromHours(1), permanent: false, null);

        await h.Engine.BanNowAsync(Attacker, null, permanent: false, null);

        Assert.Equal(T0.UtcDateTime.AddHours(24), (await h.Store.GetBanAsync(Attacker))!.ExpiresUtc);
    }

    [Fact]
    public async Task An_explicit_duration_still_shortens_a_permanent_ban()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        await h.Engine.BanNowAsync(Attacker, null, permanent: true, null);

        await h.Engine.BanNowAsync(Attacker, TimeSpan.FromHours(1), permanent: false, null);

        var row = (await h.Store.GetBanAsync(Attacker))!;
        Assert.False(row.IsPermanent);
        Assert.Equal(T0.UtcDateTime.AddHours(1), row.ExpiresUtc);
    }
}
