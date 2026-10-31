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
