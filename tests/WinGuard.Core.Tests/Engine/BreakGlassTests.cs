using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Engine;
using WinGuard.Core.Ipc;
using WinGuard.Core.Model;
using WinGuard.Core.Notifications;
using WinGuard.Core.Tests.Fakes;
using WinGuard.Service;
using WinGuard.Service.Ipc;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>
/// The break-glass drop file and what the engine and the CLI do with it, all in a temporary folder:
/// nothing here reads or writes %ProgramData%, the real firewall or the real service.
/// </summary>
public sealed class BreakGlassTests : IDisposable
{
    private static readonly DateTimeOffset T0 = new(2026, 3, 1, 12, 0, 0, TimeSpan.Zero);
    private static readonly DateTime Now = T0.UtcDateTime;
    private const string Attacker = "203.0.113.50";

    private readonly string _folder = Path.Combine(Path.GetTempPath(), "winguard-breakglass-" + Guid.NewGuid().ToString("N"));

    public BreakGlassTests() => Directory.CreateDirectory(_folder);

    public void Dispose() => Directory.Delete(_folder, recursive: true);

    private string FilePath => Path.Combine(_folder, DisarmFile.FileName);

    /// <summary>The real file logic, without the ownership rules that need an elevated test run.</summary>
    private DisarmFile NewFile() => new(FilePath)
    {
        TrustCheck = _ => null,
        CreateSecured = path => new FileStream(path, FileMode.CreateNew, FileAccess.Write),
    };

    private void WriteRaw(string json) => File.WriteAllText(FilePath, json, new UTF8Encoding(false));

    private static string Record(DateTime issued, DateTime until, int version = 1) =>
        $$"""{"Version":{{version}},"IssuedUtc":"{{issued:O}}","UntilUtc":"{{until:O}}","By":"admin"}""";

    private static bool IsElevatedAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    // ---- the file ----

    [Fact]
    public void No_file_means_armed()
    {
        Assert.Equal(DisarmStatus.None, NewFile().Read(Now).Status);
    }

    [Fact]
    public void A_written_file_reads_back_as_active_until_its_end()
    {
        var file = NewFile();

        var until = file.Write(TimeSpan.FromMinutes(30), Now, @"HOST\admin");
        var state = file.Read(Now);

        Assert.Equal(Now.AddMinutes(30), until);
        Assert.Equal(DisarmStatus.Active, state.Status);
        Assert.Equal(until, state.UntilUtc);
        Assert.Equal(DateTimeKind.Utc, state.UntilUtc!.Value.Kind);
        Assert.Equal(@"HOST\admin", state.By);
    }

    [Fact]
    public void The_window_is_exact_at_its_end()
    {
        var file = NewFile();
        var until = file.Write(TimeSpan.FromMinutes(30), Now, null);

        Assert.Equal(DisarmStatus.Active, file.Read(until.AddTicks(-1)).Status);
        Assert.Equal(DisarmStatus.Expired, file.Read(until).Status);
    }

    [Fact]
    public void Writing_leaves_no_temporary_file_behind()
    {
        NewFile().Write(TimeSpan.FromMinutes(5), Now, null);

        Assert.Equal([FilePath], Directory.GetFileSystemEntries(_folder));
    }

    [Fact]
    public void A_failed_write_keeps_the_earlier_disarm_and_leaves_no_debris()
    {
        NewFile().Write(TimeSpan.FromMinutes(5), Now, null);
        var broken = new DisarmFile(FilePath)
        {
            TrustCheck = _ => null,
            CreateSecured = path =>
            {
                File.WriteAllText(path, "partial");
                throw new IOException("disk full");
            },
        };

        Assert.Throws<IOException>(() => broken.Write(TimeSpan.FromHours(1), Now, null));

        Assert.Equal(Now.AddMinutes(5), NewFile().Read(Now).UntilUtc);
        Assert.Equal([FilePath], Directory.GetFileSystemEntries(_folder));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(1441)]
    public void A_window_out_of_bounds_cannot_be_written(int minutes)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => NewFile().Write(TimeSpan.FromMinutes(minutes), Now, null));

        Assert.False(File.Exists(FilePath));
    }

    [Fact]
    public void The_longest_window_is_accepted()
    {
        var file = NewFile();

        file.Write(DisarmFile.MaxWindow, Now, null);

        Assert.Equal(DisarmStatus.Active, file.Read(Now).Status);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not json")]
    [InlineData("{")]
    [InlineData("[]")]
    [InlineData("null")]
    [InlineData("{}")]
    [InlineData("""{"Version":1}""")]
    [InlineData("""{"Version":1,"UntilUtc":"yesterday"}""")]
    public void A_corrupt_file_disarms_nothing(string content)
    {
        WriteRaw(content);

        var state = NewFile().Read(Now);

        Assert.Equal(DisarmStatus.Invalid, state.Status);
        Assert.False(string.IsNullOrEmpty(state.Problem));
    }

    [Fact]
    public void Binary_garbage_disarms_nothing()
    {
        File.WriteAllBytes(FilePath, [0xFF, 0x00, 0xFE, 0x7B, 0x00]);

        Assert.Equal(DisarmStatus.Invalid, NewFile().Read(Now).Status);
    }

    [Fact]
    public void An_oversized_file_is_not_even_parsed()
    {
        WriteRaw(Record(Now, Now.AddMinutes(5)) + new string(' ', 8192));

        Assert.Equal(DisarmStatus.Invalid, NewFile().Read(Now).Status);
    }

    [Fact]
    public void A_file_claiming_more_than_the_maximum_window_disarms_nothing()
    {
        // Edited by hand, or written by something else: the bound holds wherever the file came from.
        WriteRaw(Record(Now, Now.AddHours(24).AddSeconds(1)));

        Assert.Equal(DisarmStatus.Invalid, NewFile().Read(Now).Status);
    }

    [Fact]
    public void A_clock_set_back_cannot_stretch_the_window()
    {
        NewFile().Write(TimeSpan.FromHours(24), Now, null);

        Assert.Equal(DisarmStatus.Invalid, NewFile().Read(Now.AddDays(-30)).Status);
    }

    [Fact]
    public void A_future_format_version_disarms_nothing()
    {
        WriteRaw(Record(Now, Now.AddMinutes(5), version: 2));

        Assert.Equal(DisarmStatus.Invalid, NewFile().Read(Now).Status);
    }

    [Fact]
    public void Times_without_a_zone_disarm_nothing()
    {
        WriteRaw("""{"Version":1,"IssuedUtc":"2026-03-01T12:00:00","UntilUtc":"2026-03-01T13:00:00"}""");

        Assert.Equal(DisarmStatus.Invalid, NewFile().Read(Now).Status);
    }

    [Fact]
    public void Who_disarmed_is_kept_printable_and_short()
    {
        WriteRaw($$"""{"Version":1,"IssuedUtc":"{{Now:O}}","UntilUtc":"{{Now.AddMinutes(5):O}}","By":"evil\r\nBLOCKED 1.2.3.4{{new string('x', 200)}}"}""");

        var state = NewFile().Read(Now);

        Assert.Equal(DisarmStatus.Active, state.Status);
        Assert.NotNull(state.By);
        Assert.DoesNotContain('\n', state.By);
        Assert.DoesNotContain('\r', state.By);
        Assert.True(state.By.Length <= 64);
    }

    [Fact]
    public void A_link_in_place_of_the_file_disarms_nothing()
    {
        var target = Path.Combine(_folder, "target.json");
        File.WriteAllText(target, Record(Now, Now.AddMinutes(5)));
        var (exitCode, _) = WinGuard.Service.Program.RunProcess("cmd.exe", "/c", "mklink", FilePath, target);
        if (exitCode != 0)
        {
            return; // creating a file symlink needs a privilege this run does not have
        }

        Assert.Equal(DisarmStatus.Untrusted, NewFile().Read(Now).Status);
    }

    [Fact]
    public void A_file_the_trust_check_refuses_disarms_nothing_and_says_why()
    {
        var writer = NewFile();
        writer.Write(TimeSpan.FromMinutes(5), Now, null);
        var reader = new DisarmFile(FilePath) { TrustCheck = _ => "it is owned by a standard user" };

        var state = reader.Read(Now);

        Assert.Equal(DisarmStatus.Untrusted, state.Status);
        Assert.Equal("it is owned by a standard user", state.Problem);
        Assert.Null(state.UntilUtc);
    }

    [Fact]
    public void A_trust_check_that_throws_disarms_nothing()
    {
        NewFile().Write(TimeSpan.FromMinutes(5), Now, null);
        var reader = new DisarmFile(FilePath) { TrustCheck = _ => throw new UnauthorizedAccessException("no") };

        Assert.Equal(DisarmStatus.Invalid, reader.Read(Now).Status);
    }

    [Fact]
    public void The_real_trust_check_refuses_an_ordinary_file()
    {
        // What a standard user could drop into a folder a portable run left unhardened: created
        // with the inherited ACL, which gives its creator (and more) write access.
        WriteRaw(Record(Now, Now.AddMinutes(5)));

        var state = new DisarmFile(FilePath).Read(Now);

        Assert.Equal(DisarmStatus.Untrusted, state.Status);
    }

    [Fact]
    public void The_real_writer_produces_a_file_the_real_check_trusts_or_refuses_to_write()
    {
        var file = new DisarmFile(FilePath);

        if (IsElevatedAdministrator())
        {
            file.Write(TimeSpan.FromMinutes(5), Now, null);
            Assert.Equal(DisarmStatus.Active, file.Read(Now).Status);
        }
        else
        {
            // Only an elevated token may make the Administrators group the owner.
            Assert.ThrowsAny<Exception>(() => file.Write(TimeSpan.FromMinutes(5), Now, null));
            Assert.Empty(Directory.GetFileSystemEntries(_folder));
        }
    }

    [Fact]
    public void Delete_says_whether_there_was_a_file()
    {
        var file = NewFile();
        file.Write(TimeSpan.FromMinutes(5), Now, null);

        Assert.True(file.Delete());
        Assert.False(file.Delete());
    }

    // ---- the engine ----

    [Fact]
    public async Task Disarming_removes_every_rule_and_stops_all_firewall_writes()
    {
        await using var h = await Harness.StartAsync(NewFile());
        await h.Engine.BanNowAsync(Attacker, TimeSpan.FromDays(1), permanent: false, null);
        Assert.Contains(Attacker, h.Firewall.Blocked);

        h.File.Write(TimeSpan.FromMinutes(30), h.Now, @"HOST\admin");
        await h.Engine.HousekeepOnceAsync();

        Assert.Empty(h.Firewall.Blocked);
        Assert.Equal(1, h.Firewall.ClearAllCallCount);
        Assert.True(h.Engine.IsDisarmed);
        Assert.Equal(h.Now.AddMinutes(30), h.Engine.DisarmedUntilUtc);

        var calls = h.Firewall.BlockCalls.Count + h.Firewall.UnblockCalls.Count + h.Firewall.SyncRulesCalls.Count;
        await h.Engine.BanNowAsync("203.0.113.51", TimeSpan.FromDays(1), permanent: false, null);
        await h.Engine.UnbanAsync(Attacker);
        await h.Engine.HousekeepOnceAsync();

        Assert.Equal(calls, h.Firewall.BlockCalls.Count + h.Firewall.UnblockCalls.Count + h.Firewall.SyncRulesCalls.Count);
        Assert.Empty(h.Firewall.Blocked);
    }

    [Fact]
    public async Task Disarming_is_a_warning_that_reaches_the_notification_channels()
    {
        await using var h = await Harness.StartAsync(NewFile());

        h.File.Write(TimeSpan.FromMinutes(30), h.Now, @"HOST\admin");
        await h.Engine.HousekeepOnceAsync();

        var logged = Assert.Single(h.Store.Events, e => e.Message.StartsWith("DISARMED ", StringComparison.Ordinal));
        Assert.Equal(LogEventLevel.Warning, logged.Level);
        Assert.Contains(@"HOST\admin", logged.Message);
        Assert.Equal(WinGuardEventIds.Disarmed, WinGuardEventIds.For(logged));
        Assert.True(WinGuardEventIds.IsNotifiable(logged));
        Assert.Contains(h.Published, e => e.Message == logged.Message);
    }

    [Fact]
    public async Task Disarming_is_reported_once_not_on_every_pass()
    {
        await using var h = await Harness.StartAsync(NewFile());

        h.File.Write(TimeSpan.FromMinutes(30), h.Now, null);
        await h.Engine.HousekeepOnceAsync();
        await h.Engine.HousekeepOnceAsync();
        await h.Engine.HousekeepOnceAsync();

        Assert.Single(h.Store.Events, e => e.Message.StartsWith("DISARMED ", StringComparison.Ordinal));
        Assert.Equal(1, h.Firewall.ClearAllCallCount);
    }

    [Fact]
    public async Task The_status_reply_carries_the_disarm_and_its_end()
    {
        await using var h = await Harness.StartAsync(NewFile());
        var holder = new SettingsHolder(h.Store, NullLogger<SettingsHolder>.Instance);
        await holder.LoadAsync();
        var handler = new IpcRequestHandler(h.Store, h.Engine, holder, h.Firewall, new DetectorRuntimeState(), h.Time, NullLogger<IpcRequestHandler>.Instance);

        async Task<ServiceStatusDto> StatusAsync()
        {
            var request = JsonSerializer.Serialize(new IpcRequest { Id = 1, Method = IpcMethods.GetStatus }, IpcJson.Options);
            var response = JsonSerializer.Deserialize<IpcResponse>((await handler.HandleLineAsync(request, CancellationToken.None))!, IpcJson.Options)!;
            return JsonSerializer.Deserialize<ServiceStatusDto>(response.Result!.Value, IpcJson.Options)!;
        }

        var armed = await StatusAsync();
        Assert.False(armed.Disarmed);
        Assert.Null(armed.DisarmedUntilUtc);

        h.File.Write(TimeSpan.FromMinutes(30), h.Now, null);
        await h.Engine.HousekeepOnceAsync();

        var disarmed = await StatusAsync();
        Assert.True(disarmed.Disarmed);
        Assert.Equal(h.Now.AddMinutes(30), disarmed.DisarmedUntilUtc);
    }

    [Fact]
    public async Task Bans_are_still_recorded_and_say_they_are_not_enforced()
    {
        await using var h = await Harness.StartAsync(NewFile());
        h.File.Write(TimeSpan.FromMinutes(30), h.Now, null);
        await h.Engine.HousekeepOnceAsync();

        for (var i = 0; i < 5; i++)
        {
            await h.Engine.ProcessAsync(new FailedLogin
            {
                IpAddress = Attacker,
                Source = ProtocolSource.MsSql,
                UserName = "sa",
                TimestampUtc = h.Now,
            });
        }

        Assert.NotNull(await h.Store.GetBanAsync(Attacker));
        Assert.Empty(h.Firewall.BlockCalls);
        var blocked = Assert.Single(h.Store.Events, e => e.Message.StartsWith($"BLOCKED {Attacker}", StringComparison.Ordinal));
        Assert.Contains("disarmed", blocked.Message);
    }

    [Fact]
    public async Task When_the_window_ends_enforcement_resumes_through_the_reconcile()
    {
        await using var h = await Harness.StartAsync(NewFile());
        await h.Engine.BanNowAsync(Attacker, TimeSpan.FromDays(1), permanent: false, null);
        h.File.Write(TimeSpan.FromMinutes(30), h.Now, null);
        await h.Engine.HousekeepOnceAsync();
        Assert.Empty(h.Firewall.Blocked);

        h.Time.Advance(TimeSpan.FromMinutes(31));
        await h.Engine.HousekeepOnceAsync();

        Assert.False(h.Engine.IsDisarmed);
        Assert.Null(h.Engine.DisarmedUntilUtc);
        Assert.Contains(Attacker, h.Firewall.Blocked);
        Assert.False(File.Exists(h.File.Path));

        var rearmed = Assert.Single(h.Store.Events, e => e.Message.StartsWith("REARMED ", StringComparison.Ordinal));
        Assert.Equal(LogEventLevel.Warning, rearmed.Level);
        Assert.Equal(WinGuardEventIds.Rearmed, WinGuardEventIds.For(rearmed));
    }

    [Fact]
    public async Task A_ban_recorded_while_disarmed_is_enforced_after_it()
    {
        await using var h = await Harness.StartAsync(NewFile());
        h.File.Write(TimeSpan.FromMinutes(30), h.Now, null);
        await h.Engine.HousekeepOnceAsync();
        await h.Engine.BanNowAsync(Attacker, TimeSpan.FromDays(1), permanent: false, null);
        Assert.Empty(h.Firewall.Blocked);

        h.Time.Advance(TimeSpan.FromMinutes(31));
        await h.Engine.HousekeepOnceAsync();

        Assert.Contains(Attacker, h.Firewall.Blocked);
    }

    [Fact]
    public async Task The_window_closes_on_time_even_if_housekeeping_has_not_run()
    {
        await using var h = await Harness.StartAsync(NewFile());
        h.File.Write(TimeSpan.FromMinutes(30), h.Now, null);
        await h.Engine.HousekeepOnceAsync();

        h.Time.Advance(TimeSpan.FromMinutes(31));

        // A hung housekeeping pass must not extend the window.
        Assert.False(h.Engine.IsDisarmed);
        await h.Engine.BanNowAsync(Attacker, TimeSpan.FromDays(1), permanent: false, null);
        Assert.Contains(Attacker, h.Firewall.Blocked);
    }

    [Fact]
    public async Task Rearming_early_restores_the_rules_on_the_next_pass()
    {
        await using var h = await Harness.StartAsync(NewFile());
        await h.Engine.BanNowAsync(Attacker, TimeSpan.FromDays(1), permanent: false, null);
        h.File.Write(TimeSpan.FromMinutes(30), h.Now, null);
        await h.Engine.HousekeepOnceAsync();

        Assert.True(h.File.Delete());
        await h.Engine.HousekeepOnceAsync();

        Assert.False(h.Engine.IsDisarmed);
        Assert.Contains(Attacker, h.Firewall.Blocked);
        Assert.Contains(h.Store.Events, e => e.Message.StartsWith("REARMED ", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_disarm_survives_a_restart_until_it_expires()
    {
        var file = NewFile();
        var store = new FakeStore();
        var firewall = new FakeFirewall();
        var time = new FakeTimeProvider(T0);
        await store.UpsertBanAsync(new BanEntry
        {
            IpAddress = Attacker,
            Source = ProtocolSource.Rdp,
            BannedAtUtc = Now,
            ExpiresUtc = Now.AddDays(1),
            OffenseCount = 1,
        });
        firewall.Block(Attacker);
        file.Write(TimeSpan.FromMinutes(30), Now, null);

        await using (var restarted = await Harness.StartAsync(file, store, firewall, time))
        {
            Assert.True(restarted.Engine.IsDisarmed);
            Assert.Empty(firewall.Blocked);
            Assert.Empty(firewall.SyncRulesCalls);
        }

        time.Advance(TimeSpan.FromMinutes(31));
        await using var later = await Harness.StartAsync(file, store, firewall, time);

        Assert.False(later.Engine.IsDisarmed);
        Assert.Contains(Attacker, firewall.Blocked);
        Assert.False(File.Exists(file.Path));
    }

    [Fact]
    public async Task A_window_that_ended_while_the_service_was_down_is_logged_and_disarms_nothing()
    {
        var file = NewFile();
        file.Write(TimeSpan.FromMinutes(30), Now.AddHours(-2), null);

        await using var h = await Harness.StartAsync(file);

        Assert.False(h.Engine.IsDisarmed);
        var refused = Assert.Single(h.Store.Events, e => e.Message.StartsWith("DISARM REFUSED ", StringComparison.Ordinal));
        Assert.Equal(WinGuardEventIds.DisarmRefused, WinGuardEventIds.For(refused));
        Assert.Contains("window ended", refused.Message);
        Assert.False(File.Exists(file.Path));
    }

    [Fact]
    public async Task A_corrupt_file_at_start_up_disarms_nothing_and_stays_for_inspection()
    {
        var store = new FakeStore();
        var firewall = new FakeFirewall();
        await store.UpsertBanAsync(new BanEntry
        {
            IpAddress = Attacker,
            Source = ProtocolSource.Rdp,
            BannedAtUtc = Now,
            ExpiresUtc = Now.AddDays(1),
            OffenseCount = 1,
        });
        WriteRaw("not json");

        await using var h = await Harness.StartAsync(NewFile(), store, firewall);

        Assert.False(h.Engine.IsDisarmed);
        Assert.Equal(0, firewall.ClearAllCallCount);
        Assert.Contains(Attacker, firewall.Blocked);
        Assert.Single(h.Store.Events, e => e.Message.StartsWith("DISARM REFUSED ", StringComparison.Ordinal));
        Assert.True(File.Exists(FilePath));
    }

    [Fact]
    public async Task A_bad_file_is_reported_once_however_many_passes_see_it()
    {
        await using var h = await Harness.StartAsync(NewFile());
        WriteRaw("not json");

        await h.Engine.HousekeepOnceAsync();
        await h.Engine.HousekeepOnceAsync();
        await h.Engine.HousekeepOnceAsync();

        Assert.Single(h.Store.Events, e => e.Message.StartsWith("DISARM REFUSED ", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_new_problem_after_a_good_file_is_reported_again()
    {
        await using var h = await Harness.StartAsync(NewFile());

        WriteRaw("not json");
        await h.Engine.HousekeepOnceAsync();
        h.File.Delete();
        await h.Engine.HousekeepOnceAsync();
        WriteRaw("not json");
        await h.Engine.HousekeepOnceAsync();

        Assert.Equal(2, h.Store.Events.Count(e => e.Message.StartsWith("DISARM REFUSED ", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task A_file_that_goes_bad_during_a_window_rearms_at_once()
    {
        await using var h = await Harness.StartAsync(NewFile());
        await h.Engine.BanNowAsync(Attacker, TimeSpan.FromDays(1), permanent: false, null);
        h.File.Write(TimeSpan.FromMinutes(30), h.Now, null);
        await h.Engine.HousekeepOnceAsync();

        WriteRaw("not json");
        await h.Engine.HousekeepOnceAsync();

        Assert.False(h.Engine.IsDisarmed);
        Assert.Contains(Attacker, h.Firewall.Blocked);
        Assert.Contains(h.Store.Events, e => e.Message.StartsWith("REARMED ", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_file_written_by_someone_untrusted_never_disarms()
    {
        var file = new DisarmFile(FilePath)
        {
            TrustCheck = _ => "it is owned by S-1-5-21-1-2-3-1001, not by SYSTEM or the Administrators group",
            CreateSecured = path => new FileStream(path, FileMode.CreateNew, FileAccess.Write),
        };
        await using var h = await Harness.StartAsync(file);
        await h.Engine.BanNowAsync(Attacker, TimeSpan.FromDays(1), permanent: false, null);

        file.Write(TimeSpan.FromMinutes(30), h.Now, "not really");
        await h.Engine.HousekeepOnceAsync();

        Assert.False(h.Engine.IsDisarmed);
        Assert.Equal(0, h.Firewall.ClearAllCallCount);
        Assert.Contains(Attacker, h.Firewall.Blocked);
        var refused = Assert.Single(h.Store.Events, e => e.Message.StartsWith("DISARM REFUSED ", StringComparison.Ordinal));
        Assert.Contains("S-1-5-21-1-2-3-1001", refused.Message);
    }

    [Fact]
    public async Task Disarming_again_moves_the_end_of_the_window()
    {
        await using var h = await Harness.StartAsync(NewFile());
        h.File.Write(TimeSpan.FromMinutes(10), h.Now, null);
        await h.Engine.HousekeepOnceAsync();

        h.File.Write(TimeSpan.FromHours(2), h.Now, null);
        await h.Engine.HousekeepOnceAsync();

        Assert.Equal(h.Now.AddHours(2), h.Engine.DisarmedUntilUtc);
        Assert.Equal(1, h.Firewall.ClearAllCallCount);
        Assert.Equal(2, h.Store.Events.Count(e => e.Message.StartsWith("DISARMED ", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task Rules_that_reappear_or_outlive_a_failed_clear_are_removed_again()
    {
        await using var h = await Harness.StartAsync(NewFile());
        h.File.Write(TimeSpan.FromMinutes(30), h.Now, null);
        await h.Engine.HousekeepOnceAsync();

        h.Firewall.Block(Attacker);
        await h.Engine.HousekeepOnceAsync();

        Assert.Empty(h.Firewall.Blocked);
        Assert.Equal(2, h.Firewall.ClearAllCallCount);
    }

    [Fact]
    public async Task An_unreadable_firewall_during_a_window_is_left_alone()
    {
        await using var h = await Harness.StartAsync(NewFile());
        h.File.Write(TimeSpan.FromMinutes(30), h.Now, null);
        await h.Engine.HousekeepOnceAsync();

        h.Firewall.FailListBlocked = true;
        await h.Engine.HousekeepOnceAsync();

        Assert.Equal(1, h.Firewall.ClearAllCallCount);
        Assert.True(h.Engine.IsDisarmed);
    }

    [Fact]
    public async Task Disarming_also_clears_rules_left_over_in_report_only_mode()
    {
        await using var h = await Harness.StartAsync(NewFile(), configure: s => s.ReportOnly = true);
        h.Firewall.Block(Attacker);

        h.File.Write(TimeSpan.FromMinutes(30), h.Now, null);
        await h.Engine.HousekeepOnceAsync();

        Assert.Empty(h.Firewall.Blocked);
    }

    [Fact]
    public async Task Rearming_does_not_enforce_while_report_only_is_on()
    {
        await using var h = await Harness.StartAsync(NewFile(), configure: s => s.ReportOnly = true);
        await h.Engine.BanNowAsync(Attacker, TimeSpan.FromDays(1), permanent: false, null);
        h.File.Write(TimeSpan.FromMinutes(30), h.Now, null);
        await h.Engine.HousekeepOnceAsync();

        h.File.Delete();
        await h.Engine.HousekeepOnceAsync();

        Assert.Empty(h.Firewall.Blocked);
        Assert.Contains(h.Store.Events, e => e.Message.StartsWith("REARMED ", StringComparison.Ordinal) && e.Message.Contains("report-only"));
    }

    [Fact]
    public async Task Clearing_bans_at_start_up_while_disarmed_writes_no_rules()
    {
        var store = new FakeStore();
        var firewall = new FakeFirewall();
        await store.AddToListAsync(ListKind.Blacklist, "198.51.100.0/24");
        var file = NewFile();
        file.Write(TimeSpan.FromMinutes(30), Now, null);

        await using var h = await Harness.StartAsync(file, store, firewall, configure: s => s.ClearBansOnStartup = true);

        Assert.Empty(firewall.SyncRulesCalls);
        Assert.Empty(firewall.Blocked);
    }

    [Fact]
    public async Task Without_a_break_glass_file_configured_nothing_changes()
    {
        await using var h = await Harness.StartAsync(null);

        await h.Engine.BanNowAsync(Attacker, TimeSpan.FromDays(1), permanent: false, null);
        await h.Engine.HousekeepOnceAsync();

        Assert.False(h.Engine.IsDisarmed);
        Assert.Contains(Attacker, h.Firewall.Blocked);
    }

    [Fact]
    public async Task A_long_housekeeping_interval_cannot_delay_a_window()
    {
        // The settings allow a housekeeping interval of a day; only the poll keeps a window on time.
        var time = new ManualTimers(T0);
        var firewall = new FakeFirewall();
        var settings = new WinGuardSettings { HousekeepingInterval = TimeSpan.FromDays(1) };
        var file = NewFile();
        var engine = new BanEngine(new FakeStore(), firewall, () => settings, NullLogger<BanEngine>.Instance, time) { BreakGlass = file };
        await engine.StartAsync(CancellationToken.None);
        try
        {
            await engine.BanNowAsync(Attacker, TimeSpan.FromDays(1), permanent: false, null);
            file.Write(TimeSpan.FromMinutes(1), Now, null);

            await WaitUntilAsync(() =>
            {
                time.FireNext();
                return engine.IsDisarmed && firewall.Blocked.Count == 0;
            });

            await WaitUntilAsync(() =>
            {
                time.FireNext();
                return firewall.Blocked.Contains(Attacker);
            });

            Assert.False(engine.IsDisarmed);
            Assert.True(time.UtcNow - T0 < TimeSpan.FromMinutes(2), "the window outlasted its poll");
        }
        finally
        {
            await engine.StopAsync(CancellationToken.None);
        }
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        var started = Environment.TickCount64;
        while (!condition())
        {
            Assert.True(Environment.TickCount64 - started < 10_000, "timed out");
            await Task.Delay(5);
        }
    }

    // ---- the verbs ----

    private sealed class Terminal
    {
        public StringWriter Out { get; } = new();

        public StringWriter Error { get; } = new();
    }

    private static BreakGlassCommands.FirewallClearer Clears(bool works = true, List<string>? log = null) =>
        (out string? error) =>
        {
            log?.Add("clear");
            error = works ? null : "MpsSvc is stopped";
            return works;
        };

    [Fact]
    public void Disarm_records_the_window_and_clears_the_firewall_without_any_service()
    {
        var console = new Terminal();
        var file = NewFile();
        var clears = new List<string>();

        var exit = BreakGlassCommands.Disarm(["--disarm"], file, Clears(log: clears), elevated: true, @"HOST\admin", new FakeTimeProvider(T0), console.Out, console.Error);

        Assert.Equal(0, exit);
        Assert.Single(clears);
        var state = file.Read(Now);
        Assert.Equal(DisarmStatus.Active, state.Status);
        Assert.Equal(Now.AddMinutes(60), state.UntilUtc);
        Assert.Contains("disarmed until", console.Out.ToString());
        Assert.Equal(string.Empty, console.Error.ToString());
    }

    [Fact]
    public void Minutes_set_the_window()
    {
        var file = NewFile();
        var console = new Terminal();

        var exit = BreakGlassCommands.Disarm(["--disarm", "--minutes", "5"], file, Clears(), true, null, new FakeTimeProvider(T0), console.Out, console.Error);

        Assert.Equal(0, exit);
        Assert.Equal(Now.AddMinutes(5), file.Read(Now).UntilUtc);
    }

    [Theory]
    [InlineData("--minutes")]
    [InlineData("--minutes", "0")]
    [InlineData("--minutes", "-5")]
    [InlineData("--minutes", "1441")]
    [InlineData("--minutes", "99999999999999")]
    [InlineData("--minutes", "soon")]
    [InlineData("--minutes", "5", "--force")]
    [InlineData("--forever")]
    public void A_bad_command_line_changes_nothing(params string[] options)
    {
        var console = new Terminal();
        var clears = new List<string>();
        var file = NewFile();

        var exit = BreakGlassCommands.Disarm(["--disarm", .. options], file, Clears(log: clears), true, null, new FakeTimeProvider(T0), console.Out, console.Error);

        Assert.Equal(2, exit);
        Assert.Empty(clears);
        Assert.False(File.Exists(file.Path));
        Assert.Contains("1440", console.Error.ToString());
    }

    [Theory]
    [InlineData(1)]
    [InlineData(1440)]
    public void The_bounds_of_the_window_are_accepted(int minutes)
    {
        var window = BreakGlassCommands.ParseWindow(["--disarm", "--MINUTES", minutes.ToString()], out var problem);

        Assert.Null(problem);
        Assert.Equal(TimeSpan.FromMinutes(minutes), window);
    }

    [Fact]
    public void Disarm_refuses_a_prompt_that_is_not_elevated()
    {
        var console = new Terminal();
        var clears = new List<string>();
        var file = NewFile();

        var exit = BreakGlassCommands.Disarm(["--disarm"], file, Clears(log: clears), elevated: false, null, new FakeTimeProvider(T0), console.Out, console.Error);

        Assert.Equal(1, exit);
        Assert.Empty(clears);
        Assert.False(File.Exists(file.Path));
        Assert.Contains("elevated", console.Error.ToString());
    }

    [Fact]
    public void A_firewall_that_cannot_be_cleared_is_reported_but_the_disarm_stands()
    {
        var console = new Terminal();
        var file = NewFile();

        var exit = BreakGlassCommands.Disarm(["--disarm"], file, Clears(works: false), true, null, new FakeTimeProvider(T0), console.Out, console.Error);

        Assert.Equal(1, exit);
        Assert.Equal(DisarmStatus.Active, file.Read(Now).Status);
        Assert.Contains("MpsSvc is stopped", console.Error.ToString());
    }

    [Fact]
    public void A_file_that_cannot_be_written_still_clears_the_firewall_and_says_what_that_means()
    {
        var console = new Terminal();
        var clears = new List<string>();
        var missing = new DisarmFile(Path.Combine(_folder, "missing", DisarmFile.FileName))
        {
            CreateSecured = path => new FileStream(path, FileMode.CreateNew, FileAccess.Write),
        };

        var exit = BreakGlassCommands.Disarm(["--disarm"], missing, Clears(log: clears), true, null, new FakeTimeProvider(T0), console.Out, console.Error);

        Assert.Equal(1, exit);
        Assert.Single(clears);
        Assert.Contains("puts the rules back", console.Error.ToString());
        Assert.Contains("Removed all WinGuard firewall rules", console.Out.ToString());
    }

    [Fact]
    public void A_written_file_the_service_would_ignore_is_a_failure_not_a_success()
    {
        var console = new Terminal();
        var file = new DisarmFile(FilePath)
        {
            TrustCheck = _ => "it is owned by nobody",
            CreateSecured = path => new FileStream(path, FileMode.CreateNew, FileAccess.Write),
        };

        var exit = BreakGlassCommands.Disarm(["--disarm"], file, Clears(), true, null, new FakeTimeProvider(T0), console.Out, console.Error);

        Assert.Equal(1, exit);
        Assert.Contains("would ignore it", console.Error.ToString());
        Assert.DoesNotContain("disarmed until", console.Out.ToString());
    }

    [Fact]
    public void Rearm_removes_the_file()
    {
        var console = new Terminal();
        var file = NewFile();
        file.Write(TimeSpan.FromMinutes(5), Now, null);

        Assert.Equal(0, BreakGlassCommands.Rearm(file, elevated: true, console.Out, console.Error));

        Assert.False(File.Exists(file.Path));
        Assert.Contains("Rearmed", console.Out.ToString());
    }

    [Fact]
    public void Rearm_also_removes_a_file_nobody_trusts()
    {
        var console = new Terminal();
        WriteRaw("not json");

        Assert.Equal(0, BreakGlassCommands.Rearm(new DisarmFile(FilePath), elevated: true, console.Out, console.Error));

        Assert.False(File.Exists(FilePath));
    }

    [Fact]
    public void Rearm_when_not_disarmed_is_fine_and_says_so()
    {
        var console = new Terminal();

        Assert.Equal(0, BreakGlassCommands.Rearm(NewFile(), elevated: true, console.Out, console.Error));

        Assert.Contains("not disarmed", console.Out.ToString());
    }

    [Fact]
    public void Rearm_refuses_a_prompt_that_is_not_elevated()
    {
        var console = new Terminal();
        var file = NewFile();
        file.Write(TimeSpan.FromMinutes(5), Now, null);

        Assert.Equal(1, BreakGlassCommands.Rearm(file, elevated: false, console.Out, console.Error));

        Assert.True(File.Exists(file.Path));
    }

    [Fact]
    public void The_doctor_warns_about_a_disarm_and_about_a_refused_file()
    {
        var until = Now.AddMinutes(5);

        Assert.Equal((true, "armed"), BreakGlassCommands.DescribeForDoctor(DisarmState.None, null));

        var (activeOk, activeDetail) = BreakGlassCommands.DescribeForDoctor(new DisarmState(DisarmStatus.Active, until), null);
        Assert.False(activeOk);
        Assert.Contains("DISARMED until 2026-03-01 12:05:00Z", activeDetail);

        var (refusedOk, refusedDetail) = BreakGlassCommands.DescribeForDoctor(new DisarmState(DisarmStatus.Invalid, Problem: "it is not valid JSON"), null);
        Assert.False(refusedOk);
        Assert.Contains("it is not valid JSON", refusedDetail);
    }

    [Fact]
    public void The_doctor_notices_a_service_still_behind_the_file()
    {
        var status = new ServiceStatusDto { Disarmed = true, DisarmedUntilUtc = Now };

        Assert.False(BreakGlassCommands.DescribeForDoctor(DisarmState.None, status).Ok);
    }

    [Fact]
    public void The_status_line_appears_only_while_disarmed()
    {
        Assert.Null(BreakGlassCommands.DescribeForStatus(null));
        Assert.Contains("DISARMED until 2026-03-01 12:00:00Z", BreakGlassCommands.DescribeForStatus(Now));
    }

    private sealed class Harness : IAsyncDisposable
    {
        private readonly List<LogEvent> _published = [];

        public FakeStore Store { get; private init; } = null!;

        public FakeFirewall Firewall { get; private init; } = null!;

        public FakeTimeProvider Time { get; private init; } = null!;

        public DisarmFile File { get; private init; } = null!;

        public BanEngine Engine { get; private set; } = null!;

        public IReadOnlyList<LogEvent> Published => _published;

        public DateTime Now => Time.GetUtcNow().UtcDateTime;

        public static async Task<Harness> StartAsync(
            DisarmFile? file,
            FakeStore? store = null,
            FakeFirewall? firewall = null,
            FakeTimeProvider? time = null,
            Action<WinGuardSettings>? configure = null)
        {
            var settings = new WinGuardSettings { HousekeepingInterval = TimeSpan.FromHours(6) };
            configure?.Invoke(settings);

            var harness = new Harness
            {
                Store = store ?? new FakeStore(),
                Firewall = firewall ?? new FakeFirewall(),
                Time = time ?? new FakeTimeProvider(T0),
                File = file!,
            };

            harness.Engine = new BanEngine(
                harness.Store,
                harness.Firewall,
                () => settings,
                NullLogger<BanEngine>.Instance,
                harness.Time,
                new RecordingPublisher(harness._published))
            {
                BreakGlass = file,
            };

            await harness.Engine.StartAsync(CancellationToken.None);
            return harness;
        }

        public ValueTask DisposeAsync() => new(Engine.StopAsync(CancellationToken.None));

        private sealed class RecordingPublisher(List<LogEvent> events) : WinGuard.Core.Abstractions.IEventPublisher
        {
            public void Publish(LogEvent logEvent)
            {
                lock (events)
                {
                    events.Add(logEvent);
                }
            }
        }
    }

    /// <summary>A clock whose timers fire one at a time when the test says so, moving time to each.</summary>
    private sealed class ManualTimers(DateTimeOffset start) : TimeProvider
    {
        private readonly object _gate = new();
        private readonly List<Timer> _timers = [];
        private DateTimeOffset _now = start;

        public DateTimeOffset UtcNow
        {
            get
            {
                lock (_gate)
                {
                    return _now;
                }
            }
        }

        public override DateTimeOffset GetUtcNow() => UtcNow;

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            var timer = new Timer(this, callback, state);
            timer.Change(dueTime, period);
            return timer;
        }

        /// <summary>Fires the earliest timer. Without one pending, the engine is still busy: nothing moves.</summary>
        public void FireNext()
        {
            Timer? next;
            lock (_gate)
            {
                next = _timers.OrderBy(timer => timer.Due).FirstOrDefault();
                if (next is null)
                {
                    return;
                }

                _timers.Remove(next);
                _now = next.Due;
            }

            next.Fire();
        }

        private sealed class Timer(ManualTimers owner, TimerCallback callback, object? state) : ITimer
        {
            public DateTimeOffset Due { get; private set; }

            public void Fire() => callback(state);

            public bool Change(TimeSpan dueTime, TimeSpan period)
            {
                lock (owner._gate)
                {
                    owner._timers.Remove(this);
                    if (dueTime != Timeout.InfiniteTimeSpan)
                    {
                        Due = owner._now + dueTime;
                        owner._timers.Add(this);
                    }
                }

                return true;
            }

            public void Dispose() => Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);

            public ValueTask DisposeAsync()
            {
                Dispose();
                return ValueTask.CompletedTask;
            }
        }
    }
}
