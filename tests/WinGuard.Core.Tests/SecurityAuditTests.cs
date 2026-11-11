using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using WinGuard.Core.Config;
using WinGuard.Core.Ipc;
using WinGuard.Core.Model;
using WinGuard.Service;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>
/// The fixes from the audit before the repository went public: a ban on some ports that its
/// address walks around, IPv6 counted per /64, the folder a service may be registered from, and the
/// owner of the pipe the console talks to.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class SecurityAuditTests : IDisposable
{
    private static readonly DateTimeOffset T0 = new(2026, 5, 1, 12, 0, 0, TimeSpan.Zero);

    private const string Attacker = "203.0.113.50";

    private static readonly PortSet RdpPort = PortSet.Parse(["3389"]);
    private static readonly SecurityIdentifier LocalSystem = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier Users = new(WellKnownSidType.BuiltinUsersSid, null);
    private static readonly SecurityIdentifier SomeUser = new("S-1-5-21-1000000000-2000000000-3000000000-1001");

    private readonly string _folder = Path.Combine(Path.GetTempPath(), "wg-audit-" + Guid.NewGuid().ToString("N"));

    public SecurityAuditTests() => Directory.CreateDirectory(_folder);

    public void Dispose()
    {
        try
        {
            Directory.Delete(_folder, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // A leftover in the temp folder is not worth a failed test.
        }
    }

    private static SecurityIdentifier Me
    {
        get
        {
            using var identity = WindowsIdentity.GetCurrent();
            return identity.User!;
        }
    }

    // ---------- a ban on some ports only ----------

    private static async Task SendRdpFailuresAsync(EngineHarness h, int count)
    {
        for (var i = 0; i < count; i++)
        {
            await h.ProcessAsync(h.Fail(Attacker, ProtocolSource.Rdp, detector: "4625"));
        }
    }

    [Fact]
    public async Task Failures_that_go_on_behind_a_port_scoped_ban_widen_it_to_all_ports()
    {
        await using var h = await EngineHarness.StartAsync(T0, s => s.Rdp.BlockedPorts = ["3389"]);
        var threshold = h.Settings.ThresholdFor(ProtocolSource.Rdp);
        await SendRdpFailuresAsync(h, threshold);
        Assert.Equal(RdpPort, h.Firewall.PortsOf(Attacker));

        // 3389 is closed to it, so these 4625s come from SMB or WinRM.
        h.Time.Advance(TimeSpan.FromMinutes(2));
        await SendRdpFailuresAsync(h, threshold - 1);
        Assert.Equal(RdpPort, h.Firewall.PortsOf(Attacker));

        await SendRdpFailuresAsync(h, 1);

        Assert.Equal(PortSet.All, h.Firewall.PortsOf(Attacker));
        Assert.Equal(PortProfiles.AllPorts, (await h.Store.GetBanAsync(Attacker))!.PortScope);
    }

    [Fact]
    public async Task Failures_right_after_a_port_scoped_ban_are_still_passed_over()
    {
        await using var h = await EngineHarness.StartAsync(T0, s => s.Rdp.BlockedPorts = ["3389"]);
        var threshold = h.Settings.ThresholdFor(ProtocolSource.Rdp);
        await SendRdpFailuresAsync(h, threshold);

        // Events the log delivers late and connections opened before the block.
        h.Time.Advance(TimeSpan.FromSeconds(30));
        await SendRdpFailuresAsync(h, threshold * 2);

        Assert.Equal(RdpPort, h.Firewall.PortsOf(Attacker));
        Assert.Contains(h.Store.Events, e => e.Message == $"SKIPPED {Attacker} (already banned)");
    }

    [Fact]
    public async Task Failures_behind_an_all_ports_ban_stay_passed_over()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        var threshold = h.Settings.ThresholdFor(ProtocolSource.Rdp);
        await SendRdpFailuresAsync(h, threshold);
        var ban = await h.Store.GetBanAsync(Attacker);

        h.Time.Advance(TimeSpan.FromMinutes(2));
        await SendRdpFailuresAsync(h, threshold * 2);

        var after = await h.Store.GetBanAsync(Attacker);
        Assert.Equal(ban!.OffenseCount, after!.OffenseCount);
        Assert.Equal(ban.ExpiresUtc, after.ExpiresUtc);
    }

    [Fact]
    public async Task Report_only_blocks_nothing_so_later_failures_do_not_widen_a_scoped_ban()
    {
        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            s.Rdp.BlockedPorts = ["3389"];
            s.ReportOnly = true;
        });
        var threshold = h.Settings.ThresholdFor(ProtocolSource.Rdp);
        await SendRdpFailuresAsync(h, threshold);

        h.Time.Advance(TimeSpan.FromMinutes(2));
        await SendRdpFailuresAsync(h, threshold);

        Assert.Equal(nameof(ProtocolSource.Rdp), (await h.Store.GetBanAsync(Attacker))!.PortScope);
    }

    // ---------- IPv6 ----------

    [Fact]
    public void Ipv6_is_counted_per_64_unless_the_setting_says_otherwise()
    {
        var settings = new WinGuardSettings();

        Assert.Equal(64, settings.Ipv6AggregatePrefixLength);
    }

    [Fact]
    public async Task By_default_addresses_rotating_inside_one_64_are_one_attacker()
    {
        await using var h = await EngineHarness.StartAsync(T0);
        var threshold = h.Settings.ThresholdFor(ProtocolSource.MsSql);

        for (var i = 1; i <= threshold; i++)
        {
            await h.ProcessAsync(h.Fail($"2001:db8:1:2::{i:x}"));
        }

        Assert.NotNull(await h.Store.GetBanAsync("2001:db8:1:2::/64"));
    }

    // ---------- the folder a service is registered from ----------

    [Fact]
    public void A_folder_only_its_installer_and_the_administrators_can_change_is_accepted()
    {
        var security = new DirectorySecurity();
        security.SetOwner(Me);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(Rule(LocalSystem, FileSystemRights.FullControl));
        security.AddAccessRule(Rule(Administrators, FileSystemRights.FullControl));
        security.AddAccessRule(Rule(Me, FileSystemRights.FullControl));
        security.AddAccessRule(Rule(Users, FileSystemRights.ReadAndExecute));

        Assert.Empty(InstallFolderCheck.Writers(security, Me, isFolder: true));
    }

    [Theory]
    [InlineData(FileSystemRights.Modify)]
    [InlineData(FileSystemRights.WriteData)]
    [InlineData(FileSystemRights.Delete)]
    [InlineData(FileSystemRights.ChangePermissions)]
    public void A_folder_the_users_group_can_change_is_refused(FileSystemRights rights)
    {
        var security = new DirectorySecurity();
        security.SetOwner(Administrators);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(Rule(Administrators, FileSystemRights.FullControl));
        security.AddAccessRule(Rule(Users, rights));

        var writers = InstallFolderCheck.Writers(security, Me, isFolder: true);

        Assert.Single(writers);
    }

    [Fact]
    public void A_folder_owned_by_another_account_is_refused_whatever_its_access_list_says()
    {
        var security = new DirectorySecurity();
        security.SetOwner(SomeUser);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(Rule(Administrators, FileSystemRights.FullControl));

        var writers = InstallFolderCheck.Writers(security, Me, isFolder: true);

        Assert.Contains(writers, writer => writer.EndsWith("(owner)", StringComparison.Ordinal));
    }

    [Fact]
    public void An_entry_that_only_applies_to_what_is_created_later_does_not_count_against_the_folder()
    {
        var security = new DirectorySecurity();
        security.SetOwner(Administrators);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(
            Users,
            FileSystemRights.Modify,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.InheritOnly,
            AccessControlType.Allow));

        // The executable inherits that entry, and is refused for it there.
        Assert.Empty(InstallFolderCheck.Writers(security, Me, isFolder: true));
    }

    [Fact]
    public void The_whole_check_refuses_an_executable_in_a_folder_opened_to_users()
    {
        // The temp folder's own entries are whatever this machine has, so the folder gets its own.
        var directory = new DirectoryInfo(_folder);
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(Rule(LocalSystem, FileSystemRights.FullControl));
        security.AddAccessRule(Rule(Administrators, FileSystemRights.FullControl));
        security.AddAccessRule(Rule(Me, FileSystemRights.FullControl));
        directory.SetAccessControl(security);
        var executable = Path.Combine(_folder, "winguard-svc.exe");
        File.WriteAllText(executable, "not a program");
        Assert.Null(InstallFolderCheck.Problem(executable));

        security.AddAccessRule(new FileSystemAccessRule(
            Users,
            FileSystemRights.Modify,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        directory.SetAccessControl(security);

        var problem = InstallFolderCheck.Problem(executable);

        Assert.NotNull(problem);
        Assert.Contains(_folder, problem);
        Assert.Contains("Nothing was installed", problem);
    }

    private static FileSystemAccessRule Rule(SecurityIdentifier who, FileSystemRights rights) => new(
        who,
        rights,
        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
        PropagationFlags.None,
        AccessControlType.Allow);

    // ---------- the owner of the pipe ----------

    [Fact]
    public void A_pipe_owned_by_system_or_the_administrators_is_the_service()
    {
        Assert.True(PipeServerIdentity.EvaluateOwner(LocalSystem, LocalSystem, 4).Trusted);
        Assert.True(PipeServerIdentity.EvaluateOwner(Administrators, LocalSystem, 4).Trusted);
    }

    [Fact]
    public void A_pipe_owned_by_the_administrator_running_the_console_engine_is_trusted()
    {
        // With UAC off an administrator's objects belong to the account, not to the group.
        Assert.True(PipeServerIdentity.EvaluateOwner(SomeUser, SomeUser, 1234).Trusted);
    }

    [Fact]
    public void A_pipe_someone_else_created_is_refused_although_a_service_now_has_its_process_id()
    {
        var result = PipeServerIdentity.EvaluateOwner(SomeUser, LocalSystem, 1234);

        Assert.False(result.Trusted);
        Assert.Contains(SomeUser.Value, result.Problem);
        Assert.Contains("process 1234", result.Problem);
    }

    [Fact]
    public void A_pipe_whose_owner_cannot_be_read_is_refused()
    {
        Assert.False(PipeServerIdentity.EvaluateOwner(null, LocalSystem, 1234).Trusted);
    }

    [Fact]
    public async Task The_owner_is_read_through_the_connection_the_console_opens()
    {
        var name = "WinGuard-test-" + Guid.NewGuid().ToString("N");
        using var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        var accepted = server.WaitForConnectionAsync();
        using var pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
        await pipe.ConnectAsync(5000);
        await accepted;

        var owner = PipeServerIdentity.ReadOwner(pipe);

        // An elevated administrator's objects belong to the group, everyone else's to the account.
        Assert.NotNull(owner);
        Assert.True(Me.Equals(owner) || Administrators.Equals(owner), $"owner was {owner}");
    }
}
