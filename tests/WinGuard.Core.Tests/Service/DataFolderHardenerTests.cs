using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using WinGuard.Core.Engine;
using WinGuard.Service;
using Xunit;
using ServiceProgram = WinGuard.Service.Program;

namespace WinGuard.Core.Tests;

/// <summary>
/// The data-folder hardening, for real, in temporary folders. Only an elevated process can give a
/// file to the Administrators group, so these tests have it keep the test account as owner and say
/// which items count as foreign. The walk, the moves, the ACLs and every handle are the real ones.
/// Nothing here goes near %ProgramData%.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DataFolderHardenerTests : IDisposable
{
    private static readonly SecurityIdentifier SystemSid = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier Users = new(WellKnownSidType.BuiltinUsersSid, null);

    private readonly string _base = Path.Combine(Path.GetTempPath(), "wg-harden-" + Guid.NewGuid().ToString("N"));
    private readonly string _data;
    private readonly string _outside;

    public DataFolderHardenerTests()
    {
        _data = Path.Combine(_base, "WinGuard");
        _outside = Path.Combine(_base, "outside");
        Directory.CreateDirectory(_data);
        Directory.CreateDirectory(_outside);
    }

    private static SecurityIdentifier Me
    {
        get
        {
            using var identity = WindowsIdentity.GetCurrent();
            return identity.User!;
        }
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_base, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Left in the temp folder.
        }
    }

    // ---- helpers ----

    /// <summary>Everything is trusted but the given paths below the folder.</summary>
    private static HardeningProfile Profile(params string[] foreign) => new()
    {
        Owner = Me,
        FullControl = [SystemSid, Administrators, Me],
        IsTrusted = (path, _) => !foreign.Contains(path, StringComparer.OrdinalIgnoreCase),
        UseBackupPrivileges = false,
    };

    private HardeningReport Harden(params string[] foreign) => new DataFolderHardener(Profile(foreign)).Harden(_data);

    private static void Junction(string link, string target)
    {
        var (exitCode, output) = ServiceProgram.RunProcess("cmd.exe", "/c", "mklink", "/J", link, target);
        Assert.True(exitCode == 0, output);
    }

    private static void HardLink(string link, string target)
    {
        var (exitCode, output) = ServiceProgram.RunProcess("cmd.exe", "/c", "mklink", "/H", link, target);
        Assert.True(exitCode == 0, output);
    }

    private string Write(string relative, string content = "x")
    {
        var path = Path.Combine(_data, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
        return path;
    }

    private static string Acl(string path) => ServiceProgram.RunProcess(Path.Combine(Environment.SystemDirectory, "icacls.exe"), path).Output;

    private static string Descriptor(string path) =>
        new FileInfo(path).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Owner | AccessControlSections.Access);

    /// <summary>A file outside the data folder, with an ACL of its own that hardening would visibly change.</summary>
    private string Victim(string name = "secret.txt")
    {
        var path = Path.Combine(_outside, name);
        File.WriteAllText(path, "precious");
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(Me, FileSystemRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.ReadAndExecute, AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(security);
        return path;
    }

    private static void AssertLockedDown(FileSystemSecurity security, string path)
    {
        Assert.True(security.AreAccessRulesProtected, path + " still inherits");
        Assert.Equal(Me, security.GetOwner(typeof(SecurityIdentifier)));
        var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>().ToList();
        Assert.All(rules, rule => Assert.True(rule.FileSystemRights.HasFlag(FileSystemRights.FullControl), path));
        Assert.Equal(
            new[] { SystemSid.Value, Administrators.Value, Me.Value }.Order(),
            rules.Select(rule => rule.IdentityReference.Value).Order());
    }

    private static void AssertFileLockedDown(string path) => AssertLockedDown(new FileInfo(path).GetAccessControl(), path);

    private static void AssertFolderLockedDown(string path) => AssertLockedDown(new DirectoryInfo(path).GetAccessControl(), path);

    // ---- finding 1: junctions ----

    [Fact]
    public void The_target_of_a_planted_junction_is_left_alone()
    {
        var secret = Victim();
        var before = Acl(secret);
        var planted = Path.Combine(_data, "planted");
        Junction(planted, _outside);

        var report = Harden();

        Assert.Null(report.Failure);
        Assert.Equal(before, Acl(secret));
        Assert.Equal("precious", File.ReadAllText(secret));
        Assert.False(Directory.Exists(planted));
        var moved = Assert.Single(report.Quarantined);
        Assert.Equal(planted, moved.OriginalPath);
        Assert.Contains("junction", moved.Reason);
        Assert.True(new DirectoryInfo(moved.MovedTo).Attributes.HasFlag(FileAttributes.ReparsePoint));
    }

    [Fact]
    public void A_junction_further_down_is_found_too()
    {
        var secret = Victim();
        var before = Acl(secret);
        Write(@"sub\deeper\file.txt");
        Junction(Path.Combine(_data, "sub", "deeper", "planted"), _outside);

        var report = Harden();

        Assert.Null(report.Failure);
        Assert.Equal(before, Acl(secret));
        Assert.EndsWith("-planted", Assert.Single(report.Quarantined).MovedTo);
        AssertFileLockedDown(Path.Combine(_data, "sub", "deeper", "file.txt"));
    }

    [Fact]
    public void A_planted_log_folder_makes_way_for_a_real_one()
    {
        var logs = Path.Combine(_data, "Logs");
        Junction(logs, _outside);

        var report = Harden();

        Assert.Null(report.Failure);
        Assert.Single(report.Quarantined);
        Assert.False(new DirectoryInfo(logs).Attributes.HasFlag(FileAttributes.ReparsePoint));
        AssertFolderLockedDown(logs);
    }

    [Fact]
    public void The_data_folder_being_a_link_is_refused_and_its_target_left_alone()
    {
        var secret = Victim();
        var before = Acl(secret);
        var link = Path.Combine(_base, "Linked");
        Junction(link, _outside);

        var report = new DataFolderHardener(Profile()).Harden(link);

        Assert.Contains("is a link", report.Failure);
        Assert.Empty(report.Quarantined);
        Assert.Equal(before, Acl(secret));
        Assert.True(new DirectoryInfo(link).Attributes.HasFlag(FileAttributes.ReparsePoint));
    }

    // ---- hard links: the same trap without a reparse point ----

    [Fact]
    public void A_hard_link_to_a_file_elsewhere_is_moved_and_the_file_left_alone()
    {
        var secret = Victim();
        var before = Acl(secret);
        var planted = Path.Combine(_data, "planted.txt");
        HardLink(planted, secret);

        var report = Harden();

        Assert.Null(report.Failure);
        Assert.Equal(before, Acl(secret));
        Assert.False(File.Exists(planted));
        Assert.Contains("hard link", Assert.Single(report.Quarantined).Reason);
    }

    // ---- finding 2: planted content is not laundered ----

    [Fact]
    public void A_planted_database_is_moved_aside_with_its_content_intact()
    {
        var planted = Write("winguard.db", "ReportOnly and a whitelist");
        var mine = Write("winguard.db-wal", "kept");

        var report = Harden("winguard.db");

        Assert.Null(report.Failure);
        Assert.False(File.Exists(planted));
        var moved = Assert.Single(report.Quarantined);
        Assert.Equal(planted, moved.OriginalPath);
        Assert.Equal("ReportOnly and a whitelist", File.ReadAllText(moved.MovedTo));
        Assert.Contains("is owned by", moved.Reason);
        Assert.StartsWith(Path.Combine(_data, DataFolderHardener.QuarantinePrefix), moved.MovedTo);
        Assert.Equal("kept", File.ReadAllText(mine));
    }

    [Fact]
    public void A_moved_item_keeps_the_owner_and_acl_it_had()
    {
        // Laundering is the whole point of the finding: what moves aside must not be cleaned on the way.
        var planted = Write("disarm.json", "{}");
        var security = new FileInfo(planted).GetAccessControl();
        security.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.Modify, AccessControlType.Allow));
        new FileInfo(planted).SetAccessControl(security);

        var report = Harden("disarm.json");

        var moved = new FileInfo(Assert.Single(report.Quarantined).MovedTo).GetAccessControl();
        Assert.Contains(
            moved.GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>(),
            rule => rule.IdentityReference.Equals(Users) && rule.FileSystemRights.HasFlag(FileSystemRights.Write));
    }

    [Fact]
    public void A_planted_disarm_file_clears_nothing_afterwards()
    {
        var path = Path.Combine(_data, DisarmFile.FileName);
        new DisarmFile(path)
        {
            TrustCheck = _ => null,
            CreateSecured = target => new FileStream(target, FileMode.CreateNew),
        }.Write(TimeSpan.FromHours(1), DateTime.UtcNow, "planted");

        var report = Harden(DisarmFile.FileName);

        Assert.Null(report.Failure);
        Assert.Single(report.Quarantined);

        // The file the service reads afterwards: nothing there, whatever the check would have said.
        Assert.Equal(DisarmStatus.None, new DisarmFile(path) { TrustCheck = _ => null }.Read(DateTime.UtcNow).Status);
    }

    [Fact]
    public void A_foreign_folder_moves_as_a_whole_and_is_never_entered()
    {
        var secret = Victim();
        var before = Acl(secret);
        var inner = Write(@"planted\inner.txt");
        var innerBefore = Descriptor(inner);
        Junction(Path.Combine(_data, "planted", "link"), _outside);

        var report = Harden("planted");

        Assert.Null(report.Failure);
        var moved = Assert.Single(report.Quarantined);
        Assert.Equal(Path.Combine(_data, "planted"), moved.OriginalPath);
        Assert.Equal(before, Acl(secret));
        Assert.Equal(innerBefore, Descriptor(Path.Combine(moved.MovedTo, "inner.txt")));
    }

    [Fact]
    public void What_was_moved_is_listed_next_to_it()
    {
        Write("planted.txt");

        var report = Harden("planted.txt");

        var moved = Assert.Single(report.Quarantined);
        var manifest = Path.Combine(Path.GetDirectoryName(moved.MovedTo)!, DataFolderHardener.ManifestName);
        var line = Assert.Single(File.ReadAllLines(manifest));
        Assert.Contains(moved.OriginalPath, line);
        Assert.Contains(moved.Reason, line);
    }

    [Fact]
    public void A_foreign_item_that_cannot_be_moved_stops_the_run_and_is_named()
    {
        var planted = Write("planted.txt");
        var mine = Write("zz-later.txt");

        // Held open without FileShare.Delete, as an attacker could to stop it being moved.
        using (new FileStream(planted, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
            var report = Harden("planted.txt");

            Assert.Contains(planted, report.Failure);
            Assert.Contains("could not be moved aside", report.Failure);
            Assert.Empty(report.Quarantined);
            Assert.True(File.Exists(planted));
        }

        Assert.True(File.Exists(mine));
    }

    [Fact]
    public void After_a_failure_a_second_run_finishes_the_job()
    {
        var planted = Write("planted.txt");
        using (new FileStream(planted, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
            Assert.NotNull(Harden("planted.txt").Failure);
        }

        var report = Harden("planted.txt");

        Assert.Null(report.Failure);
        Assert.Single(report.Quarantined);
        Assert.False(File.Exists(planted));
    }

    // ---- the folder itself ----

    [Fact]
    public void A_foreign_data_folder_moves_aside_and_a_new_one_takes_its_place()
    {
        var planted = Write("winguard.db", "planted");
        var judged = 0;
        var profile = new HardeningProfile
        {
            Owner = Me,
            FullControl = [SystemSid, Administrators, Me],
            UseBackupPrivileges = false,

            // The first look at the folder sees the planted one, the second the new one.
            IsTrusted = (path, _) => path != "." || judged++ > 0,
        };

        var report = new DataFolderHardener(profile).Harden(_data);

        Assert.Null(report.Failure);
        var moved = Assert.Single(report.Quarantined);
        Assert.Equal(_data, moved.OriginalPath);
        Assert.Equal("planted", File.ReadAllText(Path.Combine(moved.MovedTo, "winguard.db")));
        Assert.False(File.Exists(planted));
        AssertFolderLockedDown(_data);
    }

    [Fact]
    public void A_file_in_place_of_the_data_folder_moves_aside()
    {
        var path = Path.Combine(_base, "AFile");
        File.WriteAllText(path, "planted");

        var report = new DataFolderHardener(Profile()).Harden(path);

        Assert.Null(report.Failure);
        Assert.Equal("planted", File.ReadAllText(Assert.Single(report.Quarantined).MovedTo));
        AssertFolderLockedDown(path);
    }

    [Fact]
    public void Something_that_keeps_coming_back_is_not_chased_for_ever()
    {
        var report = new DataFolderHardener(new HardeningProfile
        {
            Owner = Me,
            FullControl = [SystemSid, Administrators, Me],
            UseBackupPrivileges = false,
            IsTrusted = (_, _) => false,
        }).Harden(_data);

        Assert.Contains("keeps being replaced", report.Failure);
    }

    [Fact]
    public void A_missing_folder_is_created_locked_down()
    {
        var path = Path.Combine(_base, "New");

        var report = new DataFolderHardener(Profile()).Harden(path);

        Assert.Null(report.Failure);
        Assert.Empty(report.Quarantined);
        AssertFolderLockedDown(path);
        AssertFolderLockedDown(Path.Combine(path, "Logs"));
    }

    // ---- a healthy upgrade ----

    [Fact]
    public void A_healthy_folder_loses_nothing_and_ends_up_locked_down()
    {
        var database = Write("winguard.db", "bans and settings");
        var wal = Write("winguard.db-wal", "recent writes");
        var log = Write(@"Logs\winguard-20261031.log", "log");

        var report = Harden();

        Assert.Null(report.Failure);
        Assert.Empty(report.Quarantined);
        Assert.Equal("bans and settings", File.ReadAllText(database));
        Assert.Equal("recent writes", File.ReadAllText(wal));
        Assert.Equal("log", File.ReadAllText(log));
        Assert.DoesNotContain(Directory.GetDirectories(_data), path => Path.GetFileName(path).StartsWith(DataFolderHardener.QuarantinePrefix, StringComparison.Ordinal));
        AssertFolderLockedDown(_data);
        AssertFolderLockedDown(Path.Combine(_data, "Logs"));
        AssertFileLockedDown(database);
        AssertFileLockedDown(wal);
        AssertFileLockedDown(log);
    }

    [Fact]
    public void A_database_the_old_service_still_has_open_is_secured_where_it_is()
    {
        var database = Write("winguard.db", "bans and settings");

        // The setup hardens while the service runs, and SQLite shares neither delete nor exclusive use.
        using var held = new FileStream(database, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);

        var report = Harden();

        Assert.Null(report.Failure);
        Assert.Empty(report.Quarantined);
        AssertFileLockedDown(database);
    }

    [Fact]
    public void A_file_someone_holds_exclusively_is_still_secured()
    {
        var log = Write(@"Logs\winguard.log", "log");

        // The owner and the DACL are not data, so no share mode stands in their way.
        using var held = new FileStream(log, FileMode.Open, FileAccess.ReadWrite, FileShare.None);

        Assert.Null(Harden().Failure);

        AssertFileLockedDown(log);
    }

    [Fact]
    public void Running_twice_changes_nothing()
    {
        var database = Write("winguard.db", "bans and settings");

        Assert.Null(Harden().Failure);
        var report = Harden();

        Assert.Null(report.Failure);
        Assert.Empty(report.Quarantined);
        Assert.Equal("bans and settings", File.ReadAllText(database));
    }

    [Fact]
    public void A_new_file_in_a_hardened_folder_inherits_the_protection()
    {
        Assert.Null(Harden().Failure);

        var created = Path.Combine(_data, "Logs", "new.log");
        File.WriteAllText(created, "x");

        var rules = new FileInfo(created).GetAccessControl()
            .GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .Select(rule => rule.IdentityReference)
            .ToList();
        Assert.Contains(SystemSid, rules);
        Assert.Contains(Administrators, rules);
        Assert.DoesNotContain(Users, rules);
    }

    [Fact]
    public void An_earlier_quarantine_is_not_walked_again()
    {
        var secret = Victim();
        var before = Acl(secret);
        var quarantined = Path.Combine(_data, DataFolderHardener.QuarantinePrefix + "earlier");
        Directory.CreateDirectory(quarantined);
        Junction(Path.Combine(quarantined, "001-planted"), _outside);

        var report = Harden();

        Assert.Null(report.Failure);
        Assert.Empty(report.Quarantined);
        Assert.Equal(before, Acl(secret));
        Assert.True(Directory.Exists(Path.Combine(quarantined, "001-planted")));
    }

    [Fact]
    public void A_folder_named_like_a_quarantine_gets_no_special_treatment_if_it_is_foreign()
    {
        var name = DataFolderHardener.QuarantinePrefix + "planted";
        Directory.CreateDirectory(Path.Combine(_data, name));

        var report = Harden(name);

        Assert.Equal(Path.Combine(_data, name), Assert.Single(report.Quarantined).OriginalPath);
    }

    [Fact]
    public void A_folder_named_like_a_quarantine_below_the_top_is_walked()
    {
        var path = Write(Path.Combine("sub", DataFolderHardener.QuarantinePrefix + "x", "file.txt"));

        Assert.Null(Harden().Failure);

        AssertFileLockedDown(path);
    }

    // ---- check-then-use ----

    [Fact]
    public void A_directory_swapped_for_a_junction_behind_the_walk_changes_nothing()
    {
        var secret = Victim();
        var before = Acl(secret);
        var swapped = Path.Combine(_data, "swapped");
        Write(@"swapped\inner.txt");
        var aside = Path.Combine(_base, "swapped-away");

        var profile = new HardeningProfile
        {
            Owner = Me,
            FullControl = [SystemSid, Administrators, Me],
            UseBackupPrivileges = false,
            IsTrusted = (_, _) => true,

            // The worst moment: judged, secured, and the walk is about to read it. A walk that goes
            // by path would now list and secure the victim through the junction.
            BeforeDescending = path =>
            {
                if (path == swapped)
                {
                    Directory.Move(swapped, aside);
                    Junction(swapped, _outside);
                }
            },
        };

        var report = new DataFolderHardener(profile).Harden(_data);

        Assert.Null(report.Failure);
        Assert.Equal(before, Acl(secret));
        AssertFileLockedDown(Path.Combine(aside, "inner.txt"));
    }

    // ---- the rule, and the real profile ----

    [Fact]
    public void Only_system_and_the_administrators_group_are_trusted_owners()
    {
        Assert.True(HardeningProfile.IsTrustedOwner(SystemSid));
        Assert.True(HardeningProfile.IsTrustedOwner(Administrators));
        Assert.False(HardeningProfile.IsTrustedOwner(Users));
        Assert.False(HardeningProfile.IsTrustedOwner(new SecurityIdentifier(WellKnownSidType.WorldSid, null)));
        Assert.False(HardeningProfile.IsTrustedOwner(new SecurityIdentifier("S-1-5-21-1-2-3-1001")));
        Assert.False(HardeningProfile.IsTrustedOwner(null));
    }

    [Fact]
    public void The_product_profile_gives_everything_to_the_administrators()
    {
        var profile = new HardeningProfile();

        Assert.Equal(Administrators, profile.Owner);
        Assert.Equal([SystemSid, Administrators], profile.FullControl);
        Assert.True(profile.UseBackupPrivileges);
        Assert.True(profile.IsTrusted("winguard.db", SystemSid));
        Assert.False(profile.IsTrusted("winguard.db", Users));
    }

    [Fact]
    public void A_folder_that_cannot_be_given_to_the_administrators_is_reported()
    {
        // Only an elevated process may give anything to Administrators.
        var path = Write("winguard.db");
        using var identity = WindowsIdentity.GetCurrent();
        var elevated = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);

        var report = new DataFolderHardener(new HardeningProfile { IsTrusted = (_, _) => true, UseBackupPrivileges = false }).Harden(_data);

        Assert.Equal(elevated, report.Failure is null);
        if (elevated)
        {
            Assert.Equal(Administrators, new FileInfo(path).GetAccessControl().GetOwner(typeof(SecurityIdentifier)));
        }
        else
        {
            Assert.Contains("could not be secured", report.Failure);
        }
    }

    [Fact]
    public void The_exit_code_tells_the_setup_what_happened()
    {
        var secured = new HardeningReport(null, []);
        var movedAside = new HardeningReport(null, [new QuarantinedItem("a", "b", "c")]);
        var failed = new HardeningReport("no", [new QuarantinedItem("a", "b", "c")]);

        Assert.Equal(0, ServiceProgram.Report(secured));
        Assert.Equal(3, ServiceProgram.Report(movedAside));
        Assert.Equal(1, ServiceProgram.Report(failed));
    }
}
