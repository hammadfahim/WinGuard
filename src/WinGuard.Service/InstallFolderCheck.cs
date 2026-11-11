using System.Security.AccessControl;
using System.Security.Principal;

namespace WinGuard.Service;

/// <summary>
/// Says whether the folder a service is about to be registered from is safe to run as LocalSystem.
/// The service starts whatever file has its name in that folder, with every right there is, so
/// anyone who can write there owns the machine. Program Files is fine as Windows makes it. A folder
/// such as <c>C:\WinGuard</c> or <c>D:\Tools\WinGuard</c> inherits "Authenticated Users: Modify"
/// from its drive, and a portable copy is often extracted to exactly such a place.
/// <para>
/// Trusted are SYSTEM, the Administrators group, TrustedInstaller and the administrator running the
/// install: their own files are theirs to replace anyway. Everyone else may read and run, and no
/// more. The folder and the executable are both judged: a right on the folder lets a file be put
/// next to the executable, and a right on the executable lets it be rewritten in place.
/// </para>
/// </summary>
internal static class InstallFolderCheck
{
    /// <summary>
    /// Rights that let a file be added, replaced or opened up. The two generic values are what an
    /// entry holds when it was written as GENERIC_ALL or GENERIC_WRITE and never mapped.
    /// </summary>
    private const FileSystemRights WriteRights =
        FileSystemRights.WriteData
        | FileSystemRights.AppendData
        | FileSystemRights.Delete
        | FileSystemRights.DeleteSubdirectoriesAndFiles
        | FileSystemRights.ChangePermissions
        | FileSystemRights.TakeOwnership
        | (FileSystemRights)0x10000000
        | (FileSystemRights)0x40000000;

    private static readonly SecurityIdentifier SystemSid = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier AdministratorsSid = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier TrustedInstallerSid =
        new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

    /// <summary>
    /// Why the service must not be registered from where this executable is, or null when it may.
    /// A folder that cannot be judged is not trusted.
    /// </summary>
    /// <param name="executablePath">Full path of the service executable.</param>
    public static string? Problem(string executablePath)
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var folder = Path.GetDirectoryName(Path.GetFullPath(executablePath));
            if (string.IsNullOrEmpty(folder))
            {
                return $"The folder of '{executablePath}' could not be determined.";
            }

            const AccessControlSections sections = AccessControlSections.Access | AccessControlSections.Owner;
            var writers = Writers(new DirectoryInfo(folder).GetAccessControl(sections), identity.User, isFolder: true)
                .Concat(Writers(new FileInfo(executablePath).GetAccessControl(sections), identity.User, isFolder: false))
                .Distinct(StringComparer.Ordinal)
                .ToList();

            return writers.Count == 0 ? null : Describe(folder, writers);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SystemException)
        {
            return $"The permissions of the folder of '{executablePath}' could not be read ({ex.Message}), so it is not trusted.";
        }
    }

    /// <summary>The accounts that can change this item although they are not trusted, by name where there is one.</summary>
    /// <param name="security">The item's owner and access list.</param>
    /// <param name="installer">The account running the install.</param>
    /// <param name="isFolder">A folder's inherit-only entries say nothing about the folder itself.</param>
    internal static IReadOnlyList<string> Writers(FileSystemSecurity security, SecurityIdentifier? installer, bool isFolder)
    {
        var writers = new List<string>();
        if (security.GetOwner(typeof(SecurityIdentifier)) is SecurityIdentifier owner && !IsTrusted(owner, installer))
        {
            // An owner can always rewrite the access list, whatever it says now.
            writers.Add(Name(owner) + " (owner)");
        }

        foreach (FileSystemAccessRule rule in security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow
                || (rule.FileSystemRights & WriteRights) == 0
                || (isFolder && rule.PropagationFlags.HasFlag(PropagationFlags.InheritOnly))
                || IsTrusted((SecurityIdentifier)rule.IdentityReference, installer))
            {
                continue;
            }

            writers.Add(Name((SecurityIdentifier)rule.IdentityReference));
        }

        return writers.Distinct(StringComparer.Ordinal).ToList();
    }

    private static bool IsTrusted(SecurityIdentifier sid, SecurityIdentifier? installer) =>
        sid.Equals(SystemSid) || sid.Equals(AdministratorsSid) || sid.Equals(TrustedInstallerSid) || (installer is not null && sid.Equals(installer));

    private static string Name(SecurityIdentifier sid)
    {
        try
        {
            return sid.Translate(typeof(NTAccount)).Value;
        }
        catch (Exception ex) when (ex is IdentityNotMappedException or SystemException)
        {
            return sid.Value;
        }
    }

    private static string Describe(string folder, IReadOnlyList<string> writers) =>
        $"'{folder}' can be changed by {string.Join(", ", writers)}. A service that runs as LocalSystem from there " +
        "hands the server to whoever replaces its files. Nothing was installed. Move WinGuard to a folder under " +
        $"'{Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)}', or leave this one to administrators " +
        $"(icacls \"{folder}\" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F *S-1-5-32-545:(OI)(CI)RX), " +
        "then run --install again.";
}
