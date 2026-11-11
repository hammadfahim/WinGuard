using System.Security.AccessControl;
using System.Security.Principal;

namespace WinGuard.Core.Updates;

/// <summary>
/// The folder an installer is downloaded to before it runs elevated. It is kept apart from the
/// data folder and belongs to SYSTEM and the Administrators alone. Any user may create folders in
/// <c>%ProgramData%</c>, so one that is already there is judged by its owner, the one thing a
/// standard user cannot forge: a folder somebody else made is refused, not repaired.
/// </summary>
public static class UpdateFolder
{
    private static readonly SecurityIdentifier SystemSid = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier AdministratorsSid = new(WellKnownSidType.BuiltinAdministratorsSid, null);

    /// <summary>Where installers are downloaded to.</summary>
    public static string DefaultPath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WinGuard Updates");

    /// <summary>Makes sure the folder exists, is closed to everyone but administrators, and is empty.</summary>
    /// <param name="folder">Full path; <see cref="DefaultPath"/> in the product.</param>
    /// <returns>The folder's path.</returns>
    /// <exception cref="UpdateException">The folder cannot be trusted or prepared.</exception>
    public static string Prepare(string folder) =>
        Prepare(folder, owner => owner is not null && (owner.Equals(SystemSid) || owner.Equals(AdministratorsSid)), AdministratorsSid, [SystemSid, AdministratorsSid]);

    /// <summary>The same with the owner and the access list open to the tests, which do not run elevated.</summary>
    internal static string Prepare(string folder, Func<SecurityIdentifier?, bool> isTrustedOwner, SecurityIdentifier? newOwner, IReadOnlyList<SecurityIdentifier> fullControl)
    {
        try
        {
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            foreach (var sid in fullControl)
            {
                security.AddAccessRule(new FileSystemAccessRule(
                    sid,
                    FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow));
            }

            if (newOwner is not null)
            {
                security.SetOwner(newOwner);
            }

            var info = new DirectoryInfo(folder);
            if (!info.Exists)
            {
                // Created closed. If someone else creates it first, this changes nothing and the
                // owner check below refuses theirs.
                info.Create(security);
                info.Refresh();
            }

            if (info.Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                throw new UpdateException($"'{folder}' is a link, not a folder. Remove it and try again.");
            }

            var owner = info.GetAccessControl(AccessControlSections.Owner).GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            if (!isTrustedOwner(owner))
            {
                throw new UpdateException(
                    $"'{folder}' was created by {owner?.Value ?? "an unknown account"}, not by WinGuard, so nothing is downloaded there. " +
                    "Delete that folder and try again.");
            }

            info.SetAccessControl(security);
            foreach (var entry in info.EnumerateFileSystemInfos())
            {
                // An installer from an earlier update, or anything else: nothing in here is kept.
                if (entry is DirectoryInfo directory && !entry.Attributes.HasFlag(FileAttributes.ReparsePoint))
                {
                    directory.Delete(recursive: true);
                }
                else
                {
                    entry.Delete();
                }
            }

            return info.FullName;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            throw new UpdateException($"The download folder '{folder}' could not be prepared: {ex.Message}", ex);
        }
    }
}
