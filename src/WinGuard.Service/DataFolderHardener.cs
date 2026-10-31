using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace WinGuard.Service;

/// <summary>Something that was not trusted and was moved out of the way.</summary>
/// <param name="OriginalPath">Where it was.</param>
/// <param name="MovedTo">Where it is now.</param>
/// <param name="Reason">Why it was not trusted.</param>
internal sealed record QuarantinedItem(string OriginalPath, string MovedTo, string Reason);

/// <summary>What <see cref="DataFolderHardener.Harden"/> did.</summary>
/// <param name="Failure">Why the folder could not be secured, or null when it was.</param>
/// <param name="Quarantined">What was moved aside; can hold entries next to a failure.</param>
internal sealed record HardeningReport(string? Failure, IReadOnlyList<QuarantinedItem> Quarantined);

/// <summary>
/// What separates a test from the real thing. The defaults are the only values the product uses:
/// giving a file to the Administrators group takes elevation, so the tests keep the owner and
/// pick which items count as foreign, and everything else runs for real in a temporary folder.
/// </summary>
internal sealed class HardeningProfile
{
    private static readonly SecurityIdentifier SystemSid = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier AdministratorsSid = new(WellKnownSidType.BuiltinAdministratorsSid, null);

    /// <summary>Who owns every item afterwards.</summary>
    public SecurityIdentifier Owner { get; init; } = AdministratorsSid;

    /// <summary>Who gets full control of every item afterwards.</summary>
    public IReadOnlyList<SecurityIdentifier> FullControl { get; init; } = [SystemSid, AdministratorsSid];

    /// <summary>Whether an item may stay, given its path below the folder ("." for the folder itself) and its owner.</summary>
    public Func<string, SecurityIdentifier?, bool> IsTrusted { get; init; } = (_, owner) => IsTrustedOwner(owner);

    /// <summary>Lets an elevated run reach items whose ACL shuts the administrators out.</summary>
    public bool UseBackupPrivileges { get; init; } = true;

    /// <summary>For the tests: runs on a directory that was judged and is about to be read through its handle.</summary>
    public Action<string>? BeforeDescending { get; init; }

    /// <summary>The rule itself: SYSTEM or the Administrators group, which a standard user cannot make an owner.</summary>
    public static bool IsTrustedOwner(SecurityIdentifier? owner) =>
        owner is not null && (owner.Equals(SystemSid) || owner.Equals(AdministratorsSid));
}

/// <summary>
/// Leaves a data folder to SYSTEM and the Administrators alone, whoever got there first. The setup
/// (<c>winguard-svc --harden-data</c>) and <c>--install</c> both run this, so the logic exists once.
/// <para>
/// It replaces recursive <c>icacls</c>, which had two faults. It followed junctions below the
/// folder, so a standard user could point one at any folder and have setup re-own it. And it made
/// whatever it found Administrators-owned, which turned a planted database or <c>disarm.json</c>
/// into something every later check trusts. The owner is the one thing a standard user cannot
/// forge, because only an elevated process can make the Administrators group an owner, so it is
/// read before anything is changed.
/// </para>
/// <para>
/// The walk is top-down and goes through handles alone. Every item is opened by name relative to
/// the handle of its parent, without following a reparse point, judged by that handle, and secured
/// through it; a move opens the name once more and checks by file id that it is the same object. A
/// path is never resolved again, so a directory swapped for a junction behind the walk's back
/// changes nothing. A directory is locked before it is listed, so nothing new can appear in it. A
/// foreign directory moves as a whole and is never entered. Each item gets its security descriptor
/// directly, one call per object: <c>SetNamedSecurityInfo</c> and <c>SetSecurityInfo</c> would
/// propagate inherited entries through the tree on their own.
/// </para>
/// <para>
/// Foreign content is moved aside rather than refused: setup that stops for a stray file leaves a
/// machine without protection or updates until someone works out why. Nothing is deleted. Links go
/// too, because a link is only a name and moving it does not touch its target. Setup does stop when
/// something cannot be moved, since going on would mean trusting it. The folder itself being a link
/// is refused as well: an administrator may have put the data on another disk that way, and that is
/// not for setup to undo.
/// </para>
/// </summary>
internal sealed class DataFolderHardener
{
    /// <summary>Quarantine folders in the data folder start with this; the walk does not enter them.</summary>
    internal const string QuarantinePrefix = "Quarantine-";

    /// <summary>Holds the original paths and the reasons, next to what was moved.</summary>
    internal const string ManifestName = "quarantine.txt";

    private const string LogFolderName = "Logs";
    private const int MaxRootAttempts = 3;

    private readonly HardeningProfile _profile;
    private readonly byte[] _directorySecurity;
    private readonly byte[] _fileSecurity;
    private readonly List<QuarantinedItem> _quarantined = [];
    private readonly string _stamp = $"{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}"[..24];

    private string _root = string.Empty;
    private string? _quarantinePath;

    /// <summary>Creates the routine; one instance hardens one folder.</summary>
    /// <param name="profile">The test seam; the product's defaults when null.</param>
    public DataFolderHardener(HardeningProfile? profile = null)
    {
        _profile = profile ?? new HardeningProfile();
        _directorySecurity = BuildSecurity(inheritable: true);
        _fileSecurity = BuildSecurity(inheritable: false);
    }

    /// <summary>
    /// Secures the folder, creating it when it is missing. Can run again after a failure: what was
    /// done stays done. Never throws for anything the file system does.
    /// </summary>
    /// <param name="folder">Full path of the data folder.</param>
    public HardeningReport Harden(string folder)
    {
        _root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(folder));
        try
        {
            if (_profile.UseBackupPrivileges)
            {
                Native.TryEnableBackupPrivileges();
            }

            using var rootHandle = OpenRoot(_root);
            Secure(rootHandle, isDirectory: true, _root);
            Walk(rootHandle, _root, relative: string.Empty);
            EnsureLogFolder();
            WriteManifest();
            return new HardeningReport(null, _quarantined);
        }
        catch (Exception ex) when (ex is HardeningException or IOException or UnauthorizedAccessException or Win32Exception)
        {
            WriteManifest();
            return new HardeningReport(ex.Message, _quarantined);
        }
    }

    // ---- the folder itself ----

    /// <summary>
    /// Opens the folder, or what stands in its place. A foreign one moves aside whole and a new one
    /// takes its place: only a new object is free of handles its creator may still hold, and such a
    /// handle could put the ACL back after it was replaced. ProgramData lets any user create a
    /// folder, so someone can get in between the two steps; then the same thing happens again.
    /// </summary>
    private SafeFileHandle OpenRoot(string root)
    {
        for (var attempt = 0; attempt < MaxRootAttempts; attempt++)
        {
            var handle = Native.CreateFileW(root, Native.DirectoryAccess, Native.ShareAll, IntPtr.Zero, Native.OpenExisting, Native.OpenNoFollow, IntPtr.Zero);
            if (handle.IsInvalid)
            {
                var error = Marshal.GetLastWin32Error();
                handle.Dispose();
                if (error is not (Native.ErrorFileNotFound or Native.ErrorPathNotFound))
                {
                    throw new HardeningException($"{root} could not be opened: {new Win32Exception(error).Message}");
                }

                CreateSecuredDirectory(root);
                continue;
            }

            var item = Inspect(handle, root);
            if (item.IsLink)
            {
                handle.Dispose();
                throw new HardeningException($"{root} is a link, not a folder, which may mean another user prepared it. Remove it and try again.");
            }

            var distrust = item.IsDirectory ? Distrust(item, ".") : "it is a file, not a folder";
            if (distrust is null)
            {
                return handle;
            }

            handle.Dispose();
            MoveRootAside(item, root, distrust);
            CreateSecuredDirectory(root);
        }

        throw new HardeningException($"{root} keeps being replaced by something this routine cannot trust. Find out what creates it and try again.");
    }

    private void MoveRootAside(in ItemFacts item, string root, string reason)
    {
        var parent = Path.GetDirectoryName(root) ?? throw new HardeningException($"{root} has no parent folder to move it to.");
        using var parentHandle = Native.CreateFileW(parent, Native.ParentAccess, Native.ShareAll, IntPtr.Zero, Native.OpenExisting, Native.BackupSemantics, IntPtr.Zero);
        if (parentHandle.IsInvalid)
        {
            throw new HardeningException($"{parent} could not be opened: {LastError()}");
        }

        var destination = Path.Combine(parent, $"{Path.GetFileName(root)}.quarantine-{_stamp}-{_quarantined.Count + 1}");
        MoveAside(parentHandle, Path.GetFileName(root), item, destination, root, reason);
        _quarantined.Add(new QuarantinedItem(root, destination, reason));
    }

    // ---- what is inside ----

    private void Walk(SafeFileHandle directory, string path, string relative)
    {
        _profile.BeforeDescending?.Invoke(path);
        foreach (var name in ListNames(directory, path))
        {
            var childPath = Path.Combine(path, name);
            var childRelative = relative.Length == 0 ? name : Path.Combine(relative, name);

            using var child = Native.OpenItem(directory, name, out var status);
            if (Native.IsGone(status))
            {
                continue; // Removed meanwhile: a running service rotates logs and drops -shm files.
            }

            if (status != 0)
            {
                throw new HardeningException($"{childPath} could not be opened: {Native.StatusText(status)}");
            }

            var item = Inspect(child, childPath);
            var distrust = Distrust(item, childRelative);
            if (distrust is not null)
            {
                Quarantine(directory, name, item, childPath, distrust);
            }
            else if (item.IsDirectory)
            {
                Secure(child, isDirectory: true, childPath);

                // Holds what is already out of the way; whatever is in there stays as it is.
                if (relative.Length == 0 && name.StartsWith(QuarantinePrefix, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                Walk(child, childPath, childRelative);
            }
            else
            {
                Secure(child, isDirectory: false, childPath);
            }
        }
    }

    /// <summary>Why an item cannot stay, or null. The owner comes last: a link's owner says nothing about its target.</summary>
    private string? Distrust(in ItemFacts item, string relative)
    {
        if (item.IsLink)
        {
            return "it is a junction or symbolic link";
        }

        // One file under two names: securing this one would change the other, wherever it is.
        if (!item.IsDirectory && item.LinkCount > 1)
        {
            return $"it has {item.LinkCount} hard links, so changing it would change a file elsewhere";
        }

        return _profile.IsTrusted(relative, item.Owner)
            ? null
            : $"it is owned by {item.Owner?.Value ?? "nobody"}, not by SYSTEM or the Administrators group";
    }

    private void Quarantine(SafeFileHandle parent, string name, in ItemFacts item, string path, string reason)
    {
        var destination = Path.Combine(QuarantineFolder(), $"{_quarantined.Count + 1:D3}-{name}");
        MoveAside(parent, name, item, destination, path, reason);
        _quarantined.Add(new QuarantinedItem(path, destination, reason));
    }

    /// <summary>
    /// At the top of the data folder, created on the first foreign item, so a healthy folder gets
    /// none. The folder is locked by now, so nobody else can get at the name, which is new anyway.
    /// </summary>
    private string QuarantineFolder()
    {
        if (_quarantinePath is null)
        {
            var path = Path.Combine(_root, QuarantinePrefix + _stamp);
            CreateSecuredDirectory(path);
            _quarantinePath = path;
        }

        return _quarantinePath;
    }

    // ---- one item ----

    private readonly record struct ItemFacts(bool IsDirectory, bool IsLink, uint LinkCount, SecurityIdentifier? Owner, (uint Volume, ulong File) Id);

    private static ItemFacts Inspect(SafeFileHandle handle, string path)
    {
        if (!Native.GetFileInformationByHandle(handle, out var info))
        {
            throw new HardeningException($"{path} could not be read: {LastError()}");
        }

        return new ItemFacts(
            (info.FileAttributes & Native.AttributeDirectory) != 0,
            (info.FileAttributes & Native.AttributeReparsePoint) != 0,
            info.NumberOfLinks,
            ReadOwner(handle, path),
            info.Id);
    }

    private static SecurityIdentifier? ReadOwner(SafeFileHandle handle, string path)
    {
        _ = Native.GetKernelObjectSecurity(handle, Native.OwnerInformation, null, 0, out var needed);
        var buffer = new byte[needed];
        if (!Native.GetKernelObjectSecurity(handle, Native.OwnerInformation, buffer, needed, out _))
        {
            throw new HardeningException($"{path} could not be read: {LastError()}");
        }

        return new RawSecurityDescriptor(buffer, 0).Owner;
    }

    private void Secure(SafeFileHandle handle, bool isDirectory, string path)
    {
        var information = Native.OwnerInformation | Native.DaclInformation | Native.ProtectedDaclInformation;
        if (!Native.SetKernelObjectSecurity(handle, information, isDirectory ? _directorySecurity : _fileSecurity))
        {
            throw new HardeningException($"{path} could not be secured: {LastError()}");
        }
    }

    /// <summary>
    /// Moves one name, and only if it still is what was judged. Moving needs DELETE, and asking for
    /// that when the item is first opened would clash with anyone sharing it without delete: the
    /// service with its database open, or a prompt whose current directory is the log folder.
    /// ReOpenFile would keep to the same object but refuses directories, so this opens by name and
    /// compares the file ids. A moved link stays a link: nothing here touches its target.
    /// </summary>
    private static void MoveAside(SafeFileHandle parent, string name, in ItemFacts item, string destination, string path, string reason)
    {
        using var deletable = Native.OpenChild(parent, name, Native.DeleteAccess, 0, out var status);
        var problem = status != 0
            ? Native.StatusText(status)
            : !Native.GetFileInformationByHandle(deletable, out var info) ? LastError()
            : info.Id != item.Id ? "It changed while it was being examined."
            : Native.Rename(deletable, destination) is var error and not 0 ? new Win32Exception(error).Message
            : null;
        if (problem is not null)
        {
            throw new HardeningException(
                $"{path} cannot be trusted because {reason}, and could not be moved aside: {problem} "
                + "Close whatever has it open, or remove it by hand, and try again.");
        }
    }

    private static List<string> ListNames(SafeFileHandle directory, string path)
    {
        const int NextEntryOffset = 0;
        const int NameLengthOffset = 60;
        const int NameOffset = 68;

        var names = new List<string>();
        var buffer = new byte[64 * 1024];
        var information = Native.FileFullDirectoryRestartInfo;
        while (Native.GetFileInformationByHandleEx(directory, information, buffer, (uint)buffer.Length))
        {
            information = Native.FileFullDirectoryInfo;
            var entry = 0;
            while (true)
            {
                var length = BitConverter.ToInt32(buffer, entry + NameLengthOffset);
                var name = Encoding.Unicode.GetString(buffer, entry + NameOffset, length);
                if (name is not ("." or ".."))
                {
                    names.Add(name);
                }

                var next = BitConverter.ToInt32(buffer, entry + NextEntryOffset);
                if (next == 0)
                {
                    break;
                }

                entry += next;
            }
        }

        var error = Marshal.GetLastWin32Error();
        return error == Native.ErrorNoMoreFiles
            ? names
            : throw new HardeningException($"{path} could not be listed: {new Win32Exception(error).Message}");
    }

    // ---- new directories ----

    /// <summary>Protected from its first moment. A directory that exists by now is left to the caller's next look at it.</summary>
    private void CreateSecuredDirectory(string path)
    {
        var pinned = GCHandle.Alloc(_directorySecurity, GCHandleType.Pinned);
        try
        {
            var attributes = new Native.SecurityAttributes
            {
                Length = Marshal.SizeOf<Native.SecurityAttributes>(),
                SecurityDescriptor = pinned.AddrOfPinnedObject(),
            };

            if (!Native.CreateDirectoryW(path, ref attributes) && Marshal.GetLastWin32Error() != Native.ErrorAlreadyExists)
            {
                throw new HardeningException($"{path} could not be created: {LastError()}");
            }
        }
        finally
        {
            pinned.Free();
        }
    }

    /// <summary>
    /// Made here, not by setup: a folder setup creates belongs to whoever runs it, which on some
    /// systems is the administrator's own account, and the next upgrade would call that foreign.
    /// </summary>
    private void EnsureLogFolder() => CreateSecuredDirectory(Path.Combine(_root, LogFolderName));

    /// <summary>Best effort: the report carries the same list, and a failed write must not hide it.</summary>
    private void WriteManifest()
    {
        if (_quarantinePath is null)
        {
            return;
        }

        try
        {
            File.WriteAllLines(
                Path.Combine(_quarantinePath, ManifestName),
                _quarantined.Select(item => $"{item.OriginalPath} -> {item.MovedTo}: {item.Reason}"));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Nothing else can be done.
        }
    }

    private byte[] BuildSecurity(bool inheritable)
    {
        var flags = inheritable ? "OICI" : string.Empty;
        var entries = string.Concat(_profile.FullControl.Select(sid => $"(A;{flags};FA;;;{sid.Value})"));
        var descriptor = new RawSecurityDescriptor($"O:{_profile.Owner.Value}D:P{entries}");
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        return bytes;
    }

    private static string LastError() => new Win32Exception(Marshal.GetLastWin32Error()).Message;

    private sealed class HardeningException(string message) : Exception(message);

    private static class Native
    {
        internal const uint ShareAll = 0x7;
        internal const uint OpenExisting = 3;

        internal const uint DirectoryAccess = ItemAccess | FileListDirectory | FileTraverse;
        internal const uint DeleteAccess = Delete | FileReadAttributes | Synchronize;
        internal const uint ParentAccess = FileTraverse | FileReadAttributes | Synchronize;

        internal const uint BackupSemantics = 0x02000000;
        internal const uint OpenNoFollow = BackupSemantics | 0x00200000;

        internal const uint AttributeDirectory = 0x10;
        internal const uint AttributeReparsePoint = 0x400;

        internal const uint OwnerInformation = 0x1;
        internal const uint DaclInformation = 0x4;
        internal const uint ProtectedDaclInformation = 0x80000000;

        internal const int FileFullDirectoryInfo = 14;
        internal const int FileFullDirectoryRestartInfo = 15;

        internal const int ErrorFileNotFound = 2;
        internal const int ErrorPathNotFound = 3;
        internal const int ErrorNoMoreFiles = 18;
        internal const int ErrorAlreadyExists = 183;

        // None of these takes part in sharing checks, so no open handle can get in their way.
        private const uint ItemAccess = ReadControl | WriteDac | WriteOwner | FileReadAttributes | Synchronize;

        private const uint Delete = 0x00010000;
        private const uint ReadControl = 0x00020000;
        private const uint WriteDac = 0x00040000;
        private const uint WriteOwner = 0x00080000;
        private const uint Synchronize = 0x00100000;
        private const uint FileListDirectory = 0x1;
        private const uint FileTraverse = 0x20;
        private const uint FileReadAttributes = 0x80;

        private const uint ObjCaseInsensitive = 0x40;
        private const uint NtFileOpen = 1;
        private const uint NtOpenNoFollow = 0x00200000 | 0x00004000 | 0x00000020; // reparse point, backup intent, synchronous
        private const uint NtDirectoryFile = 0x1;
        private const uint NtNonDirectoryFile = 0x40;

        private const int StatusNotADirectory = unchecked((int)0xC0000103);
        private const int StatusDeletePending = unchecked((int)0xC0000056);
        private const int StatusObjectNameNotFound = unchecked((int)0xC0000034);
        private const int StatusObjectPathNotFound = unchecked((int)0xC000003A);

        private const int FileRenameInfo = 3;
        private const uint TokenAdjustPrivileges = 0x20;
        private const uint TokenQuery = 0x8;
        private const uint PrivilegeEnabled = 0x2;

        // Pack: a FILETIME is two DWORDs, not a QWORD.
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        internal struct ByHandleFileInformation
        {
            public uint FileAttributes;
            public ulong CreationTime;
            public ulong LastAccessTime;
            public ulong LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;

            public readonly (uint Volume, ulong File) Id => (VolumeSerialNumber, ((ulong)FileIndexHigh << 32) | FileIndexLow);
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SecurityAttributes
        {
            public int Length;
            public IntPtr SecurityDescriptor;
            public int InheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct UnicodeString
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ObjectAttributes
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IoStatusBlock
        {
            public IntPtr Status;
            public IntPtr Information;
        }

        // Pack: a LUID is two DWORDs, not a QWORD.
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        private struct TokenPrivileges
        {
            public uint PrivilegeCount;
            public long Luid;
            public uint Attributes;
        }

        /// <summary>Whether an open failed because the item is gone, which is no failure at all.</summary>
        internal static bool IsGone(int status) =>
            status is StatusObjectNameNotFound or StatusObjectPathNotFound or StatusDeletePending;

        internal static string StatusText(int status) => new Win32Exception(RtlNtStatusToDosError(status)).Message;

        /// <summary>
        /// Opens an item for judging, and a directory for listing as well. The right to list is
        /// the right to read data, which on a file is subject to sharing, so a file is opened
        /// without it. A junction counts as a directory here.
        /// </summary>
        internal static SafeFileHandle OpenItem(SafeFileHandle parent, string name, out int status)
        {
            var handle = OpenChild(parent, name, DirectoryAccess, NtDirectoryFile, out status);
            if (status != StatusNotADirectory)
            {
                return handle;
            }

            handle.Dispose();
            return OpenChild(parent, name, ItemAccess, NtNonDirectoryFile, out status);
        }

        /// <summary>
        /// Opens one name below a directory handle without following a reparse point, like openat
        /// with O_NOFOLLOW. CreateFile cannot do this: it only takes a path, and every component of
        /// a path but the last is followed.
        /// </summary>
        internal static SafeFileHandle OpenChild(SafeFileHandle parent, string name, uint access, uint options, out int status)
        {
            var buffer = Marshal.StringToHGlobalUni(name);
            var unicode = new UnicodeString
            {
                Length = (ushort)(name.Length * sizeof(char)),
                MaximumLength = (ushort)(name.Length * sizeof(char)),
                Buffer = buffer,
            };

            var pinned = GCHandle.Alloc(unicode, GCHandleType.Pinned);
            try
            {
                var attributes = new ObjectAttributes
                {
                    Length = Marshal.SizeOf<ObjectAttributes>(),
                    RootDirectory = parent.DangerousGetHandle(),
                    ObjectName = pinned.AddrOfPinnedObject(),
                    Attributes = ObjCaseInsensitive,
                };

                status = NtCreateFile(out var handle, access, ref attributes, out _, IntPtr.Zero, 0, ShareAll, NtFileOpen, NtOpenNoFollow | options, IntPtr.Zero, 0);
                GC.KeepAlive(parent);
                return handle;
            }
            finally
            {
                pinned.Free();
                Marshal.FreeHGlobal(buffer);
            }
        }

        /// <summary>
        /// Renames through the handle, so what moves is what was judged. Never replaces anything.
        /// </summary>
        /// <returns>0, or the Win32 error.</returns>
        internal static int Rename(SafeFileHandle item, string destinationPath)
        {
            // FILE_RENAME_INFO: a BOOLEAN, a HANDLE at pointer alignment (NULL for a full path), a
            // DWORD, then the name, which goes to NTFS as it is and so has to be an NT path.
            var rootOffset = IntPtr.Size;
            var lengthOffset = rootOffset + IntPtr.Size;
            var nameOffset = lengthOffset + sizeof(int);
            var nameBytes = Encoding.Unicode.GetBytes(@"\??\" + destinationPath);
            var size = nameOffset + nameBytes.Length + sizeof(char);

            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.WriteIntPtr(buffer, 0, IntPtr.Zero);
                Marshal.WriteIntPtr(buffer, rootOffset, IntPtr.Zero);
                Marshal.WriteInt32(buffer, lengthOffset, nameBytes.Length);
                Marshal.Copy(nameBytes, 0, buffer + nameOffset, nameBytes.Length);
                Marshal.WriteInt16(buffer, nameOffset + nameBytes.Length, 0);

                return SetFileInformationByHandle(item, FileRenameInfo, buffer, (uint)size) ? 0 : Marshal.GetLastWin32Error();
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        /// <summary>
        /// Best effort: without them an unelevated run simply fails at the first item it may not
        /// touch, which is the message worth reading.
        /// </summary>
        internal static void TryEnableBackupPrivileges()
        {
            if (!OpenProcessToken(GetCurrentProcess(), TokenAdjustPrivileges | TokenQuery, out var token))
            {
                return;
            }

            using (token)
            {
                foreach (var name in new[] { "SeBackupPrivilege", "SeRestorePrivilege" })
                {
                    if (LookupPrivilegeValueW(null, name, out var luid))
                    {
                        var privileges = new TokenPrivileges { PrivilegeCount = 1, Luid = luid, Attributes = PrivilegeEnabled };
                        _ = AdjustTokenPrivileges(token, false, ref privileges, 0, IntPtr.Zero, IntPtr.Zero);
                    }
                }
            }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern SafeFileHandle CreateFileW(string fileName, uint access, uint share, IntPtr securityAttributes, uint disposition, uint flags, IntPtr template);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CreateDirectoryW(string path, ref SecurityAttributes attributes);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation information);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int informationClass, byte[] buffer, uint bufferSize);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetKernelObjectSecurity(SafeFileHandle handle, uint information, byte[]? descriptor, uint length, out uint needed);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetKernelObjectSecurity(SafeFileHandle handle, uint information, byte[] descriptor);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetFileInformationByHandle(SafeFileHandle file, int informationClass, IntPtr buffer, uint bufferSize);

        [DllImport("ntdll.dll")]
        private static extern int NtCreateFile(
            out SafeFileHandle handle,
            uint access,
            ref ObjectAttributes attributes,
            out IoStatusBlock status,
            IntPtr allocationSize,
            uint fileAttributes,
            uint share,
            uint disposition,
            uint options,
            IntPtr extendedAttributes,
            uint extendedAttributesLength);

        [DllImport("ntdll.dll")]
        private static extern int RtlNtStatusToDosError(int status);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool OpenProcessToken(IntPtr process, uint access, out SafeAccessTokenHandle token);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool LookupPrivilegeValueW(string? system, string name, out long luid);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AdjustTokenPrivileges(SafeAccessTokenHandle token, [MarshalAs(UnmanagedType.Bool)] bool disableAll, ref TokenPrivileges state, uint length, IntPtr previous, IntPtr returnLength);
    }
}
