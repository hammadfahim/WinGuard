using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace WinGuard.Core.Engine;

/// <summary>What a look at the break-glass file found.</summary>
public enum DisarmStatus
{
    /// <summary>No file: WinGuard enforces as usual.</summary>
    None = 0,

    /// <summary>A valid file whose window is still open.</summary>
    Active = 1,

    /// <summary>A valid file whose window has closed.</summary>
    Expired = 2,

    /// <summary>Unreadable, malformed, or claiming a window longer than allowed. Never disarms.</summary>
    Invalid = 3,

    /// <summary>Someone other than SYSTEM or the administrators could have written it. Never disarms.</summary>
    Untrusted = 4,
}

/// <summary>The outcome of <see cref="DisarmFile.Read"/>.</summary>
/// <param name="Status">What was found.</param>
/// <param name="UntilUtc">When the window ends; set for <see cref="DisarmStatus.Active"/> and <see cref="DisarmStatus.Expired"/>.</param>
/// <param name="By">Who disarmed, as recorded in the file.</param>
/// <param name="Problem">Why the file was refused; set for the statuses that never disarm.</param>
public sealed record DisarmState(DisarmStatus Status, DateTime? UntilUtc = null, string? By = null, string? Problem = null)
{
    /// <summary>The state of a machine with no break-glass file.</summary>
    public static readonly DisarmState None = new(DisarmStatus.None);
}

/// <summary>
/// The break-glass drop file in the data folder. An administrator locked out by bad rules may have
/// no working pipe to the service, or no service at all, so <c>--disarm</c> records the request
/// here and the engine picks it up at start-up and in housekeeping.
/// <para>
/// Everything about reading it fails towards protection: only a well-formed file with an open
/// window of at most <see cref="MaxWindow"/>, that nobody but SYSTEM or the administrators can have
/// written, disarms anything. The data folder is ACL-hardened by the setup and by <c>--install</c>,
/// but a portable <c>--console</c> run leaves it as it is, and there a standard user can create
/// files in it. That is why the file's own owner and ACL are checked as well.
/// </para>
/// </summary>
public sealed class DisarmFile
{
    /// <summary>File name inside the data folder.</summary>
    public const string FileName = "disarm.json";

    /// <summary>The window of a <c>--disarm</c> without <c>--minutes</c>.</summary>
    public static readonly TimeSpan DefaultWindow = TimeSpan.FromMinutes(60);

    /// <summary>Longest window there is, so a forgotten disarm cannot leave the server open.</summary>
    public static readonly TimeSpan MaxWindow = TimeSpan.FromHours(24);

    // Far beyond the few fields it holds: nothing bigger gets parsed.
    private const int MaxFileBytes = 4096;
    private const int MaxByLength = 64;
    private const int FormatVersion = 1;

    private static readonly SecurityIdentifier SystemSid = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier AdministratorsSid = new(WellKnownSidType.BuiltinAdministratorsSid, null);

    // What would let an account change the file, or give itself the right to.
    private const FileSystemRights WriteRights =
        FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;

    /// <summary>Creates the accessor. Tests point it at a temporary folder.</summary>
    /// <param name="path">Full path of the file.</param>
    public DisarmFile(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        Path = path;
    }

    /// <summary>Full path of the file.</summary>
    public string Path { get; }

    /// <summary>
    /// Why an opened file cannot be trusted, or null. Giving a file away to the Administrators
    /// group needs elevation, so the tests replace this and <see cref="CreateSecured"/>.
    /// </summary>
    internal Func<FileStream, string?> TrustCheck { get; init; } = CheckAcl;

    /// <summary>Creates a new file only SYSTEM and the administrators can touch.</summary>
    internal Func<string, FileStream> CreateSecured { get; init; } = CreateAdminOnly;

    /// <summary>
    /// Reads the file. Never throws: whatever goes wrong comes back as a status that does not
    /// disarm. The file is judged by the same handle it is read from, so it cannot be swapped
    /// between the check and the read.
    /// </summary>
    /// <param name="nowUtc">The current time.</param>
    public DisarmState Read(DateTime nowUtc)
    {
        try
        {
            if (!File.Exists(Path))
            {
                return DisarmState.None;
            }

            if (File.GetAttributes(Path).HasFlag(FileAttributes.ReparsePoint))
            {
                return new DisarmState(DisarmStatus.Untrusted, Problem: "it is a link, not a file");
            }

            using var stream = new FileStream(Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (TrustCheck(stream) is { } distrust)
            {
                return new DisarmState(DisarmStatus.Untrusted, Problem: distrust);
            }

            if (stream.Length > MaxFileBytes)
            {
                return new DisarmState(DisarmStatus.Invalid, Problem: "it is too large");
            }

            using var reader = new StreamReader(stream, Encoding.UTF8);
            return Parse(reader.ReadToEnd(), nowUtc);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return DisarmState.None;
        }
        catch (Exception ex)
        {
            return new DisarmState(DisarmStatus.Invalid, Problem: "it could not be read: " + ex.Message);
        }
    }

    /// <summary>
    /// Records a disarm, replacing any earlier one. The file appears complete or not at all, so
    /// the engine can treat a file it cannot parse as corrupt rather than half-written.
    /// </summary>
    /// <param name="window">Length of the window, at most <see cref="MaxWindow"/>.</param>
    /// <param name="nowUtc">The current time.</param>
    /// <param name="by">Who is disarming; goes into the event the engine records.</param>
    /// <returns>When the window ends.</returns>
    public DateTime Write(TimeSpan window, DateTime nowUtc, string? by)
    {
        if (window <= TimeSpan.Zero || window > MaxWindow)
        {
            throw new ArgumentOutOfRangeException(nameof(window), window, $"A disarm lasts more than nothing and at most {MaxWindow.TotalMinutes:0} minutes.");
        }

        var until = nowUtc + window;
        var record = new DisarmRecord
        {
            Version = FormatVersion,
            IssuedUtc = nowUtc,
            UntilUtc = until,
            By = Clean(by),
        };

        var temporary = $"{Path}.{Guid.NewGuid():N}.tmp";
        try
        {
            using (var stream = CreateSecured(temporary))
            {
                JsonSerializer.Serialize(stream, record);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporary, Path, overwrite: true);
            return until;
        }
        finally
        {
            // Gone already after the move; left over only when something failed.
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    /// <summary>Removes the file. Returns whether there was one; failures throw.</summary>
    public bool Delete()
    {
        if (!File.Exists(Path))
        {
            return false;
        }

        File.Delete(Path);
        return true;
    }

    private static DisarmState Parse(string json, DateTime nowUtc)
    {
        DisarmRecord? record;
        try
        {
            record = JsonSerializer.Deserialize<DisarmRecord>(json);
        }
        catch (JsonException)
        {
            return new DisarmState(DisarmStatus.Invalid, Problem: "it is not valid JSON");
        }

        if (record is null || record.Version != FormatVersion)
        {
            return new DisarmState(DisarmStatus.Invalid, Problem: "its format is not recognized");
        }

        // A time without a zone could mean anything, and comparing it would treat it as UTC.
        if (record.IssuedUtc.Kind != DateTimeKind.Utc || record.UntilUtc.Kind != DateTimeKind.Utc)
        {
            return new DisarmState(DisarmStatus.Invalid, Problem: "its times are not in UTC");
        }

        // The window is bounded twice: as issued, and from now, for a clock that was set back.
        var issued = record.UntilUtc - record.IssuedUtc;
        if (issued <= TimeSpan.Zero || issued > MaxWindow)
        {
            return new DisarmState(DisarmStatus.Invalid, Problem: $"its window is not between 1 second and {MaxWindow.TotalHours:0} hours");
        }

        if (record.UntilUtc <= nowUtc)
        {
            return new DisarmState(DisarmStatus.Expired, record.UntilUtc, Clean(record.By));
        }

        if (record.UntilUtc - nowUtc > MaxWindow)
        {
            return new DisarmState(DisarmStatus.Invalid, Problem: "it ends too far in the future");
        }

        return new DisarmState(DisarmStatus.Active, record.UntilUtc, Clean(record.By));
    }

    /// <summary>Why the file's owner or ACL rule it out, or null.</summary>
    private static string? CheckAcl(FileStream stream)
    {
        var security = stream.GetAccessControl();
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (!IsAdministrative(owner))
        {
            return $"it is owned by {owner?.Value ?? "nobody"}, not by SYSTEM or the Administrators group";
        }

        foreach (FileSystemAccessRule rule in security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType == AccessControlType.Allow
                && (rule.FileSystemRights & WriteRights) != 0
                && !IsAdministrative(rule.IdentityReference as SecurityIdentifier))
            {
                return $"{rule.IdentityReference.Value} can change it";
            }
        }

        return null;
    }

    private static bool IsAdministrative(SecurityIdentifier? sid) =>
        sid is not null && (sid.Equals(SystemSid) || sid.Equals(AdministratorsSid));

    private static FileStream CreateAdminOnly(string path)
    {
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(AdministratorsSid);
        security.AddAccessRule(new FileSystemAccessRule(SystemSid, FileSystemRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(AdministratorsSid, FileSystemRights.FullControl, AccessControlType.Allow));

        return new FileInfo(path).Create(FileMode.CreateNew, FileSystemRights.Write | FileSystemRights.Read, FileShare.None, bufferSize: 4096, FileOptions.None, security);
    }

    /// <summary>The name goes into events and notifications: printable and short, whatever the file says.</summary>
    private static string? Clean(string? by)
    {
        if (string.IsNullOrWhiteSpace(by))
        {
            return null;
        }

        var printable = new string(by.Where(c => !char.IsControl(c)).Take(MaxByLength).ToArray()).Trim();
        return printable.Length == 0 ? null : printable;
    }

    private sealed class DisarmRecord
    {
        public int Version { get; set; }

        public DateTime IssuedUtc { get; set; }

        public DateTime UntilUtc { get; set; }

        public string? By { get; set; }
    }
}
