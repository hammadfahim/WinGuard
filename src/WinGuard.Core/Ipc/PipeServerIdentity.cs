using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace WinGuard.Core.Ipc;

/// <summary>
/// Works out who owns the other end of a pipe connection before the console talks to it. While the
/// service is stopped, or before its delayed start, any local user can create the service's pipe
/// name, and the console's settings carry secrets. Only a server running as LocalSystem (the
/// service) or as an elevated administrator (<c>--console</c>) is trusted; everything else, and
/// anything that cannot be established, fails closed.
/// </summary>
internal static class PipeServerIdentity
{
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint TokenQuery = 0x0008;

    /// <summary>Outcome of checking a pipe server.</summary>
    /// <param name="Trusted">Whether the server may be talked to.</param>
    /// <param name="Problem">Why not, for the console to show.</param>
    internal sealed record Result(bool Trusted, string? Problem);

    /// <summary>
    /// Identifies the server from the access token of the process that created the pipe, and from
    /// the owner of the pipe itself.
    /// </summary>
    public static Result Verify(NamedPipeClientStream pipe)
    {
        try
        {
            if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var processId))
            {
                return Unverified("GetNamedPipeServerProcessId", Marshal.GetLastWin32Error());
            }

            using var process = OpenProcess(ProcessQueryLimitedInformation, false, processId);
            if (process.IsInvalid)
            {
                return Unverified($"OpenProcess({processId})", Marshal.GetLastWin32Error());
            }

            // Query only: administrators are not granted more than that on a service's token.
            if (!OpenProcessToken(process, TokenQuery, out var token))
            {
                return Unverified($"OpenProcessToken({processId})", Marshal.GetLastWin32Error());
            }

            using (token)
            using (var identity = new WindowsIdentity(token.DangerousGetHandle()))
            {
                var creator = Evaluate(identity.User, identity.Groups, processId);
                return creator.Trusted ? EvaluateOwner(ReadOwner(pipe), identity.User, processId) : creator;
            }
        }
        catch (Exception ex)
        {
            return new Result(false, UnverifiedText($"{ex.GetType().Name}: {ex.Message}"));
        }
    }

    /// <summary>The decision itself, separate so it can be tested with any identity.</summary>
    /// <param name="user">The token's user.</param>
    /// <param name="enabledGroups">The token's enabled groups. Under UAC a non-elevated administrator holds Administrators as deny-only, which <see cref="WindowsIdentity.Groups"/> leaves out.</param>
    /// <param name="processId">The server's process id, for the message.</param>
    internal static Result Evaluate(SecurityIdentifier? user, IEnumerable<IdentityReference>? enabledGroups, uint processId)
    {
        if (user is not null && user.IsWellKnown(WellKnownSidType.LocalSystemSid))
        {
            return new Result(true, null);
        }

        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        if (enabledGroups?.Any(administrators.Equals) == true)
        {
            return new Result(true, null);
        }

        return new Result(
            false,
            $"Process {processId} ({user?.Value ?? "unknown user"}) owns the WinGuard pipe but is neither LocalSystem nor an elevated administrator, " +
            "so it is not the WinGuard service. This console will not talk to it. Find out what that process is, then restart the WinGuard service.");
    }

    /// <summary>
    /// The second half of the decision. The process id a pipe reports is the one that created it,
    /// and stays that number when the creator has handed the pipe to another process and exited:
    /// once Windows gives the number to a service, the check above would pass for a pipe a standard
    /// user made. The owner of the pipe object cannot be made to lie that way. It is set when the
    /// pipe is created, and only a process with the restore privilege can name an owner other than
    /// itself or a group it holds as owner.
    /// </summary>
    /// <param name="owner">Owner of the pipe object, or null when it could not be read.</param>
    /// <param name="serverUser">User of the process that passed <see cref="Evaluate"/>.</param>
    /// <param name="processId">The server's process id, for the message.</param>
    internal static Result EvaluateOwner(SecurityIdentifier? owner, SecurityIdentifier? serverUser, uint processId)
    {
        // A service's objects belong to SYSTEM or the Administrators group, an elevated
        // administrator's to that group or, with UAC off, to the administrator.
        if (owner is not null
            && (owner.IsWellKnown(WellKnownSidType.LocalSystemSid)
                || owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)
                || (serverUser is not null && owner.Equals(serverUser))))
        {
            return new Result(true, null);
        }

        return new Result(
            false,
            $"The WinGuard pipe was created by {owner?.Value ?? "an account that could not be read"}, not by process {processId} that now reports it, " +
            "so it is not the WinGuard service. This console will not talk to it. Restart the WinGuard service, and find out what created that pipe.");
    }

    /// <summary>Reads the owner through the connection itself, so it is the pipe that was opened and no other.</summary>
    internal static SecurityIdentifier? ReadOwner(PipeStream pipe) =>
        pipe.GetAccessControl().GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;

    private static Result Unverified(string what, int error) =>
        new(false, UnverifiedText($"{what} failed: {new Win32Exception(error).Message} (Win32 error {error})"));

    private static string UnverifiedText(string reason) =>
        $"This console could not verify that the WinGuard pipe belongs to the service, so it will not talk to it. {reason}";

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint serverProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint processId);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(SafeProcessHandle process, uint desiredAccess, out SafeAccessTokenHandle token);
}
