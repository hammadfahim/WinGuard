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

    /// <summary>Identifies the server from the access token of the process that created the pipe.</summary>
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
                return Evaluate(identity.User, identity.Groups, processId);
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
