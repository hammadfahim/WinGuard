using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace WinGuard.Service.Ipc;

/// <summary>
/// Works out who is on the other end of a pipe connection and whether that caller may use the
/// service: only LocalSystem and elevated administrators (PLAN.md §8).
/// <para>
/// The caller is identified from the token of the client PROCESS. No impersonation is involved,
/// so it does not depend on how the client opened the pipe, and none of this code runs under a
/// restricted identity.
/// </para>
/// <para>
/// Impersonating the client is kept only as a fallback, and with care: while a thread impersonates
/// at identification level it may not open files, so anything the runtime has to load at that
/// moment (an assembly, a type) fails with <see cref="FileNotFoundException"/> — and the failure is
/// then remembered for the life of the process. Therefore <see cref="Prewarm"/> runs every code
/// path once beforehand, and the impersonated section does nothing but copy the thread's token.
/// </para>
/// </summary>
public static class PipeClientIdentity
{
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint TokenDuplicate = 0x0002;
    private const uint TokenQuery = 0x0008;

    /// <summary>Outcome of identifying a pipe client.</summary>
    /// <param name="Identified">Whether the caller's identity could be established at all.</param>
    /// <param name="Authorized">Whether that identity is LocalSystem or an elevated administrator.</param>
    /// <param name="Client">The caller's SID (and process id when known), for the log.</param>
    /// <param name="Error">Why the caller could not be identified, when it could not.</param>
    public sealed record Result(bool Identified, bool Authorized, string Client, string? Error);

    /// <summary>
    /// Loads and runs, once and under the service's own identity, everything the identification
    /// uses. Call at start-up, before the first client connects.
    /// </summary>
    public static void Prewarm()
    {
        try
        {
            using var self = WindowsIdentity.GetCurrent();
            _ = Evaluate(self, "self");
            using var thread = CaptureThreadIdentity();
        }
        catch (Exception)
        {
            // Best effort: the process-token path does not depend on this.
        }
    }

    /// <summary>Identifies the client, preferring its process token and falling back to impersonation.</summary>
    public static Result Identify(NamedPipeServerStream pipe)
    {
        ArgumentNullException.ThrowIfNull(pipe);

        var byProcess = FromClientProcess(pipe);
        if (byProcess.Identified)
        {
            return byProcess;
        }

        var byImpersonation = FromImpersonation(pipe);
        if (byImpersonation.Identified)
        {
            return byImpersonation;
        }

        return new Result(
            Identified: false,
            Authorized: false,
            Client: "unknown",
            Error: $"client process token: {byProcess.Error}; impersonation: {byImpersonation.Error}");
    }

    /// <summary>Identifies the client from the access token of the process that opened the pipe.</summary>
    public static Result FromClientProcess(NamedPipeServerStream pipe)
    {
        try
        {
            if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var processId))
            {
                return Failed("GetNamedPipeClientProcessId", Marshal.GetLastWin32Error());
            }

            using var process = OpenProcess(ProcessQueryLimitedInformation, false, processId);
            if (process.IsInvalid)
            {
                return Failed($"OpenProcess({processId})", Marshal.GetLastWin32Error());
            }

            if (!OpenProcessToken(process, TokenQuery | TokenDuplicate, out var token))
            {
                return Failed($"OpenProcessToken({processId})", Marshal.GetLastWin32Error());
            }

            using (token)
            using (var identity = new WindowsIdentity(token.DangerousGetHandle()))
            {
                return Evaluate(identity, $"pid {processId}");
            }
        }
        catch (Exception ex)
        {
            return new Result(false, false, "unknown", $"{ex.GetType().Name}: {ex.Message}");
        }
    }

    /// <summary>Identifies the client by impersonating it just long enough to copy its token.</summary>
    public static Result FromImpersonation(NamedPipeServerStream pipe)
    {
        try
        {
            WindowsIdentity? identity = null;

            // Nothing else may happen in here: see the class remarks.
            pipe.RunAsClient(() => identity = CaptureThreadIdentity());

            if (identity is null)
            {
                return new Result(false, false, "unknown", "the thread had no token while impersonating");
            }

            using (identity)
            {
                return Evaluate(identity, "impersonated");
            }
        }
        catch (Exception ex)
        {
            return new Result(false, false, "unknown", $"{ex.GetType().Name}: {ex.Message}");
        }
    }

    private static WindowsIdentity? CaptureThreadIdentity() => WindowsIdentity.GetCurrent(ifImpersonating: true);

    private static Result Evaluate(WindowsIdentity identity, string how)
    {
        var sid = identity.User;
        var client = $"{sid?.Value ?? "unknown"} ({how})";

        // PLAN §8: Administrators + LocalSystem ONLY. Service accounts (LocalService /
        // NetworkService) are NOT trusted: any third-party service running under them
        // must not be able to unban attackers or rewrite policy (review S-M1).
        if (sid is not null && sid.IsWellKnown(WellKnownSidType.LocalSystemSid))
        {
            return new Result(true, true, client, null);
        }

        // Only an ELEVATED administrator: IsInRole is true when the Administrators group is
        // enabled in the token. Under UAC a non-elevated process of an admin user carries that
        // group as deny-only and is refused, which is why the console's manifest requests elevation.
        var elevatedAdministrator = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        return new Result(true, elevatedAdministrator, client, null);
    }

    private static Result Failed(string what, int error) =>
        new(false, false, "unknown", $"{what} failed: {new Win32Exception(error).Message} (Win32 error {error})");

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint clientProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint processId);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(SafeProcessHandle process, uint desiredAccess, out SafeAccessTokenHandle token);
}
