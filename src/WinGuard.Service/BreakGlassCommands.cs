using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Extensions.Logging.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Engine;
using WinGuard.Core.Firewall;
using WinGuard.Core.Ipc;

namespace WinGuard.Service;

/// <summary>
/// The break-glass verbs, for an administrator locked out by bad rules, working from a hypervisor
/// console, a scheduled task or remote PowerShell. Neither talks to the service: it may be stopped
/// or stuck. <c>--disarm</c> records the request in the <see cref="DisarmFile"/> and removes the
/// firewall rules itself; a running service follows the file within seconds.
/// </summary>
internal static class BreakGlassCommands
{
    private const int UsageError = 2;

    /// <summary>Removes all WinGuard firewall rules; false and a reason when it could not.</summary>
    internal delegate bool FirewallClearer(out string? error);

    /// <summary><c>--disarm [--minutes N]</c> for this machine.</summary>
    [SupportedOSPlatform("windows")]
    public static int Disarm(string[] args)
    {
        using var identity = WindowsIdentity.GetCurrent();
        return Disarm(args, new DisarmFile(Defaults.DisarmFilePath), ClearRules, IsAdministrator(identity), identity.Name, TimeProvider.System, Console.Out, Console.Error);
    }

    /// <summary><c>--rearm</c> for this machine.</summary>
    [SupportedOSPlatform("windows")]
    public static int Rearm()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return Rearm(new DisarmFile(Defaults.DisarmFilePath), IsAdministrator(identity), Console.Out, Console.Error);
    }

    /// <summary>
    /// The file goes first, so a running service cannot put the rules back behind this command, and
    /// a failure of one step does not stop the other: rules gone for now beat a lockout, and a
    /// recorded disarm still ends the lockout once the firewall can be reached.
    /// </summary>
    internal static int Disarm(
        string[] args,
        DisarmFile file,
        FirewallClearer clearFirewall,
        bool elevated,
        string? by,
        TimeProvider time,
        TextWriter output,
        TextWriter error)
    {
        if (ParseWindow(args, out var problem) is not { } window)
        {
            error.WriteLine(problem);
            return UsageError;
        }

        if (!elevated)
        {
            error.WriteLine("--disarm needs an elevated (Run as administrator) prompt.");
            return 1;
        }

        var now = time.GetUtcNow().UtcDateTime;
        var recorded = TryRecord(file, window, now, by, error);
        var cleared = clearFirewall(out var clearError);

        if (recorded is { } until)
        {
            output.WriteLine($"WinGuard is disarmed until {until:u} ({window.TotalMinutes:0} minute(s)). Nothing is enforced until then; --rearm ends it early.");
        }
        else
        {
            error.WriteLine("Nothing is recorded, so a running service puts the rules back at its next reconcile. Stop the service to keep them away.");
        }

        if (cleared)
        {
            output.WriteLine("Removed all WinGuard firewall rules.");
        }
        else
        {
            error.WriteLine($"Failed to remove WinGuard firewall rules: {clearError}");
        }

        return recorded is not null && cleared ? 0 : 1;
    }

    internal static int Rearm(DisarmFile file, bool elevated, TextWriter output, TextWriter error)
    {
        if (!elevated)
        {
            error.WriteLine("--rearm needs an elevated (Run as administrator) prompt.");
            return 1;
        }

        try
        {
            output.WriteLine(file.Delete()
                ? "Rearmed. A running service restores the firewall rules within seconds; a stopped one does at its next start."
                : "WinGuard was not disarmed.");
            return 0;
        }
        catch (Exception ex)
        {
            error.WriteLine($"Could not remove {file.Path}: {ex.Message}");
            return 1;
        }
    }

    /// <summary>The window asked for, or null and a message. Out-of-range values are refused, not silently changed.</summary>
    internal static TimeSpan? ParseWindow(string[] args, out string? problem)
    {
        var maxMinutes = (int)DisarmFile.MaxWindow.TotalMinutes;
        var usage = $"Usage: winguard-svc --disarm [--minutes N], N from 1 to {maxMinutes} (default {DisarmFile.DefaultWindow.TotalMinutes:0}).";
        problem = null;

        // args[0] is "--disarm".
        switch (args.Length)
        {
            case 1:
                return DisarmFile.DefaultWindow;

            case 3 when args[1].ToLowerInvariant() is "--minutes" or "/minutes"
                && int.TryParse(args[2], NumberStyles.None, CultureInfo.InvariantCulture, out var minutes)
                && minutes >= 1
                && minutes <= maxMinutes:
                return TimeSpan.FromMinutes(minutes);

            default:
                problem = usage;
                return null;
        }
    }

    /// <summary>How the disarm state reads in <c>--doctor</c>. The file decides; the service only follows it.</summary>
    internal static (bool Ok, string Detail) DescribeForDoctor(DisarmState local, ServiceStatusDto? status) => local.Status switch
    {
        DisarmStatus.Active => (false, $"DISARMED until {local.UntilUtc:u}: nothing is enforced; --rearm ends it early"),
        DisarmStatus.Invalid or DisarmStatus.Untrusted => (false, $"armed, but a break-glass file is being ignored because {local.Problem}"),
        _ when status?.Disarmed == true => (false, $"the service still reports a disarm until {status.DisarmedUntilUtc:u}"),
        _ => (true, "armed"),
    };

    /// <summary>The line <c>--status</c> adds while disarmed, or null.</summary>
    internal static string? DescribeForStatus(DateTime? untilUtc) => untilUtc is { } until
        ? $"DISARMED until {until:u}: firewall rules removed, nothing is enforced. --rearm ends it early."
        : null;

    /// <summary>Records the disarm and reads it back the way the engine will; returns the end of the window.</summary>
    private static DateTime? TryRecord(DisarmFile file, TimeSpan window, DateTime now, string? by, TextWriter error)
    {
        try
        {
            file.Write(window, now, by);
            var check = file.Read(now);
            if (check.Status == DisarmStatus.Active)
            {
                return check.UntilUtc;
            }

            error.WriteLine($"The disarm file was written, but the service would ignore it: {check.Problem}.");
        }
        catch (Exception ex)
        {
            error.WriteLine($"Could not write {file.Path}: {ex.Message}");
        }

        return null;
    }

    [SupportedOSPlatform("windows")]
    private static bool ClearRules(out string? error) =>
        new WindowsFirewall(NullLogger<WindowsFirewall>.Instance).TryClearAll(out error);

    [SupportedOSPlatform("windows")]
    private static bool IsAdministrator(WindowsIdentity identity) =>
        new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
}
