using System.Globalization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using WinGuard.Core.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Ipc;
using WinGuard.Core.Model;
using WinGuard.Core.Firewall;

namespace WinGuard.Service;

/// <summary>
/// Management CLI verbs that talk to the running service over its pipe (they need an elevated
/// prompt, like the GUI). Powers <c>--status</c>, <c>--list-bans</c>, <c>--ban</c>, <c>--unban</c>
/// and <c>--doctor</c>, so headless Server Core machines can be administered without the GUI.
/// </summary>
internal static class CliCommands
{
    /// <summary>Status of the running service, one line per engine. Exit 1 when the service is unreachable.</summary>
    public static async Task<int> StatusAsync()
    {
        using var client = new PipeClient();
        ServiceStatusDto? status;
        try
        {
            status = await client.GetStatusAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Could not reach the WinGuard service: " + ex.Message);
            return 1;
        }

        if (status is null)
        {
            Console.Error.WriteLine(DescribeUnavailable(client.LastProblem, client.LastRequestError));
            return 1;
        }

        Console.WriteLine($"WinGuard {status.Version} (protocol {status.ProtocolVersion}), up since {status.StartedUtc:u} UTC");
        Console.WriteLine($"Active bans: {status.ActiveBans}" + (status.ReportOnly ? "  [REPORT-ONLY MODE]" : string.Empty));
        foreach (var engine in status.Engines)
        {
            Console.WriteLine(
                $"  {engine.Name,-28} {(engine.Running ? "running" : "inactive"),-8} today: {engine.DetectionsToday,-6} bans: {engine.ActiveBans}" +
                (engine.Enabled ? string.Empty : "  (disabled)"));
        }

        return 0;
    }

    /// <summary>Active bans in a compact table. Exit 1 when the service is unreachable.</summary>
    public static async Task<int> ListBansAsync()
    {
        using var client = new PipeClient();
        List<BanDto>? bans;
        try
        {
            bans = await client.ListBansAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Could not reach the WinGuard service: " + ex.Message);
            return 1;
        }

        if (bans is null)
        {
            Console.Error.WriteLine(DescribeUnavailable(client.LastProblem, client.LastRequestError));
            return 1;
        }

        if (bans.Count == 0)
        {
            Console.WriteLine("No active bans.");
            return 0;
        }

        Console.WriteLine($"{"IP",-42} {"SOURCE",-8} {"OFFENSE",-8} EXPIRES (UTC)");
        foreach (var ban in bans)
        {
            var expires = ban.IsPermanent ? "permanent" : ban.ExpiresUtc.ToString("u", CultureInfo.InvariantCulture);
            Console.WriteLine($"{ban.IpAddress,-42} {ban.Source,-8} {ban.OffenseCount,-8} {expires}");
        }

        return 0;
    }

    /// <summary>Manually bans an IP: <c>--ban &lt;ip&gt; [--permanent] [--duration d.hh:mm:ss] [--note text]</c>.</summary>
    public static async Task<int> BanAsync(string[] args)
    {
        // args[0] is "--ban"; args[1], when it is not a flag, is the IP.
        string ip;
        var rest = new List<string>();
        if (args.Length >= 2 && !args[1].StartsWith("-", StringComparison.Ordinal) && !args[1].StartsWith("/", StringComparison.Ordinal))
        {
            ip = args[1];
            rest.AddRange(args.Skip(2));
        }
        else
        {
            ip = string.Empty;
            rest.AddRange(args.Skip(1));
        }

        bool permanent = false;
        TimeSpan? duration = null;
        string? note = null;
        for (var i = 0; i < rest.Count; i++)
        {
            switch (rest[i].ToLowerInvariant())
            {
                case "--permanent":
                case "/permanent":
                    permanent = true;
                    break;
                case "--duration":
                case "/duration":
                    if (i + 1 >= rest.Count || !TimeSpan.TryParse(rest[++i], CultureInfo.InvariantCulture, out var parsed) || parsed <= TimeSpan.Zero)
                    {
                        Console.Error.WriteLine("--duration needs a positive TimeSpan, e.g. 7.00:00:00 for seven days.");
                        return 2;
                    }

                    duration = parsed;
                    break;
                case "--note":
                case "/note":
                    if (i + 1 >= rest.Count)
                    {
                        Console.Error.WriteLine("--note needs a value.");
                        return 2;
                    }

                    note = rest[++i];
                    break;
                default:
                    Console.Error.WriteLine($"Unknown option '{rest[i]}'.");
                    return 2;
            }
        }

        if (!IsValidIp(ip))
        {
            Console.Error.WriteLine("Usage: winguard-svc --ban <ip> [--permanent] [--duration d.hh:mm:ss] [--note text]");
            return 2;
        }

        using var client = new PipeClient();
        try
        {
            var ban = await client.BlockNowAsync(ip, duration, permanent, note).ConfigureAwait(false);
            var status = await client.GetStatusAsync().ConfigureAwait(false);
            Console.WriteLine(DescribeBan(ip, ban, status?.ReportOnly == true));
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Ban failed: " + ex.Message);
            return 1;
        }
    }

    /// <summary>Manually lifts a ban: <c>--unban &lt;ip|prefix&gt;</c>.</summary>
    public static async Task<int> UnbanAsync(string[] args)
    {
        if (args.Length < 2 || !Core.Engine.IpMatcher.TryNormalizeBanTarget(args[1], out _))
        {
            Console.Error.WriteLine("Usage: winguard-svc --unban <ip|prefix>");
            return 2;
        }

        using var client = new PipeClient();
        try
        {
            await client.UnblockAsync(args[1], alsoWhitelist: false).ConfigureAwait(false);
            Console.WriteLine($"Unbanned {args[1]}.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Unban failed: " + ex.Message);
            return 1;
        }
    }

    /// <summary>
    /// Health check: service reachability, prerequisites (audit policy, firewall service,
    /// RdpCoreTS channel), data/log directories and the firewall COM API. Prints a report; exits
    /// non-zero when a check that matters for protection fails.
    /// </summary>
    public static async Task<int> DoctorAsync()
    {
        var failures = 0;
        var warnings = 0;

        void Report(string label, bool ok, bool warnOnly = false, string? detail = null)
        {
            var marker = ok ? "[ OK ]" : warnOnly ? "[WARN]" : "[FAIL]";
            Console.WriteLine($"{marker} {label}{(string.IsNullOrWhiteSpace(detail) ? string.Empty : ": " + detail)}");
            if (!ok)
            {
                if (warnOnly)
                {
                    warnings++;
                }
                else
                {
                    failures++;
                }
            }
        }

        Console.WriteLine("WinGuard doctor");
        Console.WriteLine(new string('-', 60));

        // 1. Service pipe + live status.
        ServiceStatusDto? status;
        string? unavailable;
        using (var client = new PipeClient())
        {
            status = await client.GetStatusAsync().ConfigureAwait(false);
            unavailable = DescribeUnavailable(client.LastProblem, client.LastRequestError);
        }

        if (status is null)
        {
            Report("Service running", ok: false, detail: unavailable);
        }
        else
        {
            Report("Service running", ok: true, detail: $"version {status.Version}, protocol {status.ProtocolVersion}, {status.ActiveBans} active ban(s)");
            foreach (var engine in status.Engines)
            {
                Report($"Engine {engine.Name}", engine.Running, warnOnly: !engine.Enabled, engine.Running ? "running" : "not running");
            }

            if (status.ReportOnly)
            {
                Report("Report-only mode", ok: false, warnOnly: true, "bans are recorded but NOT enforced in the firewall");
            }

            // 2. Prerequisites as the service itself sees them.
            using (var client = new PipeClient())
            {
                var prereqs = await client.CheckPrereqsAsync().ConfigureAwait(false);
                if (prereqs is null)
                {
                    // The report below still covers the local checks, but it must not look complete.
                    Report("Prerequisites", ok: false, warnOnly: true, DescribeUnavailable(client.LastProblem, client.LastRequestError));
                }
                else
                {
                    Report("Logon failure auditing", prereqs.AuditLogonFailureEnabled, detail: "required for RDP 4625 detection");
                    Report("Windows Defender Firewall service (MpsSvc)", prereqs.FirewallServiceRunning);
                    Report("RdpCoreTS/Operational channel", prereqs.RdpCoreTsChannelEnabled, warnOnly: true, "140 fallback");
                    foreach (var warning in prereqs.Warnings)
                    {
                        Console.WriteLine("       " + warning);
                    }
                }
            }
        }

        // 3. Local environment checks (no service needed).
        Report("Data folder", CheckWritable(Defaults.DataFolder), detail: Defaults.DataFolder);
        Report("Log folder", CheckWritable(Defaults.LogFolder), detail: Defaults.LogFolder);
        Report("Database file", File.Exists(Defaults.DatabasePath), warnOnly: true, File.Exists(Defaults.DatabasePath) ? "present" : "not created yet");

        var (firewallOk, firewallDetail) = ProbeFirewall(logger => new WindowsFirewall(logger));
        Report("Firewall COM API", firewallOk, detail: firewallDetail);
        Report("Firewall service state (local probe)", new WindowsFirewall(NullLogger<WindowsFirewall>.Instance).IsServiceRunning());

        Console.WriteLine(new string('-', 60));
        Console.WriteLine(failures == 0 && warnings == 0
            ? "All checks passed."
            : $"{failures} failure(s), {warnings} warning(s).");
        return failures == 0 ? 0 : 1;
    }

    /// <summary>What to print when the service gave no answer, most specific reason first.</summary>
    internal static string DescribeUnavailable(string? problem, string? requestError) =>
        problem ?? requestError ?? PipeClient.ServiceNotRunningMessage;

    /// <summary>The outcome of a manual ban, as the service recorded it.</summary>
    internal static string DescribeBan(string ip, BanDto? ban, bool reportOnly)
    {
        var outcome = ban switch
        {
            null => $"Banned {ip}.",
            { IsPermanent: true } => $"Banned {ban.IpAddress} permanently (offense #{ban.OffenseCount}).",
            _ => $"Banned {ban.IpAddress} for {ban.ExpiresUtc - ban.BannedAtUtc:c}, until {ban.ExpiresUtc:u} (offense #{ban.OffenseCount}).",
        };

        return reportOnly ? outcome + " Report-only mode: recorded, but the firewall is unchanged." : outcome;
    }

    /// <summary>
    /// Whether the firewall's rules can really be read. <see cref="IFirewall.ListBlocked"/> never
    /// throws and answers null when it failed; the reason only shows in what it logs, which is why
    /// the probe listens there.
    /// </summary>
    /// <param name="create">Creates the firewall to probe, logging to the given logger.</param>
    internal static (bool Ok, string Detail) ProbeFirewall(Func<ILogger<WindowsFirewall>, IFirewall> create)
    {
        var errors = new FirstErrorLogger();
        try
        {
            var blocked = create(errors).ListBlocked();
            if (blocked is null)
            {
                return (false, errors.First ?? "The firewall rules could not be read.");
            }

            return (true, blocked.Count == 0 ? "reachable, no WinGuard rules" : $"reachable, {blocked.Count} address(es) blocked");
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

    /// <summary>
    /// Whether a file can be written to the folder. A missing folder is a failed check, not
    /// something to create: it would belong to whoever ran the doctor, and the installer's
    /// hardening assumes nobody but an administrator gets to create it.
    /// </summary>
    internal static bool CheckWritable(string folder)
    {
        try
        {
            if (!Directory.Exists(folder))
            {
                return false;
            }

            var probe = Path.Combine(folder, ".winguard-doctor-probe");
            File.WriteAllText(probe, "probe");
            File.Delete(probe);
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    private static bool IsValidIp(string? value) =>
        !string.IsNullOrWhiteSpace(value)
        && value.IndexOf('/') < 0
        && Core.Engine.IpMatcher.IsValid(value);

    /// <summary>Remembers the first error logged, for <see cref="ProbeFirewall"/>.</summary>
    private sealed class FirstErrorLogger : ILogger<WindowsFirewall>
    {
        public string? First { get; private set; }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Error;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (IsEnabled(logLevel))
            {
                First ??= exception?.GetBaseException().Message ?? formatter(state, exception);
            }
        }
    }
}
