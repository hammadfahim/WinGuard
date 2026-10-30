using System.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using WinGuard.Core.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Detection;
using WinGuard.Core.Engine;
using WinGuard.Core.Firewall;
using WinGuard.Core.Monitoring;
using WinGuard.Core.Notifications;
using WinGuard.Core.Store;
using WinGuard.Service.Ipc;
using WinGuard.Service.Logging;

namespace WinGuard.Service;

/// <summary>
/// WinGuard service host and management CLI (PLAN.md §13). Verbs:
/// <list type="bullet">
///   <item><c>--install</c> — register the service via <c>sc.exe</c> (delayed-auto, description,
///   restart-on-failure) and start it.</item>
///   <item><c>--uninstall</c> — stop and delete the service.</item>
///   <item><c>--console</c> — run the host in the current console.</item>
///   <item><c>--clear-firewall</c> — delete every <c>WinGuard_Block_*</c> rule and exit 0.</item>
///   <item><c>--disarm</c> / <c>--rearm</c> — break-glass: stop enforcing for a bounded time, and end
///   that early; both work without the service.</item>
///   <item><c>--status</c> / <c>--list-bans</c> / <c>--ban</c> / <c>--unban</c> / <c>--doctor</c> —
///   manage the running service over its pipe (elevated console required).</item>
///   <item>no arguments — run as the Windows service.</item>
/// </list>
/// Exit codes: 0 success, non-zero on failure (message on stderr).
/// </summary>
internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        try
        {
            if (args.Length > 0)
            {
                switch (args[0].ToLowerInvariant())
                {
                    case "--install":
                        return InstallService();
                    case "--uninstall":
                        return UninstallService();
                    case "--clear-firewall":
                        return ClearFirewall();
                    case "--disarm":
                        return BreakGlassCommands.Disarm(args);
                    case "--rearm":
                        return BreakGlassCommands.Rearm();
                    case "--console":
                        return await RunHostAsync(args, console: true).ConfigureAwait(false);
                    case "--status":
                        return await CliCommands.StatusAsync().ConfigureAwait(false);
                    case "--list-bans":
                        return await CliCommands.ListBansAsync().ConfigureAwait(false);
                    case "--ban":
                        return await CliCommands.BanAsync(args).ConfigureAwait(false);
                    case "--unban":
                        return await CliCommands.UnbanAsync(args).ConfigureAwait(false);
                    case "--doctor":
                        return await CliCommands.DoctorAsync().ConfigureAwait(false);
                    case "--help":
                    case "-h":
                    case "/?":
                        PrintHelp();
                        return 0;
                    default:
                        Console.Error.WriteLine($"Unknown option '{args[0]}'. Use --help for usage.");
                        return 2;
                }
            }

            return await RunHostAsync(args, console: false).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"WinGuard failed: {ex.Message}");
            TryLogFatal(ex);
            return 1;
        }
    }

    /// <summary>
    /// A start-up failure happens before (or outside) the host's logging, and a Windows service has
    /// no console: leave a trace in the log folder so "the service will not start" can be diagnosed.
    /// </summary>
    private static void TryLogFatal(Exception exception)
    {
        try
        {
            Directory.CreateDirectory(Defaults.LogFolder);
            File.AppendAllText(
                Path.Combine(Defaults.LogFolder, "winguard-fatal.log"),
                $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} [CRT] WinGuard failed: {exception}{Environment.NewLine}");
        }
        catch (Exception)
        {
            // Nothing else can be done.
        }
    }

    // ---- service host ----

    private static async Task<int> RunHostAsync(string[] args, bool console)
    {
        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
        {
            // Pass configuration-relevant args through (e.g. --DatabasePath <path>);
            // the --console verb itself is filtered so the command-line provider only
            // sees well-formed --key value pairs.
            Args = args
                .Where(a => !string.Equals(a, "--console", StringComparison.OrdinalIgnoreCase))
                .ToArray(),
            ContentRootPath = AppContext.BaseDirectory,
        });

        if (!console)
        {
            builder.Services.AddWindowsService(options => options.ServiceName = Defaults.ServiceName);
        }

        ConfigureLogging(builder, console);
        ConfigureServices(builder);

        using var host = builder.Build();

        var store = host.Services.GetRequiredService<IStore>();
        await store.InitializeAsync().ConfigureAwait(false);

        var settings = host.Services.GetRequiredService<SettingsHolder>();
        await settings.LoadAsync().ConfigureAwait(false);

        await host.RunAsync().ConfigureAwait(false);
        return 0;
    }

    private static void ConfigureLogging(HostApplicationBuilder builder, bool console)
    {
        builder.Logging.ClearProviders();

        var minimumLevel = ParseLevel(builder.Configuration["Logging:LogLevel:Default"]) ?? LogLevel.Information;
        builder.Logging.SetMinimumLevel(minimumLevel);
        builder.Logging.AddProvider(new FileLoggerProvider(Defaults.LogFolder, minimumLevel));

        if (console)
        {
            builder.Logging.AddConsole();
        }
    }

    internal static void ConfigureServices(HostApplicationBuilder builder)
    {
        var databasePath = builder.Configuration["DatabasePath"];
        if (string.IsNullOrWhiteSpace(databasePath))
        {
            databasePath = Defaults.DatabasePath;
        }

        var resolvedDatabasePath = databasePath!;

        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddSingleton<SettingsHolder>();
        builder.Services.AddSingleton<DetectorRuntimeState>();

        builder.Services.AddSingleton<IStore>(sp =>
            new SqliteStore(resolvedDatabasePath, sp.GetRequiredService<ILogger<SqliteStore>>(), sp.GetRequiredService<TimeProvider>()));

        builder.Services.AddSingleton<IFirewall>(sp =>
            new WindowsFirewall(
                sp.GetRequiredService<ILogger<WindowsFirewall>>(),
                Defaults.MaxAddressesPerRule,
                () => sp.GetRequiredService<SettingsHolder>().Current));

        // Event fan-out: warning/error engine events are enqueued (never blocking the engine path)
        // and delivered by one background loop — to the Windows Application event log (SIEM
        // friendly, opt-out via settings) and to the configured notification channels.
        builder.Services.AddSingleton(sp => new NotificationDispatcher(
            () => sp.GetRequiredService<SettingsHolder>().Current,
            sp.GetRequiredService<ILogger<NotificationDispatcher>>(),
            new WindowsEventLogWriter(sp.GetRequiredService<ILogger<WindowsEventLogWriter>>())));

        builder.Services.AddSingleton<IEventPublisher>(sp => sp.GetRequiredService<NotificationDispatcher>());

        builder.Services.AddSingleton(sp =>
            new BanEngine(
                sp.GetRequiredService<IStore>(),
                sp.GetRequiredService<IFirewall>(),
                () => sp.GetRequiredService<SettingsHolder>().Current,
                sp.GetRequiredService<ILogger<BanEngine>>(),
                sp.GetRequiredService<TimeProvider>(),
                sp.GetRequiredService<IEventPublisher>())
            {
                BreakGlass = new DisarmFile(Defaults.DisarmFilePath),
                Metrics = new PrometheusTextfileWriter(sp.GetRequiredService<ILogger<PrometheusTextfileWriter>>()),
            });

        builder.Services.AddSingleton<IDetector>(sp =>
            new RdpSecurityLogDetector(
                () => sp.GetRequiredService<SettingsHolder>().Current,
                sp.GetRequiredService<ILogger<RdpSecurityLogDetector>>(),
                sp.GetRequiredService<TimeProvider>()));

        builder.Services.AddSingleton<IDetector>(sp =>
            new RdpCoreTsDetector(
                () => sp.GetRequiredService<SettingsHolder>().Current,
                sp.GetRequiredService<ILogger<RdpCoreTsDetector>>(),
                sp.GetRequiredService<TimeProvider>()));

        builder.Services.AddSingleton<IDetector>(sp =>
            new LogonSuccessDetector(
                () => sp.GetRequiredService<SettingsHolder>().Current,
                sp.GetRequiredService<ILogger<LogonSuccessDetector>>()));

        builder.Services.AddSingleton<IDetector>(sp =>
            new MsSqlDetector(
                () => sp.GetRequiredService<SettingsHolder>().Current,
                sp.GetRequiredService<ILogger<MsSqlDetector>>(),
                sp.GetRequiredService<TimeProvider>()));

        builder.Services.AddSingleton<IDetector>(sp =>
            new FtpLogDetector(
                () => sp.GetRequiredService<SettingsHolder>().Current,
                sp.GetRequiredService<ILogger<FtpLogDetector>>(),
                sp.GetRequiredService<TimeProvider>()));

        builder.Services.AddSingleton<IDetector>(sp =>
            new CustomLogDetector(
                () => sp.GetRequiredService<SettingsHolder>().Current,
                sp.GetRequiredService<ILogger<CustomLogDetector>>(),
                sp.GetRequiredService<TimeProvider>()));

        builder.Services.AddSingleton<IpcRequestHandler>();

        // Hosted services stop in reverse order: delivery comes first so it outlives the engine,
        // and whatever the engine still reports while it shuts down gets delivered.
        builder.Services.AddHostedService<NotificationHostedService>();
        builder.Services.AddHostedService<GuardWorker>();
        builder.Services.AddHostedService<PipeServer>();
    }

    // ---- CLI verbs ----

    private static int InstallService()
    {
        var executable = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(executable))
        {
            Console.Error.WriteLine("Could not determine the service executable path.");
            return 1;
        }

        // A portable install gets the same data-folder protection as the setup, before anything
        // runs as LocalSystem on top of a folder a standard user may have prepared.
        if (SecureDataFolder(Defaults.DataFolder) is { } problem)
        {
            Console.Error.WriteLine($"Failed to secure the data folder: {problem}");
            return 1;
        }

        // The path is passed WITH its quotes so the stored ImagePath is quoted; an unquoted path
        // containing spaces ("C:\Program Files\...") is the classic unquoted-service-path weakness.
        var create = RunProcess(ScExe,
            "create", Defaults.ServiceName,
            "binPath=", "\"" + executable + "\"",
            "start=", "delayed-auto",
            "DisplayName=", Defaults.ServiceDisplayName);
        if (create.ExitCode != 0)
        {
            Console.Error.WriteLine($"Failed to create the service: {create.Output}");
            return create.ExitCode;
        }

        Console.WriteLine($"Created service '{Defaults.ServiceName}'.");

        var description = RunProcess(ScExe, "description", Defaults.ServiceName, Defaults.ServiceDescription);
        if (description.ExitCode != 0)
        {
            Console.Error.WriteLine($"Warning: could not set the service description: {description.Output}");
        }

        var failure = RunProcess(ScExe,
            "failure", Defaults.ServiceName,
            "reset=", "86400",
            "actions=", "restart/5000/restart/5000/restart/5000");
        if (failure.ExitCode != 0)
        {
            Console.Error.WriteLine($"Warning: could not set service failure actions: {failure.Output}");
        }

        var start = RunProcess(ScExe, "start", Defaults.ServiceName);
        if (start.ExitCode != 0)
        {
            // Already-running (1056) is benign; report but do not fail the install.
            Console.Error.WriteLine($"Warning: could not start the service: {start.Output}");
        }
        else
        {
            Console.WriteLine($"Started service '{Defaults.ServiceName}'.");
        }

        return 0;
    }

    private static int UninstallService()
    {
        var stop = RunProcess(ScExe, "stop", Defaults.ServiceName);
        if (stop.ExitCode != 0)
        {
            Console.Error.WriteLine($"Warning: could not stop the service (it may not be running): {stop.Output}");
        }

        // Deleting a service that is still stopping only marks it for deletion.
        var stopped = false;
        for (var attempt = 0; attempt < ServiceStopWaitSeconds && !stopped; attempt++)
        {
            var query = RunProcess(ScExe, "query", Defaults.ServiceName);
            stopped = IsServiceStopped(query.ExitCode, query.Output);
            if (!stopped)
            {
                Thread.Sleep(1000);
            }
        }

        if (!stopped)
        {
            Console.Error.WriteLine($"Warning: the service did not stop within {ServiceStopWaitSeconds} seconds; it will be deleted once it has.");
        }

        var delete = RunProcess(ScExe, "delete", Defaults.ServiceName);
        if (delete.ExitCode != 0)
        {
            Console.Error.WriteLine($"Failed to delete the service: {delete.Output}");
            return delete.ExitCode;
        }

        Console.WriteLine($"Deleted service '{Defaults.ServiceName}'.");
        return 0;
    }

    private static int ClearFirewall()
    {
        var firewall = new WindowsFirewall(NullLogger<WindowsFirewall>.Instance);
        if (!firewall.TryClearAll(out var error))
        {
            // Honest failure signal: the uninstaller warns when rules may remain (review S-M4).
            Console.Error.WriteLine($"Failed to remove WinGuard firewall rules: {error}");
            return 1;
        }

        Console.WriteLine("Removed all WinGuard firewall rules.");
        return 0;
    }

    private const int ServiceStopWaitSeconds = 30;

    /// <summary>Full path, so a file named sc.exe next to this executable can never be run instead.</summary>
    private static string ScExe => Path.Combine(Environment.SystemDirectory, "sc.exe");

    private static string IcaclsExe => Path.Combine(Environment.SystemDirectory, "icacls.exe");

    /// <summary>Reads <c>sc query</c>: a service that no longer exists has stopped too.</summary>
    internal static bool IsServiceStopped(int exitCode, string output) =>
        exitCode != 0 || output.Contains("STOPPED", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The icacls calls that leave a folder to SYSTEM + Administrators alone, whoever created it
    /// (same steps as the installer). Ownership goes first, because an owner can always grant
    /// itself access again; only then can the ACLs be replaced, and explicit entries have to be
    /// reset because <c>/grant:r</c> leaves those of other accounts in place. The second ownership
    /// pass also catches what was created meanwhile. The accounts are given as SIDs because their
    /// names are localized. No <c>/C</c>: with it icacls exits 0 even when it failed.
    /// </summary>
    internal static IReadOnlyList<string[]> DataFolderHardeningSteps(string folder) =>
    [
        [folder, "/setowner", "*S-1-5-32-544"],
        [folder, "/reset"],
        [folder, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"],
        [folder, "/setowner", "*S-1-5-32-544", "/T", "/L"],
        [Path.Combine(folder, "*"), "/reset", "/T", "/L"],
    ];

    /// <summary>Applies <see cref="DataFolderHardeningSteps"/>; returns why it could not, or null.</summary>
    internal static string? SecureDataFolder(string folder)
    {
        try
        {
            var info = new DirectoryInfo(folder);
            if (info.Exists && info.Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                // Hardening would change the link's target, and the service would write through it.
                return $"{folder} is a link, not a folder. Remove it and try again.";
            }

            Directory.CreateDirectory(folder);
            foreach (var step in DataFolderHardeningSteps(folder))
            {
                var result = RunProcess(IcaclsExe, step);
                if (result.ExitCode != 0)
                {
                    return result.Output;
                }
            }

            return null;
        }
        catch (Exception ex)
        {
            return ex.Message;
        }
    }

    internal static (int ExitCode, string Output) RunProcess(string fileName, params string[] arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException($"Could not start '{fileName}'.");

        // Read both streams at once: reading one to its end first deadlocks as soon as the other
        // fills its pipe buffer.
        var stdoutRead = process.StandardOutput.ReadToEndAsync();
        var stderrRead = process.StandardError.ReadToEndAsync();
        process.WaitForExit();
        var stdout = stdoutRead.GetAwaiter().GetResult();
        var stderr = stderrRead.GetAwaiter().GetResult();

        var output = string.IsNullOrWhiteSpace(stderr) ? stdout : $"{stdout}{Environment.NewLine}{stderr}";
        return (process.ExitCode, output.Trim());
    }

    private static LogLevel? ParseLevel(string? value) =>
        Enum.TryParse<LogLevel>(value, ignoreCase: true, out var level) ? level : null;

    private static void PrintHelp() => Console.WriteLine(
        """
        WinGuard service host

        Usage:
          winguard-svc              Run as a Windows service (default).
          winguard-svc --console    Run in the current console.
          winguard-svc --install    Register and start the Windows service.
          winguard-svc --uninstall  Stop and delete the Windows service.
          winguard-svc --clear-firewall  Delete all WinGuard_Block_* firewall rules.

        Break-glass (work without the service; need an elevated console):
          winguard-svc --disarm [--minutes N]  Remove all rules and stop enforcing for N minutes
                                               (default 60, at most 1440). Ends by itself.
          winguard-svc --rearm                 End a disarm early.

        Management (talk to the running service; needs an elevated console):
          winguard-svc --status    Show service status and per-engine counters.
          winguard-svc --list-bans List active bans.
          winguard-svc --ban <ip> [--permanent] [--duration d.hh:mm:ss] [--note text]
          winguard-svc --unban <ip|prefix>
          winguard-svc --doctor    Health check: prerequisites, paths, firewall API.
          winguard-svc --help      Show this help.
        """);
}