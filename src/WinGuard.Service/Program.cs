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
                    case "--console":
                        return await RunHostAsync(args, console: true).ConfigureAwait(false);
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

    private static void ConfigureServices(HostApplicationBuilder builder)
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

        builder.Services.AddSingleton(sp =>
            new BanEngine(
                sp.GetRequiredService<IStore>(),
                sp.GetRequiredService<IFirewall>(),
                () => sp.GetRequiredService<SettingsHolder>().Current,
                sp.GetRequiredService<ILogger<BanEngine>>(),
                sp.GetRequiredService<TimeProvider>()));

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

        // Give the SCM a moment to finish stopping before deletion.
        Thread.Sleep(1500);

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

    /// <summary>Full path, so a file named sc.exe next to this executable can never be run instead.</summary>
    private static string ScExe => Path.Combine(Environment.SystemDirectory, "sc.exe");

    private static (int ExitCode, string Output) RunProcess(string fileName, params string[] arguments)
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

        // Read both streams before waiting to avoid pipe-buffer deadlocks.
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();

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
          winguard-svc --help       Show this help.
        """);
}