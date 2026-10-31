using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WinGuard.Core.Firewall;
using WinGuard.Core.Ipc;
using WinGuard.Service;
using WinGuard.Service.Ipc;
using Xunit;
using ServiceProgram = WinGuard.Service.Program;

namespace WinGuard.Core.Tests;

/// <summary>What the management CLI prints and checks, and the service-control helpers behind it.</summary>
[SupportedOSPlatform("windows")]
public sealed class CliCommandsTests
{
    private static string NewPipeName() => "WinGuard-test-" + Guid.NewGuid().ToString("N");

    private static bool IsElevatedAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    [Fact]
    public void A_ban_prints_what_the_service_recorded_not_a_guess()
    {
        var banned = new DateTime(2026, 3, 1, 12, 0, 0, DateTimeKind.Utc);
        var ban = new BanDto
        {
            IpAddress = "203.0.113.7",
            BannedAtUtc = banned,
            ExpiresUtc = banned.AddDays(7),
            OffenseCount = 2,
        };

        Assert.Equal(
            "Banned 203.0.113.7 for 7.00:00:00, until 2026-03-08 12:00:00Z (offense #2).",
            CliCommands.DescribeBan("203.0.113.7", ban, reportOnly: false));
    }

    [Fact]
    public void A_permanent_ban_says_so()
    {
        var ban = new BanDto { IpAddress = "203.0.113.7", IsPermanent = true, OffenseCount = 1, ExpiresUtc = DateTime.MaxValue };

        Assert.Equal("Banned 203.0.113.7 permanently (offense #1).", CliCommands.DescribeBan("203.0.113.7", ban, reportOnly: false));
    }

    [Fact]
    public void A_ban_in_report_only_mode_does_not_pretend_to_be_enforced()
    {
        var ban = new BanDto { IpAddress = "203.0.113.7", IsPermanent = true };

        Assert.Contains("firewall is unchanged", CliCommands.DescribeBan("203.0.113.7", ban, reportOnly: true));
    }

    [Fact]
    public void A_service_that_reports_no_ban_still_gets_a_truthful_line()
    {
        Assert.Equal("Banned 203.0.113.7.", CliCommands.DescribeBan("203.0.113.7", null, reportOnly: false));
    }

    [Fact]
    public void The_most_specific_reason_wins()
    {
        Assert.Equal("refused", CliCommands.DescribeUnavailable("refused", "request failed"));
        Assert.Equal("request failed", CliCommands.DescribeUnavailable(null, "request failed"));
        Assert.Equal(PipeClient.ServiceNotRunningMessage, CliCommands.DescribeUnavailable(null, null));
    }

    [Fact]
    public async Task With_no_pipe_the_cli_says_the_service_is_not_running()
    {
        using var client = new PipeClient(NewPipeName());

        Assert.Null(await client.GetStatusAsync());

        Assert.Null(client.LastProblem);
        Assert.Equal(PipeClient.ServiceNotRunningMessage, CliCommands.DescribeUnavailable(client.LastProblem, client.LastRequestError));
    }

    [Fact]
    public async Task With_the_service_up_a_non_elevated_cli_is_told_to_elevate()
    {
        if (IsElevatedAdministrator())
        {
            return; // an elevated process is let in; there is nothing to tell apart
        }

        var name = NewPipeName();
        using var service = PipeServer.CreateSecuredPipe(name, PipeServer.PipeSddl, firstInstance: true);
        _ = service.WaitForConnectionAsync();
        using var client = new PipeClient(name);

        Assert.Null(await client.GetStatusAsync());

        var message = CliCommands.DescribeUnavailable(client.LastProblem, client.LastRequestError);
        Assert.Contains("administrator", message);
        Assert.DoesNotContain("not running", message);
    }

    [Fact]
    public async Task A_failed_ban_gives_the_real_reason_too()
    {
        if (IsElevatedAdministrator())
        {
            return;
        }

        var name = NewPipeName();
        using var service = PipeServer.CreateSecuredPipe(name, PipeServer.PipeSddl, firstInstance: true);
        _ = service.WaitForConnectionAsync();
        using var client = new PipeClient(name);

        var error = await Assert.ThrowsAsync<IOException>(() => client.BlockNowAsync("203.0.113.7", null, false, null));

        Assert.Contains("administrator", error.Message);
    }

    [Fact]
    public void The_firewall_probe_fails_when_the_rules_cannot_be_read()
    {
        var (ok, detail) = CliCommands.ProbeFirewall(logger => new WindowsFirewall(logger, new BrokenRuleStore()));

        Assert.False(ok);
        Assert.Contains("COM is broken", detail);
    }

    [Fact]
    public void The_firewall_probe_reports_a_firewall_that_works()
    {
        Assert.Equal((true, "reachable, no WinGuard rules"), CliCommands.ProbeFirewall(logger => new WindowsFirewall(logger, new EmptyRuleStore())));

        var two = new EmptyRuleStore { Rules = [new FirewallRuleInfo("WinGuard_Block_0001", "203.0.113.7,203.0.113.8")] };
        Assert.Equal((true, "reachable, 2 address(es) blocked"), CliCommands.ProbeFirewall(logger => new WindowsFirewall(logger, two)));
    }

    [Fact]
    public void A_firewall_that_throws_fails_the_probe_too()
    {
        var (ok, detail) = CliCommands.ProbeFirewall(_ => throw new InvalidOperationException("no firewall"));

        Assert.False(ok);
        Assert.Equal("no firewall", detail);
    }

    [Fact]
    public void The_doctor_never_creates_a_missing_folder()
    {
        var folder = Path.Combine(Path.GetTempPath(), "winguard-doctor-" + Guid.NewGuid().ToString("N"));

        Assert.False(CliCommands.CheckWritable(folder));
        Assert.False(Directory.Exists(folder));

        Directory.CreateDirectory(folder);
        try
        {
            Assert.True(CliCommands.CheckWritable(folder));
            Assert.Empty(Directory.EnumerateFileSystemEntries(folder));
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }

    [Fact]
    public async Task A_chatty_child_process_cannot_deadlock_the_cli()
    {
        // More than the pipe buffer on stderr: reading stdout to its end first used to hang here.
        var run = Task.Run(() => ServiceProgram.RunProcess(
            "cmd.exe",
            "/c",
            "for /L %i in (1,1,1500) do @echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 1>&2"));

        var (exitCode, output) = await run.WaitAsync(TimeSpan.FromSeconds(60));

        Assert.Equal(0, exitCode);
        Assert.True(output.Length > 64 * 1024, $"only {output.Length} characters");
    }

    [Theory]
    [InlineData(0, "STATE : 1  STOPPED", true)]
    [InlineData(0, "STATE : 4  RUNNING", false)]
    [InlineData(0, "STATE : 3  STOP_PENDING", false)]
    [InlineData(1060, "The specified service does not exist", true)]
    public void Sc_query_is_read_correctly(int exitCode, string output, bool stopped)
    {
        Assert.Equal(stopped, ServiceProgram.IsServiceStopped(exitCode, output));
    }

    [Fact]
    public void Delivery_stops_after_the_engine()
    {
        var builder = Host.CreateEmptyApplicationBuilder(new HostApplicationBuilderSettings());
        ServiceProgram.ConfigureServices(builder);

        var hosted = builder.Services
            .Where(service => service.ServiceType == typeof(IHostedService))
            .Select(service => service.ImplementationType)
            .ToList();

        // Hosted services stop in reverse order of registration.
        Assert.True(hosted.IndexOf(typeof(NotificationHostedService)) < hosted.IndexOf(typeof(GuardWorker)));
    }

    [Fact]
    public void The_service_wires_up_break_glass_metrics_and_the_new_optional_dependencies()
    {
        var folder = Path.Combine(Path.GetTempPath(), "winguard-wiring-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            var builder = Host.CreateEmptyApplicationBuilder(new HostApplicationBuilderSettings());
            builder.Configuration["DatabasePath"] = Path.Combine(folder, "winguard.db");
            ServiceProgram.ConfigureServices(builder);

            using (var host = builder.Build())
            {
                var engine = host.Services.GetRequiredService<Core.Engine.BanEngine>();

                Assert.NotNull(engine.BreakGlass);
                Assert.Equal(Core.Engine.DisarmFile.FileName, Path.GetFileName(engine.BreakGlass.Path));
                Assert.IsType<Core.Monitoring.PrometheusTextfileWriter>(engine.Metrics);
                Assert.NotNull(host.Services.GetRequiredService<SettingsHolder>());
                Assert.NotNull(host.Services.GetRequiredService<IpcRequestHandler>());
            }
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(folder, recursive: true);
        }
    }

    private sealed class BrokenRuleStore : IFirewallRuleStore
    {
        public IReadOnlyList<FirewallRuleInfo> ReadRules() => throw new InvalidOperationException("COM is broken");

        public void Upsert(string name, int protocol, string? localPorts, string remoteAddresses) => throw new NotSupportedException();

        public void Remove(string name) => throw new NotSupportedException();
    }

    private sealed class EmptyRuleStore : IFirewallRuleStore
    {
        public List<FirewallRuleInfo> Rules { get; init; } = [];

        public IReadOnlyList<FirewallRuleInfo> ReadRules() => Rules;

        public void Upsert(string name, int protocol, string? localPorts, string remoteAddresses) => throw new NotSupportedException();

        public void Remove(string name) => throw new NotSupportedException();
    }
}
