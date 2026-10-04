using System.Threading.Channels;
using Microsoft.Extensions.Logging.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Detection;
using WinGuard.Core.Engine;
using WinGuard.Core.Model;
using WinGuard.Core.Store;
using WinGuard.Core.Tests.Fakes;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>
/// End-to-end wiring test (no admin rights needed): custom log file -> detector -> channel ->
/// BanEngine -> real SQLite store -> firewall. Mirrors what GuardWorker does in the service.
/// </summary>
public class PipelineIntegrationTests
{
    [Fact]
    public async Task Failed_logins_appended_to_a_log_end_up_banned_in_store_and_firewall()
    {
        var dir = Path.Combine(Path.GetTempPath(), "winguard-it-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var log = Path.Combine(dir, "auth.log");
        await File.WriteAllTextAsync(log, "startup line\n");

        var settings = new WinGuardSettings { FailedLoginThreshold = 3 };
        settings.Ftp.PollInterval = TimeSpan.FromMilliseconds(150);
        settings.CustomSources.Add(new CustomLogSource
        {
            Name = "it-app",
            PathGlob = log,
            Regex = @"Failed login from (?<ipaddress>\S+)",
        });
        settings.Normalize();

        await using var store = new SqliteStore(Path.Combine(dir, "t.db"), NullLogger<SqliteStore>.Instance);
        await store.InitializeAsync();
        var firewall = new FakeFirewall();
        var engine = new BanEngine(store, firewall, () => settings, NullLogger<BanEngine>.Instance);
        var detector = new CustomLogDetector(() => settings, NullLogger<CustomLogDetector>.Instance);
        var channel = Channel.CreateUnbounded<FailedLogin>();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

        try
        {
            await engine.StartAsync(cts.Token);
            await detector.StartAsync(channel, cts.Token);
            var engineTask = engine.RunAsync(channel.Reader, cts.Token);

            await Task.Delay(700); // let the tailer take its skip-to-end cursor
            await File.AppendAllTextAsync(log, string.Concat(Enumerable.Repeat("Failed login from 203.0.113.9\n", 3)));

            var deadline = DateTime.UtcNow.AddSeconds(15);
            while (DateTime.UtcNow < deadline && !firewall.Blocked.Contains("203.0.113.9"))
            {
                await Task.Delay(100);
            }

            Assert.Contains("203.0.113.9", firewall.Blocked);
            var ban = await store.GetBanAsync("203.0.113.9");
            Assert.NotNull(ban);
            Assert.Equal(1, ban!.OffenseCount);
            Assert.Contains(await store.GetEventsAsync(50), e => e.Message.StartsWith("BLOCKED 203.0.113.9"));

            cts.Cancel();
            await engineTask;
        }
        finally
        {
            await engine.StopAsync();
            cts.Cancel();
            try { Directory.Delete(dir, recursive: true); } catch (IOException) { }
        }
    }

    [Fact]
    public async Task Events_can_be_polled_with_an_id_cursor()
    {
        var dir = Path.Combine(Path.GetTempPath(), "winguard-it-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        await using var store = new SqliteStore(Path.Combine(dir, "t.db"), NullLogger<SqliteStore>.Instance);
        try
        {
            await store.InitializeAsync();
            for (var i = 1; i <= 5; i++)
            {
                await store.AddEventAsync(new LogEvent { TimestampUtc = DateTime.UtcNow, Message = "e" + i });
            }

            var all = await store.GetEventsAsync(10);
            var cursor = all.Max(e => e.Id);
            Assert.Empty(await store.GetEventsAsync(10, null, cursor));

            await store.AddEventAsync(new LogEvent { TimestampUtc = DateTime.UtcNow, Message = "e6" });
            var fresh = await store.GetEventsAsync(10, null, cursor);
            Assert.Single(fresh);
            Assert.Equal("e6", fresh[0].Message);
        }
        finally
        {
            await store.DisposeAsync();
            try { Directory.Delete(dir, recursive: true); } catch (IOException) { }
        }
    }

    [Fact]
    public async Task File_change_signal_wakes_a_wait_before_the_interval_elapses()
    {
        var dir = Path.Combine(Path.GetTempPath(), "winguard-it-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var file = Path.Combine(dir, "a.log");
        await File.WriteAllTextAsync(file, "x\n");
        using var signal = new FileChangeSignal();
        try
        {
            signal.Watch([file]);
            var started = DateTime.UtcNow;
            var wait = signal.WaitAsync(TimeSpan.FromSeconds(20), TimeProvider.System, CancellationToken.None);
            await Task.Delay(200);
            await File.AppendAllTextAsync(file, "y\n");

            await wait.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.True(DateTime.UtcNow - started < TimeSpan.FromSeconds(10));
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch (IOException) { }
        }
    }
}
