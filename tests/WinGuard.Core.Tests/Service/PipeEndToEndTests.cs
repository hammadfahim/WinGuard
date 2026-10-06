using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using WinGuard.Core.Engine;
using WinGuard.Core.Ipc;
using WinGuard.Core.Tests.Fakes;
using WinGuard.Service;
using WinGuard.Service.Ipc;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>
/// The console's real <see cref="PipeClient"/> talking to the service's real <see cref="PipeServer"/>
/// over a real named pipe: connect, be identified, handshake, send requests, be refused, survive a
/// service restart. Each test serves on its own pipe name. The store and firewall are in-memory.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class PipeEndToEndTests
{
    private static readonly PipeClientIdentity.Result Admin = new(true, true, "test-admin", null);
    private static readonly PipeClientIdentity.Result NotAdmin = new(true, false, "test-user", null);
    private static readonly PipeClientIdentity.Result Unidentified = new(false, false, "unknown", "test: cannot identify");

    [Fact]
    public async Task The_real_caller_check_lets_an_elevated_console_in_and_tells_any_other_why_not()
    {
        // No stand-in here: the server identifies this test process exactly as it would the console.
        await using var service = await TestService.StartAsync(identify: null);
        using var client = new PipeClient(service.PipeName);

        var connected = await client.TryReconnectNowAsync();

        if (IsElevatedAdministrator())
        {
            Assert.True(connected, client.LastProblem);
            Assert.Null(client.LastProblem);
            Assert.NotNull(await client.GetStatusAsync());
        }
        else
        {
            Assert.False(connected);
            Assert.False(client.IsConnected);
            Assert.Contains("administrator", client.LastProblem, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public async Task An_authorized_console_connects_and_can_use_every_kind_of_request()
    {
        await using var service = await TestService.StartAsync(_ => Admin);
        using var client = new PipeClient(service.PipeName);
        var states = new List<bool>();
        client.StateChanged += states.Add;

        Assert.True(await client.TryReconnectNowAsync(), client.LastProblem);
        Assert.True(client.IsConnected);
        Assert.Null(client.LastProblem);
        Assert.Equal(new[] { true }, states);

        var status = await client.GetStatusAsync();
        Assert.NotNull(status);
        Assert.Equal(PipeConstants.ProtocolVersion, status!.ProtocolVersion);

        await client.BlockNowAsync("203.0.113.7", TimeSpan.FromHours(1), permanent: false, note: "e2e");
        var ban = Assert.Single((await client.ListBansAsync())!);
        Assert.Equal("203.0.113.7", ban.IpAddress);
        Assert.Contains("203.0.113.7", service.Firewall.Blocked);

        await client.AddToListAsync(whitelist: true, "198.51.100.0/24");
        Assert.Contains((await client.ListListsAsync())!, e => e.Value == "198.51.100.0/24");

        var settings = await client.GetSettingsAsync();
        settings!.FailedLoginThreshold = 3;
        var stored = await client.UpdateSettingsAsync(settings);
        Assert.Equal(3, stored!.FailedLoginThreshold);

        Assert.NotEmpty((await client.ListEventsAsync(50, null))!);
        Assert.NotNull(await client.CheckPrereqsAsync());

        await client.UnblockAsync("203.0.113.7", alsoWhitelist: false);
        Assert.Empty((await client.ListBansAsync())!);

        // A request the service refuses is an answer, not a broken connection.
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.BlockNowAsync("not-an-ip", null, false, null));
        Assert.True(client.IsConnected);
        Assert.NotNull(await client.GetStatusAsync());
    }

    [Fact]
    public async Task A_refused_console_is_not_connected_and_shows_the_services_reason()
    {
        await using var service = await TestService.StartAsync(_ => NotAdmin);
        using var client = new PipeClient(service.PipeName);
        var states = new List<bool>();
        client.StateChanged += states.Add;

        // Twice: the refusal must be reported every time, not only on the first attempt.
        for (var attempt = 0; attempt < 2; attempt++)
        {
            Assert.False(await client.TryReconnectNowAsync());
            Assert.False(client.IsConnected);
            Assert.Contains("Access denied", client.LastProblem);
        }

        Assert.Empty(states); // never flickered to "connected"
        Assert.Null(await client.GetStatusAsync());
    }

    [Fact]
    public async Task A_client_identified_only_after_its_first_request_still_gets_that_request_answered()
    {
        var calls = 0;
        await using var service = await TestService.StartAsync(_ => Interlocked.Increment(ref calls) == 1 ? Unidentified : Admin);
        using var client = new PipeClient(service.PipeName);

        Assert.True(await client.TryReconnectNowAsync(), client.LastProblem);
        Assert.NotNull(await client.GetStatusAsync());
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task A_client_that_can_never_be_identified_is_refused_before_anything_is_executed()
    {
        await using var service = await TestService.StartAsync(_ => Unidentified);

        // A raw client whose very first line is a state-changing request.
        using var raw = new NamedPipeClientStream(".", service.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await raw.ConnectAsync(5000);
        var request = new IpcRequest
        {
            Id = 7,
            Method = IpcMethods.BlockNow,
            Params = JsonSerializer.SerializeToElement(new BlockNowParams { Ip = "203.0.113.99", Permanent = true }, IpcJson.Options),
        };
        await raw.WriteAsync(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(request, IpcJson.Options) + "\n"));

        using var reader = new StreamReader(raw, Encoding.UTF8);
        var answer = JsonSerializer.Deserialize<IpcResponse>((await reader.ReadLineAsync())!, IpcJson.Options)!;

        Assert.False(answer.Ok);
        Assert.Equal(0, answer.Id);
        Assert.Contains("Access denied", answer.Error);
        Assert.Null(await reader.ReadLineAsync()); // the service hung up
        Assert.Empty(await service.Store.GetActiveBansAsync());
        Assert.Empty(service.Firewall.Blocked);
    }

    [Fact]
    public async Task The_console_notices_a_stopped_service_and_reconnects_to_a_restarted_one()
    {
        var pipeName = TestService.NewPipeName();
        using var client = new PipeClient(pipeName);

        var first = await TestService.StartAsync(_ => Admin, pipeName);
        Assert.True(await client.TryReconnectNowAsync(), client.LastProblem);
        await first.DisposeAsync();

        Assert.Null(await client.GetStatusAsync());
        Assert.False(client.IsConnected);
        Assert.False(await client.TryReconnectNowAsync());
        Assert.Null(client.LastProblem); // no pipe = simply not running, nothing to explain

        await using var second = await TestService.StartAsync(_ => Admin, pipeName);
        Assert.True(await client.TryReconnectNowAsync(), client.LastProblem);
        Assert.NotNull(await client.GetStatusAsync());
    }

    [Fact]
    public async Task Several_consoles_can_be_connected_at_once()
    {
        await using var service = await TestService.StartAsync(_ => Admin);
        var clients = Enumerable.Range(0, 4).Select(_ => new PipeClient(service.PipeName)).ToList();
        try
        {
            foreach (var client in clients)
            {
                Assert.True(await client.TryReconnectNowAsync(), client.LastProblem);
            }

            var statuses = await Task.WhenAll(clients.Select(c => c.GetStatusAsync()));
            Assert.All(statuses, Assert.NotNull);
        }
        finally
        {
            clients.ForEach(c => c.Dispose());
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task The_caller_is_identified_from_a_real_pipe_however_the_client_opened_it(bool clientAsksForIdentification)
    {
        var name = TestService.NewPipeName();
        using var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        var accepted = server.WaitForConnectionAsync();
        using var client = clientAsksForIdentification
            ? new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification)
            : new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
        await client.ConnectAsync(5000);
        await accepted;

        var mySid = WindowsIdentity.GetCurrent().User!.Value;

        var byProcess = PipeClientIdentity.FromClientProcess(server);
        Assert.True(byProcess.Identified, byProcess.Error);
        Assert.StartsWith(mySid, byProcess.Client);
        Assert.Equal(IsElevatedAdministrator(), byProcess.Authorized);

        var combined = PipeClientIdentity.Identify(server);
        Assert.True(combined.Identified, combined.Error);
        Assert.Equal(IsElevatedAdministrator(), combined.Authorized);

        if (clientAsksForIdentification)
        {
            // The fallback: usable at once only when the client fixed its identity at connect time.
            PipeClientIdentity.Prewarm();
            var byImpersonation = PipeClientIdentity.FromImpersonation(server);
            Assert.True(byImpersonation.Identified, byImpersonation.Error);
            Assert.StartsWith(mySid, byImpersonation.Client);
        }
    }

    private static bool IsElevatedAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>The service's IPC stack on a test pipe: real PipeServer + IpcRequestHandler + BanEngine.</summary>
    private sealed class TestService : IAsyncDisposable
    {
        private PipeServer _server = null!;
        private BanEngine _engine = null!;

        public string PipeName { get; private set; } = string.Empty;

        public FakeStore Store { get; } = new();

        public FakeFirewall Firewall { get; } = new();

        public static string NewPipeName() => "WinGuard-test-" + Guid.NewGuid().ToString("N");

        public static async Task<TestService> StartAsync(
            Func<NamedPipeServerStream, PipeClientIdentity.Result>? identify,
            string? pipeName = null)
        {
            var service = new TestService { PipeName = pipeName ?? NewPipeName() };
            var time = new FakeTimeProvider(new DateTimeOffset(2026, 3, 1, 12, 0, 0, TimeSpan.Zero));

            var holder = new SettingsHolder(service.Store, NullLogger<SettingsHolder>.Instance);
            await holder.LoadAsync();
            var settings = holder.Current.Clone();
            settings.HousekeepingInterval = TimeSpan.FromHours(6);
            await holder.ApplyAsync(settings);

            service._engine = new BanEngine(service.Store, service.Firewall, () => holder.Current, NullLogger<BanEngine>.Instance, time);
            await service._engine.StartAsync(CancellationToken.None);

            var handler = new IpcRequestHandler(
                service.Store,
                service._engine,
                holder,
                service.Firewall,
                new DetectorRuntimeState(),
                time,
                NullLogger<IpcRequestHandler>.Instance);

            var name = service.PipeName;
            service._server = new PipeServer(
                handler,
                NullLogger<PipeServer>.Instance,
                pipeFactory: () => new NamedPipeServerStream(
                    name,
                    PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous,
                    inBufferSize: 4096,   // same buffer sizes as the service's own pipe
                    outBufferSize: 4096),
                identify: identify);
            await service._server.StartAsync(CancellationToken.None);
            return service;
        }

        public async ValueTask DisposeAsync()
        {
            await _server.StopAsync(CancellationToken.None);
            _server.Dispose();
            await _engine.StopAsync(CancellationToken.None);
        }
    }
}
