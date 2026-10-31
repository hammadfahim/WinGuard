using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.Principal;
using WinGuard.Core.Ipc;
using WinGuard.Service.Ipc;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>
/// Who may own and open the pipe: the rule the console applies to the server, and the service's
/// refusal to open a pipe it cannot secure.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class PipeSecurityTests
{
    private static readonly SecurityIdentifier LocalSystem = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier Users = new(WellKnownSidType.BuiltinUsersSid, null);
    private static readonly SecurityIdentifier SomeUser = new("S-1-5-21-1000000000-2000000000-3000000000-1001");

    private static string NewPipeName() => "WinGuard-test-" + Guid.NewGuid().ToString("N");

    [Fact]
    public void LocalSystem_is_trusted_whatever_its_groups()
    {
        Assert.True(PipeServerIdentity.Evaluate(LocalSystem, null, 4).Trusted);
    }

    [Fact]
    public void An_elevated_administrator_is_trusted_for_console_runs()
    {
        var result = PipeServerIdentity.Evaluate(SomeUser, [Users, Administrators], 1234);

        Assert.True(result.Trusted);
        Assert.Null(result.Problem);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Anyone_else_is_refused_and_the_message_says_who(bool hasGroups)
    {
        // Enabled groups only: a non-elevated administrator's Administrators group is deny-only.
        var result = PipeServerIdentity.Evaluate(SomeUser, hasGroups ? [Users] : null, 1234);

        Assert.False(result.Trusted);
        Assert.Contains("Process 1234", result.Problem);
        Assert.Contains(SomeUser.Value, result.Problem);
    }

    [Fact]
    public void An_identity_that_cannot_be_read_is_refused()
    {
        var result = PipeServerIdentity.Evaluate(null, null, 1234);

        Assert.False(result.Trusted);
        Assert.Contains("unknown user", result.Problem);
    }

    [Fact]
    public void A_pipe_that_cannot_be_secured_is_not_opened_at_all()
    {
        var name = NewPipeName();

        var error = Assert.Throws<InvalidOperationException>(() => PipeServer.CreateSecuredPipe(name, "not an SDDL string", firstInstance: true));

        Assert.Contains("security descriptor", error.Message);
        Assert.DoesNotContain(Directory.EnumerateFiles(@"\\.\pipe\"), path => path.EndsWith(name, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task The_service_pipe_only_lets_administrators_in()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var name = NewPipeName();
        using var pipe = PipeServer.CreateSecuredPipe(name, PipeServer.PipeSddl, firstInstance: true);
        var accepted = pipe.WaitForConnectionAsync();
        using var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);

        if (new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
        {
            await client.ConnectAsync(5000);
            await accepted;
        }
        else
        {
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => client.ConnectAsync(5000));
        }
    }

    [Fact]
    public void A_squatted_name_is_refused_with_a_reason()
    {
        var name = NewPipeName();
        using var squatter = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);

        var error = Assert.Throws<IOException>(() => PipeServer.CreateSecuredPipe(name, PipeServer.PipeSddl, firstInstance: true));

        Assert.Contains("squatting", error.Message);
    }

    [Fact]
    public void Accept_failures_back_off_instead_of_logging_every_second()
    {
        Assert.Equal(new[] { 1d, 2, 4, 8, 16, 32, 60, 60 }, Enumerable.Range(1, 8).Select(n => PipeServer.AcceptRetryDelay(n).TotalSeconds));
        Assert.Equal(TimeSpan.FromSeconds(60), PipeServer.AcceptRetryDelay(int.MaxValue));
    }
}
