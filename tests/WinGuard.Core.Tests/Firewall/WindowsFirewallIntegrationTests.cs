using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Extensions.Logging.Abstractions;
using WinGuard.Core.Engine;
using WinGuard.Core.Firewall;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>
/// Exercises the real Windows Firewall COM implementation. Excluded from CI by the
/// <c>Category!=Integration</c> filter and requires an elevated process.
/// </summary>
[Trait("Category", "Integration")]
[SupportedOSPlatform("windows")]
public sealed class WindowsFirewallIntegrationTests
{
    // TEST-NET-3 (RFC 5737) address: never routable, safe to use as a test target.
    private const string TestIp = "203.0.113.250";

    [Fact]
    public void Block_unblock_and_clear_roundtrip()
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.WriteLine("Skipping firewall integration test: not running on Windows.");
            return;
        }

        if (!IsAdministrator())
        {
            Console.WriteLine("Skipping firewall integration test: process is not elevated (Administrator).");
            return;
        }

        Assert.True(IpMatcher.IsValid(TestIp));

        var firewall = new WindowsFirewall(NullLogger<WindowsFirewall>.Instance);
        try
        {
            firewall.ClearAll();

            firewall.Block(TestIp);
            Assert.Contains(TestIp, firewall.ListBlocked());

            firewall.Unblock(TestIp);
            Assert.DoesNotContain(TestIp, firewall.ListBlocked());

            firewall.Block(TestIp);
            Assert.Contains(TestIp, firewall.ListBlocked());

            firewall.ClearAll();
            Assert.DoesNotContain(TestIp, firewall.ListBlocked());
        }
        finally
        {
            firewall.ClearAll();
        }
    }

    private static bool IsAdministrator()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch (PlatformNotSupportedException)
        {
            return false;
        }
    }
}