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
    private const string SecondTestIp = "2001:db8::fa";

    [ElevatedFact]
    public void Block_unblock_and_clear_roundtrip()
    {

        Assert.True(IpMatcher.IsValid(TestIp));

        var firewall = new WindowsFirewall(NullLogger<WindowsFirewall>.Instance);
        try
        {
            firewall.ClearAll();

            firewall.Block(TestIp);
            Assert.Contains(TestIp, firewall.ListBlocked());

            // A second address must be added to the rule, not replace the first one, and a
            // fresh instance (no cache) must read both back from Windows.
            firewall.Block(SecondTestIp);
            var fresh = new WindowsFirewall(NullLogger<WindowsFirewall>.Instance);
            Assert.Contains(TestIp, fresh.ListBlocked());
            Assert.Contains(SecondTestIp, fresh.ListBlocked());
            firewall.Unblock(SecondTestIp);

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

    /// <summary>
    /// Reports the test as SKIPPED (not passed) when it cannot run, so an unelevated run never
    /// looks like the real firewall was exercised.
    /// </summary>
    private sealed class ElevatedFactAttribute : FactAttribute
    {
        public ElevatedFactAttribute()
        {
            if (!OperatingSystem.IsWindows())
            {
                Skip = "Requires Windows.";
            }
            else if (!IsAdministrator())
            {
                Skip = "Requires an elevated (Administrator) process: it edits the real Windows Firewall.";
            }
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