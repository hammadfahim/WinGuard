using WinGuard.Core.Config;
using WinGuard.Service.Ipc;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>Reading the Logon audit policy, and the warning for features that need success auditing.</summary>
public sealed class AuditPrereqTests
{
    [Theory]
    [InlineData(0, false, false)]
    [InlineData(1, true, false)]
    [InlineData(2, false, true)]
    [InlineData(3, true, true)]
    public void The_audit_setting_value_is_read_as_flags(int value, bool success, bool failure)
    {
        var csv = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value\r\n"
            + $"VPS-01,System,Logon,{{0CCE9215-69AE-11D9-BED3-505054503030}},Whatever,,{value}\r\n";

        Assert.Equal((success, failure), IpcRequestHandler.ParseAuditCsv(csv));
    }

    [Theory]
    [InlineData("Success and Failure", true, true)]
    [InlineData("Success", true, false)]
    [InlineData("Failure", false, true)]
    [InlineData("No Auditing", false, false)]
    public void Without_a_setting_value_the_inclusion_text_decides(string inclusion, bool success, bool failure)
    {
        var csv = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting\r\n"
            + $"VPS-01,System,Logon,{{0CCE9215-69AE-11D9-BED3-505054503030}},{inclusion},\r\n";

        Assert.Equal((success, failure), IpcRequestHandler.ParseAuditCsv(csv));
    }

    [Fact]
    public void Empty_audit_output_means_nothing_is_audited()
    {
        Assert.Equal((false, false), IpcRequestHandler.ParseAuditCsv(string.Empty));
    }

    [Fact]
    public void Success_auditing_is_only_a_problem_when_a_logon_feature_is_on()
    {
        var settings = new WinGuardSettings();
        Assert.Null(IpcRequestHandler.LogonSuccessAuditWarning(settings, successAudited: false));

        settings.Rules.CompromiseAlerts = true;
        Assert.Null(IpcRequestHandler.LogonSuccessAuditWarning(settings, successAudited: true));
        Assert.Contains("auditpol", IpcRequestHandler.LogonSuccessAuditWarning(settings, successAudited: false), StringComparison.Ordinal);

        settings.Rules.CompromiseAlerts = false;
        settings.Rules.TrustAdminIpHours = 1;
        Assert.NotNull(IpcRequestHandler.LogonSuccessAuditWarning(settings, successAudited: false));
    }
}
