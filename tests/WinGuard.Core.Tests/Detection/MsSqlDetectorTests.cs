using Microsoft.Extensions.Logging.Abstractions;
using WinGuard.Core.Detection;
using WinGuard.Core.Model;
using WinGuard.Core.Tests.Fakes;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>Parser tests for the MS SQL Server Application 18456 detector (PLAN.md §4.3).</summary>
public sealed class MsSqlDetectorTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 31, 9, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Extracts_client_ip_and_user_from_message()
    {
        var xml = TestData.ReadText("mssql-18456.xml");
        var message = TestData.ReadText("mssql-18456-message.txt");
        var settings = TestData.NewSettings();

        Assert.True(MsSqlDetector.TryParse(xml, message, settings, TestData.SqlInstances, out var failed));
        Assert.NotNull(failed);

        Assert.Equal("203.0.113.77", failed!.IpAddress);
        Assert.Equal("sa", failed.UserName);
        Assert.Equal(ProtocolSource.MsSql, failed.Source);
        Assert.Equal("18456", failed.Detector);
    }

    [Fact]
    public void Ignores_message_matching_default_ignore_patterns()
    {
        var xml = TestData.ReadText("mssql-18456.xml");
        var ignored = TestData.ReadText("mssql-18456-message-ignored.txt");
        var settings = TestData.NewSettings();

        Assert.Contains(
            "Failed to open the explicitly specified database",
            settings.MsSql.IgnoreMessagePatterns);

        Assert.False(MsSqlDetector.TryParse(xml, ignored, settings, TestData.SqlInstances, out var failed));
        Assert.Null(failed);
    }

    [Fact]
    public void Null_message_falls_back_to_xml_and_drops_when_no_client()
    {
        var xml = TestData.ReadText("mssql-18456.xml");
        var settings = TestData.NewSettings();

        // The fixture XML contains no "[CLIENT: ...]" text at all.
        Assert.False(MsSqlDetector.TryParse(xml, null, settings, TestData.SqlInstances, out var failed));
        Assert.Null(failed);
    }

    // ---------- only an installed instance counts ----------

    private const string Message = "Login failed for user 'sa'. Reason: Password did not match. [CLIENT: 198.51.100.9]";

    // What ReportEvent with RegisterEventSource(null, name) leaves in the Application log.
    private static string Forged(string provider) => $"""
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <Provider Name="{provider}" />
            <EventID Qualifiers="49152">18456</EventID>
            <TimeCreated SystemTime="2026-10-31T09:30:45.0000000Z" />
            <Channel>Application</Channel>
            <Security UserID="S-1-5-21-1-2-3-1001" />
          </System>
          <EventData><Data>x</Data><Data>[CLIENT: 198.51.100.9]</Data></EventData>
        </Event>
        """;

    private static MsSqlDetector Detector(params string[] instances) =>
        new(() => TestData.NewSettings(), NullLogger<MsSqlDetector>.Instance, null, () => SqlServerInstances.ToProviderNames(instances));

    [Theory]
    [InlineData("MSSQLSERVER")]
    [InlineData("MSSQL$SQLEXPRESS")]
    public void An_event_a_standard_user_can_write_bans_nobody_on_a_machine_without_sql_server(string provider)
    {
        Assert.Null(Detector().ParseEvent(Forged(provider), Message));
    }

    [Theory]
    [InlineData("MSSQLSERVER", "MSSQLSERVER")]
    [InlineData("MSSQLSERVER", "mssqlserver")]
    [InlineData("SQLEXPRESS", "MSSQL$SQLEXPRESS")]
    [InlineData("SQLEXPRESS", "mssql$sqlexpress")]
    public void An_installed_instance_is_counted(string instance, string provider)
    {
        var failed = Detector(instance).ParseEvent(Forged(provider), Message);

        Assert.Equal("198.51.100.9", failed?.IpAddress);
    }

    [Theory]
    [InlineData("MSSQLSERVER", "MSSQL$OTHER")]
    [InlineData("SQLEXPRESS", "MSSQLSERVER")]
    [InlineData("SQLEXPRESS", "SQLEXPRESS")]
    [InlineData("MSSQLSERVER", "MSSQLSERVER2")]
    [InlineData("MSSQLSERVER", "MyMSSQLSERVER")]
    public void Any_other_source_is_ignored(string instance, string provider)
    {
        Assert.Null(Detector(instance).ParseEvent(Forged(provider), Message));
    }

    [Fact]
    public void Instance_names_become_provider_names()
    {
        var providers = SqlServerInstances.ToProviderNames(["MSSQLSERVER", "SQLEXPRESS", "mssqlserver", " "]);

        Assert.Equal(["MSSQL$SQLEXPRESS", "MSSQLSERVER"], providers.Order(StringComparer.Ordinal));
    }

    [Fact]
    public void The_real_lookup_reads_the_registry_without_failing()
    {
        // Whatever this machine has installed; every name it finds must be a provider name.
        Assert.All(SqlServerInstances.ReadInstalledProviders(), provider => Assert.StartsWith("MSSQL", provider));
    }

    [Fact]
    public void A_storm_of_events_does_not_read_the_registry_each_time()
    {
        var reads = 0;
        var instances = new SqlServerInstances(
            () =>
            {
                reads++;
                return TestData.SqlInstances;
            },
            new FakeTimeProvider(T0),
            NullLogger.Instance);

        for (var i = 0; i < 1000; i++)
        {
            Assert.Contains("MSSQLSERVER", instances.Current);
        }

        Assert.Equal(1, reads);
    }

    [Fact]
    public void An_instance_installed_later_is_noticed_and_a_removed_one_forgotten()
    {
        var time = new FakeTimeProvider(T0);
        var installed = Array.Empty<string>();
        var instances = new SqlServerInstances(() => SqlServerInstances.ToProviderNames(installed), time, NullLogger.Instance);
        Assert.Empty(instances.Current);

        installed = ["SQLEXPRESS"];
        Assert.Empty(instances.Current);

        time.Advance(SqlServerInstances.RefreshInterval);
        Assert.Contains("MSSQL$SQLEXPRESS", instances.Current);

        installed = [];
        time.Advance(SqlServerInstances.RefreshInterval);
        Assert.Empty(instances.Current);
    }

    [Fact]
    public void A_failed_reading_keeps_the_last_known_instances()
    {
        var time = new FakeTimeProvider(T0);
        var fail = false;
        var instances = new SqlServerInstances(
            () => fail ? throw new UnauthorizedAccessException("denied") : TestData.SqlInstances,
            time,
            NullLogger.Instance);
        Assert.NotEmpty(instances.Current);

        fail = true;
        time.Advance(SqlServerInstances.RefreshInterval);

        Assert.Contains("MSSQLSERVER", instances.Current);
    }

    [Fact]
    public void Until_a_reading_succeeds_nothing_counts_as_sql_server()
    {
        var instances = new SqlServerInstances(
            () => throw new UnauthorizedAccessException("denied"),
            new FakeTimeProvider(T0),
            NullLogger.Instance);

        Assert.Empty(instances.Current);
    }
}