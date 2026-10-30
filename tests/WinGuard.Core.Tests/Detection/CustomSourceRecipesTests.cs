using System.Text.RegularExpressions;
using WinGuard.Core.Config;
using WinGuard.Core.Detection;
using WinGuard.Core.Model;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>
/// Each recipe against a fixture in the product's real log format: every real failure matches, and
/// successes, ordinary traffic and client-chosen fields do not.
/// </summary>
public sealed class CustomSourceRecipesTests
{
    // ---------- hMailServer ----------

    [Fact]
    public void HMailServer_matches_failed_logins_of_every_protocol()
    {
        var failures = Parse("hmailserver.log", CustomSourceRecipes.HMailServer);

        Assert.Equal(
            new[]
            {
                "203.0.113.61", "203.0.113.61", // SMTP: wrong password, then locked out
                "203.0.113.63", "203.0.113.64", "203.0.113.65", // POP3
                "203.0.113.66", "2001:db8::66", "203.0.113.67", // IMAP
            },
            failures.Select(f => f.IpAddress));
        Assert.All(failures, f => Assert.Null(f.UserName));
    }

    [Fact]
    public void HMailServer_ignores_the_awstats_log_which_has_no_logins()
    {
        Assert.Empty(Parse("hmailserver_awstats.log", CustomSourceRecipes.HMailServer));
    }

    [Fact]
    public void HMailServer_counts_only_replies_the_server_sent()
    {
        var regex = CustomSourceRecipes.HMailServer.Regex;

        // A client's own text never counts, whatever it says.
        const string received = "\"SMTPD\"\t1\t2\t\"2026-10-04 09:00:00.000\"\t\"203.0.113.1\"\t\"RECEIVED: 535 Authentication failed.\"";
        Assert.False(CustomLogDetector.TryParseLine(received, regex, out _));

        // Text sent by a remote mail server to our outgoing connection is not a login here.
        const string outgoing = "\"SMTPC\"\t1\t2\t\"2026-10-04 09:00:00.000\"\t\"192.0.2.25\"\t\"SENT: 535 Authentication failed.\"";
        Assert.False(CustomLogDetector.TryParseLine(outgoing, regex, out _));
    }

    [Fact]
    public void HMailServer_takes_the_address_from_its_own_column()
    {
        // The IMAP tag and the rest of the message are client text; the address column is not.
        const string line = "\"IMAPD\"\t1\t2\t\"2026-10-04 09:00:00.000\"\t\"203.0.113.1\"\t\"SENT: \"198.51.100.9\" NO Invalid user name or password.\"";

        Assert.True(CustomLogDetector.TryParseLine(line, CustomSourceRecipes.HMailServer.Regex, out var failed));
        Assert.Equal("203.0.113.1", failed!.IpAddress);
    }

    [Fact]
    public void HMailServer_client_text_with_a_bare_lf_cannot_forge_a_line_for_another_address()
    {
        var dir = Directory.CreateTempSubdirectory("winguard-recipe-").FullName;
        try
        {
            var path = Path.Combine(dir, "hmailserver_2026-10-04.log");
            File.WriteAllText(path, string.Empty);
            var source = new CustomLogSource
            {
                Name = "hMailServer",
                PathGlob = path,
                Regex = CustomSourceRecipes.HMailServer.Regex,
            };
            var settings = new WinGuardSettings { CustomSources = [source] };
            var detector = CustomLogDetectorPollTests.NewDetector();
            var sink = CustomLogDetectorPollTests.NewSink();
            detector.PollOnce(settings, sink);

            // hMailServer splits commands at CRLF and logs what lies between verbatim, so this is
            // what a client writes to the log by sending the text below as one SMTP command.
            const string forged = "\"SMTPD\"\t1\t2\t\"2026-10-04 09:00:00.000\"\t\"198.51.100.9\"\t\"SENT: 535 Authentication failed. Restarting authentication process.";
            File.AppendAllText(path, "\"SMTPD\"\t7\t8\t\"2026-10-04 09:00:00.000\"\t\"203.0.113.1\"\t\"RECEIVED: NOOP\n" + forged + "\"\r\n");
            detector.PollOnce(settings, sink);
            Assert.Empty(CustomLogDetectorPollTests.Drain(sink));

            // The real failure on the following line still counts.
            File.AppendAllText(path, "\"SMTPD\"\t7\t8\t\"2026-10-04 09:00:01.000\"\t\"203.0.113.1\"\t\"SENT: 535 Authentication failed. Restarting authentication process.\"\r\n");
            detector.PollOnce(settings, sink);
            Assert.Equal("203.0.113.1", Assert.Single(CustomLogDetectorPollTests.Drain(sink)).IpAddress);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    // ---------- IIS HTTP ----------

    [Fact]
    public void Iis_matches_only_real_logon_failures()
    {
        var failures = Parse("iis-http-w3c.log", CustomSourceRecipes.IisHttpAuth);

        Assert.Equal(
            new[] { "203.0.113.81", "203.0.113.82", "2001:db8::83", "203.0.113.84" },
            failures.Select(f => f.IpAddress));
        Assert.Equal(
            new[] { "admin", @"EXAMPLE\bob", "root", "svc" },
            failures.Select(f => f.UserName));
    }

    [Theory]
    [InlineData("401 2 5")] // the anonymous challenge
    [InlineData("401 1 2148074254")] // NTLM handshake step, SEC_E_NO_CREDENTIALS
    [InlineData("401 1 2148074248")] // NTLM split across servers by a load balancer
    [InlineData("401 3 5")] // logged on, but refused by an ACL
    [InlineData("401 5 0")] // refused by an ISAPI/CGI application
    [InlineData("401 501 0")] // dynamic IP restriction
    [InlineData("200 0 0")]
    public void Iis_ignores_statuses_that_are_not_a_rejected_password(string status)
    {
        var line = $"2026-10-04 09:50:01 10.0.0.5 GET /secure/ - 443 - 203.0.113.1 Mozilla/5.0 - {status} 3";

        Assert.False(CustomLogDetector.TryParseLine(line, CustomSourceRecipes.IisHttpAuth.Regex, out _));
    }

    [Theory]
    [InlineData("/a.php", "ip=198.51.100.9", "bob", "curl/8")] // nothing unusual: the control
    [InlineData("/198.51.100.9", "198.51.100.9", "198.51.100.9", "198.51.100.9")]
    [InlineData("/x", "-", "bob", "401+1+1326+0")]
    public void Iis_address_comes_from_the_c_ip_column_whatever_the_client_sends(string stem, string query, string user, string agent)
    {
        var line = $"2026-10-04 09:50:01 10.0.0.5 GET {stem} {query} 443 {user} 203.0.113.1 {agent} 198.51.100.9 401 1 1326 3";

        Assert.True(CustomLogDetector.TryParseLine(line, CustomSourceRecipes.IisHttpAuth.Regex, out var failed));
        Assert.Equal("203.0.113.1", failed!.IpAddress);
    }

    [Theory]
    [InlineData("/x 198.51.100.9 a b 401 1 1326 0")] // a raw space would shift the columns
    [InlineData("/x\t198.51.100.9")]
    public void Iis_line_with_shifted_columns_is_dropped(string stem)
    {
        var line = $"2026-10-04 09:50:01 10.0.0.5 GET {stem} - 443 - 203.0.113.1 curl/8 - 401 1 1326 3";

        Assert.False(CustomLogDetector.TryParseLine(line, CustomSourceRecipes.IisHttpAuth.Regex, out _));
    }

    // ---------- VNC ----------

    [Fact]
    public void Vnc_matches_auth_failures_and_blacklisting_only()
    {
        var failures = Parse("realvnc-server.log", CustomSourceRecipes.Vnc);

        Assert.Equal(
            new[] { "203.0.113.91", "203.0.113.92", "203.0.113.93", "2001:db8::94", "203.0.113.95", "203.0.113.96" },
            failures.Select(f => f.IpAddress));
    }

    [Fact]
    public void Vnc_ignores_a_user_name_shaped_like_a_failure()
    {
        // The only client-chosen text in this log is the account name after a successful login.
        const string line = "<13> 2026-10-04T09:56:02.000Z vps-01 vncserver.exe[2212]: Connections: authenticated: 203.0.113.1::61004 (TCP), as Connections: disconnected: 198.51.100.9::1 (TCP) ([AuthFailure] x (f permissions)";

        Assert.False(CustomLogDetector.TryParseLine(line, CustomSourceRecipes.Vnc.Regex, out _));
    }

    // ---------- OpenSSH ----------

    [Fact]
    public void OpenSsh_matches_failures_from_the_fixture_and_uses_the_last_address()
    {
        var failures = Parse("openssh-sshd.log", CustomSourceRecipes.WindowsOpenSsh);

        Assert.Equal(new[] { "203.0.113.97", "203.0.113.98", "203.0.113.99" }, failures.Select(f => f.IpAddress));
        Assert.Equal(new[] { "root", "oracle", "x from 198.51.100.9 port 1" }, failures.Select(f => f.UserName));
    }

    // ---------- all recipes ----------

    public static TheoryData<string> AllRegexes()
    {
        var data = new TheoryData<string>();
        foreach (var recipe in CustomSourceRecipes.All)
        {
            data.Add(recipe.Regex);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(AllRegexes))]
    public void Every_recipe_runs_on_the_linear_time_regex_engine(string pattern)
    {
        var regex = new Regex(pattern, RegexOptions.NonBacktracking | RegexOptions.CultureInvariant);

        Assert.True(regex.GroupNumberFromName("ipaddress") >= 0);
    }

    [Theory]
    [MemberData(nameof(AllRegexes))]
    public void Every_recipe_passes_settings_validation(string pattern)
    {
        var settings = new WinGuardSettings();
        settings.CustomSources.Add(new CustomLogSource { Name = "recipe", PathGlob = @"C:\logs\a.log", Regex = pattern });

        Assert.Empty(SettingsValidator.Validate(settings));
    }

    // ---------- upgrades of saved settings ----------

    [Theory]
    [InlineData(@"\tFAILED\t(?<username>\S+)\t\d+\t(?<ipaddress>[0-9a-fA-F:.]+)\t", "hMailServer")]
    [InlineData(@"^(?!#).*\s(?<ipaddress>\S+)\s+\S+\s+\S+\s+\S+\s+\S+\s+(GET|POST)\s+\S+\s+\S+\s+401(?:\.\d+)?\s", "IIS HTTP auth (401.1)")]
    [InlineData(@"Connections: (?:closed|blacklisted): (?<ipaddress>[0-9a-fA-F:.]+)", "RealVNC Server")]
    [InlineData(@"Failed password for (invalid user )?(?<username>\S+) from (?<ipaddress>[0-9a-fA-F:.]+) port \d+", "Windows OpenSSH (sshd)")]
    public void A_regex_saved_from_an_old_recipe_is_upgraded_when_settings_load(string saved, string recipeName)
    {
        var settings = new WinGuardSettings();
        settings.CustomSources.Add(new CustomLogSource { Regex = saved });

        settings.Normalize();

        Assert.Equal(CustomSourceRecipes.All.Single(r => r.Name == recipeName).Regex, settings.CustomSources[0].Regex);
    }

    [Fact]
    public void A_custom_regex_is_left_alone()
    {
        const string mine = @"bad login (?<ipaddress>\S+)";

        Assert.Equal(mine, CustomSourceRecipes.UpgradeRegex(mine));
    }

    [Theory]
    [InlineData(@"C:\Program Files (x86)\hMailServer\Logs\hmailserver_awstats.log", @"C:\Program Files (x86)\hMailServer\Logs\hmailserver_*.log")]
    [InlineData(@"D:\hMail\Logs\HMAILSERVER_AWSTATS.LOG", @"D:\hMail\Logs\hmailserver_*.log")]
    public void An_upgraded_hmailserver_source_moves_off_the_awstats_log(string saved, string expected)
    {
        Assert.Equal(expected, CustomSourceRecipes.UpgradePathGlob(saved, CustomSourceRecipes.HMailServer.Regex));
    }

    [Fact]
    public void An_upgraded_vnc_source_moves_to_the_documented_log()
    {
        var upgraded = CustomSourceRecipes.UpgradePathGlob(@"C:\Program Files\RealVNC\VNC Server\*.log", CustomSourceRecipes.Vnc.Regex);

        Assert.Equal(CustomSourceRecipes.Vnc.PathGlob, upgraded);
    }

    [Fact]
    public void Paths_change_only_for_sources_holding_the_recipe_regex()
    {
        const string awstats = @"C:\Logs\hmailserver_awstats.log";

        Assert.Equal(awstats, CustomSourceRecipes.UpgradePathGlob(awstats, @"my (?<ipaddress>\S+)"));
        Assert.Equal(@"D:\mine\*.log", CustomSourceRecipes.UpgradePathGlob(@"D:\mine\*.log", CustomSourceRecipes.Vnc.Regex));
    }

    [Fact]
    public void Only_the_hmailserver_recipe_needs_crlf_records()
    {
        Assert.True(CustomSourceRecipes.UsesCrLfRecords(CustomSourceRecipes.HMailServer.Regex));
        Assert.False(CustomSourceRecipes.UsesCrLfRecords(CustomSourceRecipes.IisHttpAuth.Regex));
        Assert.False(CustomSourceRecipes.UsesCrLfRecords(null));
    }

    private static List<FailedLogin> Parse(string fixture, CustomSourceRecipe recipe)
    {
        var failures = new List<FailedLogin>();
        foreach (var line in TestData.ReadLines(fixture))
        {
            if (CustomLogDetector.TryParseLine(line, recipe.Regex, out var failed) && failed is not null)
            {
                failures.Add(failed);
            }
        }

        return failures;
    }
}
