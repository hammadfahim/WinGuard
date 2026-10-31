using System.Text.Json;
using WinGuard.Core.Config;
using WinGuard.Core.Ipc;
using WinGuard.Core.Model;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>The port types and settings behind port-scoped bans: no engine, no firewall.</summary>
public sealed class PortProfilesTests
{
    // ---------- PortSet ----------

    [Theory]
    [InlineData(new[] { "3389", "1433" }, "1433,3389")]
    [InlineData(new[] { "3389", "1433", "3389" }, "1433,3389")]
    [InlineData(new[] { " 3389 ", "1433" }, "1433,3389")]
    [InlineData(new[] { "21", "20-22" }, "20-22")]
    [InlineData(new[] { "20-25", "24-30" }, "20-30")]
    [InlineData(new[] { "3389", "3390" }, "3389-3390")]
    [InlineData(new[] { "50000-50100", "21" }, "21,50000-50100")]
    public void A_port_set_has_one_canonical_form(string[] tokens, string expected)
    {
        Assert.Equal(expected, PortSet.Parse(tokens).Text);
    }

    [Theory]
    [InlineData("")]
    [InlineData("ftp")]
    [InlineData("70000,500-100,1-2-3,-5,5-")]
    public void Nothing_usable_means_all_ports(string tokens)
    {
        Assert.True(PortSet.Parse(tokens.Split(',')).IsAll);
    }

    [Fact]
    public void Garbage_next_to_valid_ports_is_dropped()
    {
        Assert.Equal("3389", PortSet.Parse(["3389", "bogus"]).Text);
    }

    [Fact]
    public void The_same_set_written_differently_is_one_family()
    {
        var one = PortSet.Parse(["3389", "1433"]);
        var other = PortSet.Parse(["1433", " 3389", "1433"]);

        Assert.Equal(one, other);
        Assert.Equal(one.RuleFamily, other.RuleFamily);
    }

    [Fact]
    public void Different_sets_are_different_families()
    {
        var families = new[] { "21", "22", "1433", "3389", "1433,3389", "21-22" }
            .Select(text => PortSet.Parse(text.Split(',')).RuleFamily)
            .ToHashSet();

        Assert.Equal(6, families.Count);
        Assert.DoesNotContain(string.Empty, families);
    }

    [Fact]
    public void A_rule_family_is_stable_across_releases()
    {
        // It is part of the rule names in a customer's firewall: changing it orphans their rules.
        Assert.Equal("PCB2DCA9D", PortSet.Parse(["3389"]).RuleFamily);
        Assert.Equal(string.Empty, PortSet.All.RuleFamily);
    }

    [Fact]
    public void Coverage_understands_ranges_and_all_ports()
    {
        var wide = PortSet.Parse(["20-30", "3389"]);

        Assert.True(wide.Covers(PortSet.Parse(["21"])));
        Assert.True(wide.Covers(PortSet.Parse(["22-25", "3389"])));
        Assert.False(wide.Covers(PortSet.Parse(["1433"])));
        Assert.False(wide.Covers(PortSet.Parse(["30-31"])));
        Assert.False(wide.Covers(PortSet.All));
        Assert.True(PortSet.All.Covers(wide));
        Assert.True(PortSet.All.Covers(PortSet.All));
    }

    [Fact]
    public void A_union_with_all_ports_is_all_ports()
    {
        Assert.True(PortSet.Parse(["3389"]).Union(PortSet.All).IsAll);
        Assert.True(PortSet.All.Union(PortSet.Parse(["3389"])).IsAll);
        Assert.Equal("1433,3389", PortSet.Parse(["3389"]).Union(PortSet.Parse(["1433"])).Text);
    }

    // ---------- scopes ----------

    [Fact]
    public void An_engine_without_a_profile_uses_the_global_setting()
    {
        var settings = new WinGuardSettings();
        var scope = PortProfiles.ScopeFor(ProtocolSource.Rdp, "4625");

        Assert.True(PortProfiles.Resolve(scope, settings).IsAll);

        settings.BlockedPorts = ["3389"];
        Assert.Equal("3389", PortProfiles.Resolve(scope, settings).Text);
    }

    [Fact]
    public void An_engine_profile_beats_the_global_setting()
    {
        var settings = new WinGuardSettings { BlockedPorts = ["22"], MsSql = { BlockedPorts = ["1433"] } };

        Assert.Equal("1433", PortProfiles.Resolve(PortProfiles.ScopeFor(ProtocolSource.MsSql, "18456"), settings).Text);
        Assert.Equal("22", PortProfiles.Resolve(PortProfiles.ScopeFor(ProtocolSource.Rdp, "4625"), settings).Text);
    }

    [Fact]
    public void A_ban_from_before_profiles_follows_the_global_setting_not_any_profile()
    {
        var settings = new WinGuardSettings { Rdp = { BlockedPorts = ["3389"] } };

        Assert.True(PortProfiles.Resolve(null, settings).IsAll);

        settings.BlockedPorts = ["22"];
        Assert.Equal("22", PortProfiles.Resolve(null, settings).Text);
    }

    [Fact]
    public void The_all_ports_scope_ignores_every_setting()
    {
        var settings = new WinGuardSettings { BlockedPorts = ["22"], Rdp = { BlockedPorts = ["3389"] } };

        Assert.True(PortProfiles.Resolve(PortProfiles.AllPorts, settings).IsAll);
    }

    [Fact]
    public void Widening_unions_the_engines_and_is_order_independent()
    {
        var settings = new WinGuardSettings { Rdp = { BlockedPorts = ["3389"] }, MsSql = { BlockedPorts = ["1433"] } };
        var rdp = PortProfiles.ScopeFor(ProtocolSource.Rdp, null);
        var sql = PortProfiles.ScopeFor(ProtocolSource.MsSql, null);

        var widened = PortProfiles.Widen(rdp, sql);

        Assert.Equal("1433,3389", PortProfiles.Resolve(widened, settings).Text);
        Assert.Equal(widened, PortProfiles.Widen(sql, rdp));
        Assert.Equal(widened, PortProfiles.Widen(widened, sql));
    }

    [Fact]
    public void One_engine_without_ports_makes_a_widened_scope_all_ports()
    {
        var settings = new WinGuardSettings { Rdp = { BlockedPorts = ["3389"] } };

        var widened = PortProfiles.Widen(PortProfiles.ScopeFor(ProtocolSource.Rdp, null), PortProfiles.ScopeFor(ProtocolSource.Ftp, null));

        Assert.True(PortProfiles.Resolve(widened, settings).IsAll);
    }

    [Fact]
    public void Widening_never_takes_a_ban_off_all_ports()
    {
        Assert.Equal(PortProfiles.AllPorts, PortProfiles.Widen(PortProfiles.AllPorts, "Rdp"));
    }

    [Fact]
    public void Widening_a_ban_from_before_profiles_keeps_it_on_the_global_ports_too()
    {
        var settings = new WinGuardSettings { BlockedPorts = ["22"], MsSql = { BlockedPorts = ["1433"] } };

        Assert.Equal("22,1433", PortProfiles.Resolve(PortProfiles.Widen(null, "MsSql"), settings).Text);
    }

    [Fact]
    public void Custom_sources_have_their_own_profiles()
    {
        var settings = new WinGuardSettings
        {
            CustomSources =
            [
                new CustomLogSource { Name = "hmail", BlockedPorts = ["25", "587"] },
                new CustomLogSource { Name = "My, odd\nsource", BlockedPorts = ["8443"] },
                new CustomLogSource { Name = string.Empty, BlockedPorts = ["9000"] },
                new CustomLogSource { Name = "open" },
            ],
        };

        Assert.Equal("25,587", PortProfiles.Resolve(PortProfiles.ScopeFor(ProtocolSource.Custom, "hmail"), settings).Text);
        Assert.Equal("25,587", PortProfiles.Resolve(PortProfiles.ScopeFor(ProtocolSource.Custom, "HMAIL"), settings).Text);
        Assert.Equal("8443", PortProfiles.Resolve(PortProfiles.ScopeFor(ProtocolSource.Custom, "My, odd\nsource"), settings).Text);
        Assert.Equal("9000", PortProfiles.Resolve(PortProfiles.ScopeFor(ProtocolSource.Custom, null), settings).Text);
        Assert.True(PortProfiles.Resolve(PortProfiles.ScopeFor(ProtocolSource.Custom, "open"), settings).IsAll);
    }

    [Fact]
    public void A_scope_with_an_odd_source_name_widens_as_one_engine()
    {
        var settings = new WinGuardSettings { CustomSources = [new CustomLogSource { Name = "a\nb", BlockedPorts = ["8443"] }], Rdp = { BlockedPorts = ["3389"] } };

        var widened = PortProfiles.Widen("Rdp", PortProfiles.ScopeFor(ProtocolSource.Custom, "a\nb"));

        Assert.Equal("3389,8443", PortProfiles.Resolve(widened, settings).Text);
    }

    [Fact]
    public void A_deleted_custom_source_falls_back_to_the_global_setting()
    {
        var scope = PortProfiles.ScopeFor(ProtocolSource.Custom, "gone");

        Assert.True(PortProfiles.Resolve(scope, new WinGuardSettings()).IsAll);
        Assert.Equal("22", PortProfiles.Resolve(scope, new WinGuardSettings { BlockedPorts = ["22"] }).Text);
    }

    [Fact]
    public void An_engine_this_version_has_no_profile_for_uses_the_global_setting()
    {
        Assert.True(PortProfiles.Resolve("SomethingNew", new WinGuardSettings()).IsAll);
    }

    [Fact]
    public void Ftp_passive_range_comes_with_the_ftp_profile()
    {
        var settings = new WinGuardSettings { Ftp = { BlockedPorts = ["21"], PassivePortRange = "50000-50100" } };

        Assert.Equal("21,50000-50100", PortProfiles.Resolve("Ftp", settings).Text);
    }

    [Fact]
    public void Ftp_passive_range_alone_is_no_profile()
    {
        var settings = new WinGuardSettings { Ftp = { PassivePortRange = "50000-50100" } };

        Assert.True(PortProfiles.Resolve("Ftp", settings).IsAll);
    }

    // ---------- settings ----------

    [Fact]
    public void Settings_saved_before_profiles_existed_have_none()
    {
        var settings = JsonSerializer.Deserialize<WinGuardSettings>(
            """{"blockedPorts":["22"],"rdp":{"enabled":true},"customSources":[{"name":"x"}]}""",
            IpcJson.Options)!;

        settings.Normalize();

        Assert.Equal(["22"], settings.BlockedPorts);
        Assert.Empty(settings.Rdp.BlockedPorts);
        Assert.Empty(settings.CustomSources[0].BlockedPorts);
        Assert.Empty(settings.Ftp.PassivePortRange);
        Assert.Empty(settings.BlocklistFiles);
    }

    [Fact]
    public void Profiles_are_validated_like_the_global_list()
    {
        string[] dirty = ["3389", " 21-22 ", "70000", "500-100", "1-2-3", "-5", "5-", "ftp", "0", "65535"];
        string[] clean = ["3389", "21-22", "0", "65535"];
        var settings = new WinGuardSettings
        {
            Rdp = { BlockedPorts = dirty },
            MsSql = { BlockedPorts = dirty },
            Ftp = { BlockedPorts = dirty },
            CustomSources = [new CustomLogSource { Name = "x", BlockedPorts = dirty }],
        };

        settings.Normalize();

        Assert.Equal(clean, settings.Rdp.BlockedPorts);
        Assert.Equal(clean, settings.MsSql.BlockedPorts);
        Assert.Equal(clean, settings.Ftp.BlockedPorts);
        Assert.Equal(clean, settings.CustomSources[0].BlockedPorts);
    }

    [Fact]
    public void Explicit_nulls_in_stored_settings_do_not_crash_normalization()
    {
        var settings = JsonSerializer.Deserialize<WinGuardSettings>(
            """{"blocklistFiles":null,"rdp":{"blockedPorts":null},"ftp":{"passivePortRange":null},"customSources":[null,{"name":"x","blockedPorts":null}]}""",
            IpcJson.Options)!;

        settings.Normalize();

        Assert.Empty(settings.Rdp.BlockedPorts);
        Assert.Empty(settings.BlocklistFiles);
        Assert.Empty(settings.Ftp.PassivePortRange);
        Assert.Empty(settings.CustomSources[1].BlockedPorts);
    }

    [Theory]
    [InlineData(" 50000-50100 ", "50000-50100")]
    [InlineData("50000", "50000")]
    [InlineData("passive", "")]
    [InlineData("50100-50000", "")]
    public void The_passive_range_is_validated_too(string given, string expected)
    {
        var settings = new WinGuardSettings { Ftp = { PassivePortRange = given } };

        settings.Normalize();

        Assert.Equal(expected, settings.Ftp.PassivePortRange);
    }

    [Fact]
    public void Blocklist_paths_are_trimmed_and_listed_once()
    {
        var settings = new WinGuardSettings { BlocklistFiles = [@" C:\lists\drop.txt ", @"c:\LISTS\drop.txt", "  ", @"C:\lists\mine.txt"] };

        settings.Normalize();

        Assert.Equal([@"C:\lists\drop.txt", @"C:\lists\mine.txt"], settings.BlocklistFiles);
    }

    [Fact]
    public void Profiles_survive_cloning()
    {
        var settings = new WinGuardSettings
        {
            Rdp = { BlockedPorts = ["3389"] },
            Ftp = { PassivePortRange = "50000-50100" },
            CustomSources = [new CustomLogSource { Name = "x", BlockedPorts = ["8443"] }],
            BlocklistFiles = [@"C:\lists\drop.txt"],
        };

        var clone = settings.Clone();

        Assert.Equal(["3389"], clone.Rdp.BlockedPorts);
        Assert.Equal("50000-50100", clone.Ftp.PassivePortRange);
        Assert.Equal(["8443"], clone.CustomSources[0].BlockedPorts);
        Assert.Equal([@"C:\lists\drop.txt"], clone.BlocklistFiles);
    }

    [Theory]
    [InlineData(@"\\server\share\drop.txt")]
    [InlineData(@"\\?\C:\lists\drop.txt")]
    [InlineData(@"\\.\pipe\drop")]
    [InlineData("//server/share/drop.txt")]
    public void A_blocklist_on_the_network_is_refused(string path)
    {
        var problems = SettingsValidator.Validate(new WinGuardSettings { BlocklistFiles = [path] });

        Assert.Contains(path, Assert.Single(problems));
    }

    [Fact]
    public void A_blocklist_on_a_local_drive_is_accepted()
    {
        Assert.Empty(SettingsValidator.Validate(new WinGuardSettings { BlocklistFiles = [@"C:\lists\drop.txt"] }));
    }

    // ---------- presets ----------

    [Fact]
    public void The_rdp_preset_uses_the_port_it_is_given()
    {
        var preset = PortPresets.Rdp(listeningPort: 13389);

        Assert.Equal(["13389"], preset.Ports);
        Assert.Null(preset.Note);
    }

    [Fact]
    public void The_rdp_preset_says_so_when_it_had_to_assume_the_default()
    {
        var preset = PortPresets.Rdp(listeningPort: null);

        Assert.Equal(["3389"], preset.Ports);
        Assert.Contains("3389", preset.Note);
    }

    [Theory]
    [InlineData(3389, 3389)]
    [InlineData(65535, 65535)]
    public void A_registry_dword_holding_a_port_is_used(int value, int expected)
    {
        Assert.Equal(expected, PortPresets.ParseRdpPort(value));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(65536)]
    [InlineData("3389")]
    [InlineData(null)]
    public void Anything_else_in_the_registry_is_no_port(object? value)
    {
        Assert.Null(PortPresets.ParseRdpPort(value));
    }

    [Fact]
    public void The_machines_rdp_port_can_be_read_without_writing_anything()
    {
        // Any value is fine, this machine's listener is its own business; it must just be usable.
        var preset = PortPresets.Rdp();

        Assert.True(PortSet.TryParseRange(Assert.Single(preset.Ports), out _, out _));
    }

    [Fact]
    public void The_ftp_preset_never_guesses_a_passive_range()
    {
        var preset = PortPresets.Ftp(null);

        Assert.Equal(["21"], preset.Ports);
        Assert.Contains("passive", preset.Note, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void The_ftp_preset_takes_the_configured_passive_range()
    {
        var preset = PortPresets.Ftp(" 50000-50100 ");

        Assert.Equal(["21", "50000-50100"], preset.Ports);
        Assert.Null(preset.Note);
    }

    [Fact]
    public void The_ftp_preset_refuses_a_passive_range_that_is_not_one()
    {
        var preset = PortPresets.Ftp("high");

        Assert.Equal(["21"], preset.Ports);
        Assert.Contains("high", preset.Note);
    }

    [Fact]
    public void Every_preset_is_a_valid_profile()
    {
        var presets = PortPresets.All(new WinGuardSettings { Ftp = { PassivePortRange = "50000-50100" } });

        Assert.Equal(["RDP", "MS SQL", "FTP", "SSH"], presets.Select(preset => preset.Name));
        Assert.Contains("50000-50100", presets.Single(preset => preset.Name == "FTP").Ports);
        Assert.All(presets, preset => Assert.All(preset.Ports, port => Assert.True(PortSet.TryParseRange(port, out _, out _))));
        Assert.Equal(["22"], presets.Single(preset => preset.Name == "SSH").Ports);
        Assert.Equal(["1433"], presets.Single(preset => preset.Name == "MS SQL").Ports);
    }
}
