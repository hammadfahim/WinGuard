using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Engine;
using WinGuard.Core.Firewall;
using WinGuard.Core.Model;
using WinGuard.Core.Tests.Fakes;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>
/// Local blocklist files: read when they change, kept when they fail, and enforced through reconcile
/// like blacklisted ranges without ever touching what must stay reachable.
/// </summary>
public sealed class BlocklistTests : IDisposable
{
    private static readonly DateTimeOffset T0 = new(2026, 5, 1, 12, 0, 0, TimeSpan.Zero);
    private static readonly DateTime Now = T0.UtcDateTime;

    private const string Range = "198.51.100.0/24";
    private const string Attacker = "203.0.113.50";

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "winguard-blocklist-" + Guid.NewGuid().ToString("N"));

    public BlocklistTests()
    {
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        Directory.Delete(_dir, recursive: true);
    }

    // ---------- the loader ----------

    [Fact]
    public void A_file_is_loaded_with_its_counts()
    {
        var path = Write("drop.txt", "1.2.3.0/24 ; SBL1\n# comment\nnonsense\n0.0.0.0/0\n1.2.3.4\n");
        var loader = new BlocklistLoader(100);

        var refresh = loader.Refresh([path], Now);

        var status = loader.Current;
        Assert.True(refresh.EntriesChanged);
        Assert.True(refresh.CountsChanged);
        Assert.Empty(refresh.Warnings);
        Assert.Equal(["1.2.3.0/24"], status.Entries);
        Assert.Equal(2, status.Skipped);
        Assert.Equal(0, status.Capped);
        var file = Assert.Single(status.Files);
        Assert.Equal(path, file.Path);
        Assert.Equal(2, file.Loaded);
        Assert.Equal(2, file.Skipped);
        Assert.Equal(Now, file.LastLoadedUtc);
        Assert.Null(file.Problem);
    }

    [Theory]
    [InlineData("utf-8")]
    [InlineData("utf-16")]
    public void A_byte_order_mark_is_understood(string encoding)
    {
        var path = Path.Combine(_dir, "bom.txt");
        File.WriteAllText(path, "1.2.3.0/24\n", Encoding.GetEncoding(encoding));
        var loader = new BlocklistLoader(100);

        loader.Refresh([path], Now);

        Assert.Equal(["1.2.3.0/24"], loader.Current.Entries);
        Assert.Equal(0, loader.Current.Skipped);
    }

    [Fact]
    public void Windows_line_endings_are_understood()
    {
        var path = Write("crlf.txt", "1.2.3.0/24\r\n5.6.7.0/24 ; x\r\n");
        var loader = new BlocklistLoader(100);

        loader.Refresh([path], Now);

        Assert.Equal(["1.2.3.0/24", "5.6.7.0/24"], loader.Current.Entries);
    }

    [Fact]
    public void An_unchanged_file_is_not_read_again()
    {
        var path = Write("drop.txt", "1.2.3.0/24\n");
        var loader = new BlocklistLoader(100);
        loader.Refresh([path], Now);

        // Same timestamp and size, other content: only a read could notice.
        var stamp = File.GetLastWriteTimeUtc(path);
        File.WriteAllText(path, "9.9.9.0/24\n");
        File.SetLastWriteTimeUtc(path, stamp);
        var refresh = loader.Refresh([path], Now.AddMinutes(1));

        Assert.False(refresh.EntriesChanged);
        Assert.False(refresh.CountsChanged);
        Assert.Equal(["1.2.3.0/24"], loader.Current.Entries);
        Assert.Equal(Now, Assert.Single(loader.Current.Files).LastLoadedUtc);
    }

    [Fact]
    public void A_new_timestamp_gets_the_file_read_again()
    {
        var path = Write("drop.txt", "1.2.3.0/24\n");
        var loader = new BlocklistLoader(100);
        loader.Refresh([path], Now);

        Rewrite(path, "9.9.9.0/24\n");
        var refresh = loader.Refresh([path], Now.AddMinutes(1));

        Assert.True(refresh.EntriesChanged);
        Assert.Equal(["9.9.9.0/24"], loader.Current.Entries);
    }

    [Fact]
    public void A_refresh_with_nothing_new_changes_nothing()
    {
        var path = Write("drop.txt", "1.2.3.0/24\n");
        var loader = new BlocklistLoader(100);
        loader.Refresh([path], Now);
        var entries = loader.Current.Entries;

        var refresh = loader.Refresh([path], Now.AddMinutes(1));

        Assert.False(refresh.EntriesChanged);
        Assert.Same(entries, loader.Current.Entries);
    }

    [Fact]
    public void A_missing_file_keeps_its_entries_and_warns_once()
    {
        var path = Write("drop.txt", "1.2.3.0/24\n");
        var loader = new BlocklistLoader(100);
        loader.Refresh([path], Now);

        File.Delete(path);
        var first = loader.Refresh([path], Now.AddMinutes(1));
        var second = loader.Refresh([path], Now.AddMinutes(2));

        Assert.Contains(path, Assert.Single(first.Warnings));
        Assert.Empty(second.Warnings);
        Assert.False(first.EntriesChanged);
        Assert.Equal(["1.2.3.0/24"], loader.Current.Entries);
        Assert.NotNull(Assert.Single(loader.Current.Files).Problem);
    }

    [Fact]
    public void A_file_that_comes_back_clears_its_problem()
    {
        var path = Write("drop.txt", "1.2.3.0/24\n");
        var loader = new BlocklistLoader(100);
        loader.Refresh([path], Now);
        File.Delete(path);
        loader.Refresh([path], Now.AddMinutes(1));

        Write("drop.txt", "9.9.9.0/24\n");
        loader.Refresh([path], Now.AddMinutes(2));

        Assert.Equal(["9.9.9.0/24"], loader.Current.Entries);
        Assert.Null(Assert.Single(loader.Current.Files).Problem);

        // A later loss is a new problem, so it gets its own warning.
        File.Delete(path);
        Assert.Single(loader.Refresh([path], Now.AddMinutes(3)).Warnings);
    }

    [Fact]
    public void A_file_that_cannot_be_opened_keeps_its_entries_and_is_tried_again()
    {
        var path = Write("drop.txt", "1.2.3.0/24\n");
        var loader = new BlocklistLoader(100);
        loader.Refresh([path], Now);
        Rewrite(path, "9.9.9.0/24\n");

        BlocklistRefresh locked;
        using (new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            locked = loader.Refresh([path], Now.AddMinutes(1));
            Assert.Empty(loader.Refresh([path], Now.AddMinutes(2)).Warnings);
        }

        Assert.Single(locked.Warnings);
        Assert.Equal(["1.2.3.0/24"], loader.Current.Entries);

        loader.Refresh([path], Now.AddMinutes(3));
        Assert.Equal(["9.9.9.0/24"], loader.Current.Entries);
    }

    [Theory]
    [InlineData("<html><body>503 Service Unavailable</body></html>\n")]
    [InlineData("")]
    [InlineData("# nothing here any more\n")]
    public void A_file_that_stops_being_a_list_keeps_the_last_good_entries(string content)
    {
        // What a failed download leaves behind must not unblock everything.
        var path = Write("drop.txt", "1.2.3.0/24\n");
        var loader = new BlocklistLoader(100);
        loader.Refresh([path], Now);

        Rewrite(path, content);
        var refresh = loader.Refresh([path], Now.AddMinutes(1));

        Assert.Single(refresh.Warnings);
        Assert.Equal(["1.2.3.0/24"], loader.Current.Entries);
    }

    [Fact]
    public void A_rejected_version_is_read_once_and_warned_about_once()
    {
        var path = Write("drop.txt", "1.2.3.0/24\n");
        var loader = new BlocklistLoader(100);
        loader.Refresh([path], Now);
        Rewrite(path, "garbage\n");
        loader.Refresh([path], Now.AddMinutes(1));

        var second = loader.Refresh([path], Now.AddMinutes(2));

        Assert.Empty(second.Warnings);
        Assert.Equal(1, loader.Current.Skipped);
    }

    [Fact]
    public void A_garbage_file_with_no_good_version_loads_nothing_and_says_why()
    {
        var path = Write("drop.txt", "garbage\n");
        var loader = new BlocklistLoader(100);

        var refresh = loader.Refresh([path], Now);

        Assert.Single(refresh.Warnings);
        Assert.Empty(loader.Current.Entries);
        Assert.Equal(1, loader.Current.Skipped);
        Assert.Null(Assert.Single(loader.Current.Files).LastLoadedUtc);
    }

    [Fact]
    public void A_comment_only_file_with_no_good_version_is_simply_empty()
    {
        var path = Write("drop.txt", "# to be filled\n");
        var loader = new BlocklistLoader(100);

        var refresh = loader.Refresh([path], Now);

        Assert.Empty(refresh.Warnings);
        Assert.Empty(loader.Current.Entries);
        Assert.Null(Assert.Single(loader.Current.Files).Problem);
    }

    [Fact]
    public void A_partly_valid_new_version_replaces_the_old_one_and_counts_what_it_skipped()
    {
        var path = Write("drop.txt", "1.2.3.0/24\n");
        var loader = new BlocklistLoader(100);
        loader.Refresh([path], Now);

        Rewrite(path, "9.9.9.0/24\nbroken\n");
        loader.Refresh([path], Now.AddMinutes(1));

        Assert.Equal(["9.9.9.0/24"], loader.Current.Entries);
        Assert.Equal(1, loader.Current.Skipped);
    }

    /// <summary>A list of that many entries, none of which merge.</summary>
    private static string ListOf(int entries) =>
        string.Concat(Enumerable.Range(0, entries).Select(i => $"20.{i / 200}.{i % 200}.0/25\n"));

    [Fact]
    public void A_list_cut_to_under_half_keeps_the_last_good_entries_and_warns_once()
    {
        // An interrupted download: what is there parses, and the rest must not get unblocked.
        var path = Write("drop.txt", ListOf(200));
        var loader = new BlocklistLoader(1000);
        loader.Refresh([path], Now);

        Rewrite(path, ListOf(50));
        var refresh = loader.Refresh([path], Now.AddMinutes(1));
        var second = loader.Refresh([path], Now.AddMinutes(2));

        Assert.Contains("cut off", Assert.Single(refresh.Warnings));
        Assert.Empty(second.Warnings);
        Assert.Equal(200, loader.Current.Entries.Count);
        Assert.Contains("cut off", Assert.Single(loader.Current.Files).Problem);
    }

    [Fact]
    public void A_list_that_loses_less_than_half_replaces_the_old_one()
    {
        var path = Write("drop.txt", ListOf(200));
        var loader = new BlocklistLoader(1000);
        loader.Refresh([path], Now);

        Rewrite(path, ListOf(100));
        var refresh = loader.Refresh([path], Now.AddMinutes(1));

        Assert.Empty(refresh.Warnings);
        Assert.Equal(100, loader.Current.Entries.Count);
    }

    [Fact]
    public void A_short_list_may_shrink_as_it_likes()
    {
        var path = Write("drop.txt", ListOf(99));
        var loader = new BlocklistLoader(1000);
        loader.Refresh([path], Now);

        Rewrite(path, ListOf(1));
        var refresh = loader.Refresh([path], Now.AddMinutes(1));

        Assert.Empty(refresh.Warnings);
        Assert.Single(loader.Current.Entries);
    }

    [Fact]
    public void Taking_a_list_off_and_adding_it_back_accepts_a_short_version()
    {
        var path = Write("drop.txt", ListOf(200));
        var loader = new BlocklistLoader(1000);
        loader.Refresh([path], Now);
        Rewrite(path, ListOf(50));
        loader.Refresh([path], Now.AddMinutes(1));

        loader.Refresh([], Now.AddMinutes(2));
        var refresh = loader.Refresh([path], Now.AddMinutes(3));

        Assert.Empty(refresh.Warnings);
        Assert.Equal(50, loader.Current.Entries.Count);
    }

    [Fact]
    public void A_file_too_large_to_be_a_list_is_refused_before_it_is_read()
    {
        var path = Write("huge.txt", string.Empty);
        using (var stream = new FileStream(path, FileMode.Open, FileAccess.Write))
        {
            stream.SetLength((64L * 1024 * 1024) + 1);
        }

        var loader = new BlocklistLoader(100);
        var refresh = loader.Refresh([path], Now);

        Assert.Contains("larger", Assert.Single(refresh.Warnings));
        Assert.Empty(loader.Current.Entries);
    }

    [Theory]
    [InlineData(@"\\server\share\drop.txt")]
    [InlineData(@"\\?\C:\drop.txt")]
    [InlineData("//server/share/drop.txt")]
    public void A_network_or_device_path_is_never_opened(string path)
    {
        var loader = new BlocklistLoader(100);

        var refresh = loader.Refresh([path], Now);

        Assert.Single(refresh.Warnings);
        Assert.Contains("UNC", Assert.Single(loader.Current.Files).Problem);
    }

    [Fact]
    public void A_path_reaching_the_network_through_a_variable_is_refused_too()
    {
        Environment.SetEnvironmentVariable("WINGUARD_TEST_LISTS", @"\\server\share");
        try
        {
            var loader = new BlocklistLoader(100);

            loader.Refresh([@"%WINGUARD_TEST_LISTS%\drop.txt"], Now);

            Assert.Contains("UNC", Assert.Single(loader.Current.Files).Problem);
        }
        finally
        {
            Environment.SetEnvironmentVariable("WINGUARD_TEST_LISTS", null);
        }
    }

    [Fact]
    public void A_folder_is_not_a_file()
    {
        var loader = new BlocklistLoader(100);

        loader.Refresh([_dir], Now);

        Assert.NotNull(Assert.Single(loader.Current.Files).Problem);
    }

    [Fact]
    public void Environment_variables_in_a_path_are_expanded()
    {
        var path = Write("drop.txt", "1.2.3.0/24\n");
        Environment.SetEnvironmentVariable("WINGUARD_TEST_LISTS", _dir);
        try
        {
            var loader = new BlocklistLoader(100);

            loader.Refresh([@"%WINGUARD_TEST_LISTS%\drop.txt"], Now);

            Assert.Equal(["1.2.3.0/24"], loader.Current.Entries);
        }
        finally
        {
            Environment.SetEnvironmentVariable("WINGUARD_TEST_LISTS", null);
        }
    }

    [Fact]
    public void Files_merge_and_one_failing_does_not_affect_the_others()
    {
        var first = Write("a.txt", "1.2.2.0/24\n");
        var second = Write("b.txt", "1.2.3.0/24\n");
        var loader = new BlocklistLoader(100);
        loader.Refresh([first, second], Now);
        Assert.Equal(["1.2.2.0/23"], loader.Current.Entries);

        File.Delete(second);
        Rewrite(first, "9.9.9.0/24\n");
        loader.Refresh([first, second], Now.AddMinutes(1));

        Assert.Equal(["1.2.3.0/24", "9.9.9.0/24"], loader.Current.Entries);
    }

    [Fact]
    public void A_file_taken_off_the_settings_is_dropped_even_if_it_was_failing()
    {
        var first = Write("a.txt", "1.2.2.0/24\n");
        var second = Write("b.txt", "9.9.9.0/24\n");
        var loader = new BlocklistLoader(100);
        loader.Refresh([first, second], Now);
        File.Delete(second);
        loader.Refresh([first, second], Now.AddMinutes(1));

        var refresh = loader.Refresh([first], Now.AddMinutes(2));

        Assert.True(refresh.EntriesChanged);
        Assert.Equal(["1.2.2.0/24"], loader.Current.Entries);
        Assert.Single(loader.Current.Files);
    }

    [Fact]
    public void The_cap_applies_across_files_and_is_reported()
    {
        var first = Write("a.txt", "1.1.1.1\n2.2.2.2\n");
        var second = Write("b.txt", "3.3.3.3\n4.4.4.4\n");
        var loader = new BlocklistLoader(3);

        loader.Refresh([first, second], Now);

        Assert.Equal(3, loader.Current.Entries.Count);
        Assert.Equal(1, loader.Current.Capped);
    }

    [Fact]
    public void A_list_over_the_real_cap_is_cut_to_it()
    {
        var text = new StringBuilder();
        for (var i = 0; i < Defaults.MaxBlocklistEntries + 500; i++)
        {
            text.Append("20.").Append(i >> 15).Append('.').Append((i >> 7) & 0xFF).Append('.').Append((i & 0x7F) * 2).Append('\n');
        }

        var path = Write("big.txt", text.ToString());
        var loader = new BlocklistLoader(Defaults.MaxBlocklistEntries);

        loader.Refresh([path], Now);

        Assert.Equal(Defaults.MaxBlocklistEntries, loader.Current.Entries.Count);
        Assert.Equal(500, loader.Current.Capped);
    }

    [Fact]
    public void Removing_a_list_makes_room_under_the_cap_again()
    {
        var first = Write("a.txt", "1.1.1.1\n2.2.2.2\n");
        var second = Write("b.txt", "3.3.3.3\n");
        var loader = new BlocklistLoader(2);
        loader.Refresh([first, second], Now);

        loader.Refresh([first], Now.AddMinutes(1));

        Assert.Equal(0, loader.Current.Capped);
        Assert.Equal(2, loader.Current.Entries.Count);
    }

    [Fact]
    public void Saved_entries_stand_in_for_a_file_that_cannot_be_read()
    {
        var path = Path.Combine(_dir, "gone.txt");
        var loader = new BlocklistLoader(100);
        loader.Seed(new Dictionary<string, string[]> { [path] = ["1.2.3.0/24"] });

        var refresh = loader.Refresh([path], Now);

        Assert.True(refresh.EntriesChanged);
        Assert.Equal(["1.2.3.0/24"], loader.Current.Entries);
        Assert.NotNull(Assert.Single(loader.Current.Files).Problem);
    }

    [Fact]
    public void A_readable_file_replaces_saved_entries()
    {
        var path = Write("drop.txt", "9.9.9.0/24\n");
        var loader = new BlocklistLoader(100);
        loader.Seed(new Dictionary<string, string[]> { [path] = ["1.2.3.0/24"] });

        loader.Refresh([path], Now);

        Assert.Equal(["9.9.9.0/24"], loader.Current.Entries);
    }

    [Fact]
    public void Saved_entries_are_checked_like_a_lists_own()
    {
        var path = Path.Combine(_dir, "gone.txt");
        var loader = new BlocklistLoader(100);
        loader.Seed(new Dictionary<string, string[]> { [path] = ["0.0.0.0/0", "LocalSubnet", "1.2.3.0/24"] });

        loader.Refresh([path], Now);

        Assert.Equal(["1.2.3.0/24"], loader.Current.Entries);
    }

    [Fact]
    public void Saved_entries_of_a_file_no_longer_configured_are_ignored()
    {
        var loader = new BlocklistLoader(100);
        loader.Seed(new Dictionary<string, string[]> { [@"C:\old\drop.txt"] = ["1.2.3.0/24"] });

        loader.Refresh([], Now);

        Assert.Empty(loader.Current.Entries);
        Assert.Empty(loader.Current.Files);
    }

    // ---------- the engine ----------

    [Fact]
    public async Task Off_by_default_nothing_is_read_or_reported()
    {
        await using var h = await EngineHarness.StartAsync(T0);

        await h.Engine.HousekeepOnceAsync();

        Assert.Empty(h.Engine.GetBlocklistStatus().Files);
        Assert.DoesNotContain(h.Store.Events, e => e.Message.Contains("BLOCKLIST", StringComparison.Ordinal));
        Assert.DoesNotContain("blocklist_last_good", h.Store.SettingValues.Keys);
    }

    [Fact]
    public async Task Entries_are_enforced_from_the_start_up_sync_on_all_ports()
    {
        var path = Write("drop.txt", $"{Range}\n192.0.2.7\n");

        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            s.BlocklistFiles = [path];
            s.BlockedPorts = ["22"];
            s.Rdp.BlockedPorts = ["3389"];
        });

        var sync = Assert.Single(h.Firewall.SyncRulesCalls);
        Assert.Contains(Range, sync);
        Assert.Contains("192.0.2.7", sync);
        Assert.Equal(PortSet.All, h.Firewall.PortsOf(Range));
        Assert.Equal(PortSet.All, h.Firewall.PortsOf("192.0.2.7"));
        Assert.Empty(h.Firewall.BlockCalls);
    }

    [Fact]
    public async Task A_whitelisted_address_is_cut_out_of_a_range()
    {
        var path = Write("drop.txt", "198.51.100.0/30\n");

        await using var h = await EngineHarness.StartAsync(
            T0,
            s => s.BlocklistFiles = [path],
            seed: store => store.AddToListAsync(ListKind.Whitelist, "198.51.100.1"));

        Assert.DoesNotContain("198.51.100.0/30", h.Firewall.Blocked);
        Assert.DoesNotContain("198.51.100.1", h.Firewall.Blocked);
        Assert.Contains("198.51.100.0", h.Firewall.Blocked);
        Assert.Contains("198.51.100.2/31", h.Firewall.Blocked);
    }

    [Fact]
    public async Task A_whitelisted_range_covering_an_entry_removes_it()
    {
        var path = Write("drop.txt", $"{Range}\n192.0.2.7\n");

        await using var h = await EngineHarness.StartAsync(
            T0,
            s => s.BlocklistFiles = [path],
            seed: store => store.AddToListAsync(ListKind.Whitelist, "198.51.0.0/16"));

        Assert.Equal(["192.0.2.7"], h.Firewall.Blocked);
    }

    [Fact]
    public async Task An_address_whitelisted_later_is_released_by_the_next_pass()
    {
        var path = Write("drop.txt", "198.51.100.0/30\n");
        await using var h = await EngineHarness.StartAsync(T0, s => s.BlocklistFiles = [path]);
        Assert.Contains("198.51.100.0/30", h.Firewall.Blocked);

        await h.Store.AddToListAsync(ListKind.Whitelist, "198.51.100.1");
        await h.Engine.HousekeepOnceAsync();

        Assert.DoesNotContain("198.51.100.0/30", h.Firewall.Blocked);
        Assert.DoesNotContain("198.51.100.1", h.Firewall.Blocked);
    }

    [Fact]
    public async Task Taking_an_address_off_the_whitelist_brings_the_whole_range_back()
    {
        var path = Write("drop.txt", "198.51.100.0/30\n");
        await using var h = await EngineHarness.StartAsync(
            T0,
            s => s.BlocklistFiles = [path],
            seed: store => store.AddToListAsync(ListKind.Whitelist, "198.51.100.1"));

        await h.Store.RemoveFromListAsync(ListKind.Whitelist, "198.51.100.1");
        await h.Engine.HousekeepOnceAsync();

        Assert.Equal(["198.51.100.0/30"], h.Firewall.Blocked);
    }

    [Fact]
    public async Task The_servers_own_addresses_are_never_blocked()
    {
        // Loopback is the one own address every machine has; internal processing keeps it from
        // being excluded for being internal, so this exercises the whitelist alone.
        var path = Write("drop.txt", "127.0.0.0/30\n");

        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            s.BlocklistFiles = [path];
            s.ProcessInternalIPs = true;
        });

        Assert.Equal(["127.0.0.0", "127.0.0.2/31"], h.Firewall.Blocked.Order());
    }

    [Theory]
    [InlineData("10.0.0.0/8")]
    [InlineData("192.168.0.0/16")]
    [InlineData("172.16.0.0/12")]
    [InlineData("127.0.0.0/8")]
    [InlineData("169.254.0.0/16")]
    [InlineData("100.64.0.0/10")]
    [InlineData("fc00::/32")]
    [InlineData("fe80::/32")]
    public void Published_bogon_entries_are_internal_ranges(string range)
    {
        var internalRanges = new IpMatcher(IpMatcher.InternalRanges, []);

        Assert.Empty(internalRanges.SubtractWhitelist(range));
    }

    [Fact]
    public async Task A_bogon_list_cannot_lock_the_lan_out()
    {
        var path = Write("level1.txt", "10.0.0.0/8\n192.168.0.0/16\n172.0.0.0/8\n" + Range + "\n");

        await using var h = await EngineHarness.StartAsync(T0, s => s.BlocklistFiles = [path]);

        Assert.Contains(Range, h.Firewall.Blocked);
        Assert.DoesNotContain("10.0.0.0/8", h.Firewall.Blocked);
        Assert.DoesNotContain("192.168.0.0/16", h.Firewall.Blocked);
        Assert.DoesNotContain("172.0.0.0/8", h.Firewall.Blocked);
        Assert.Contains("172.0.0.0/12", h.Firewall.Blocked); // the rest of 172/8 is public
        var matcher = new IpMatcher(h.Firewall.Blocked, []);
        Assert.False(matcher.IsWhitelisted("172.16.0.1"));
        Assert.True(matcher.IsWhitelisted("172.32.0.1"));
    }

    [Fact]
    public async Task With_internal_addresses_processed_a_list_may_hold_them()
    {
        var path = Write("drop.txt", "10.20.30.0/24\n");

        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            s.BlocklistFiles = [path];
            s.ProcessInternalIPs = true;
        });

        Assert.Contains("10.20.30.0/24", h.Firewall.Blocked);
    }

    [Fact]
    public void The_internal_ranges_match_what_is_called_internal()
    {
        foreach (var range in IpMatcher.InternalRanges)
        {
            Assert.True(IpMatcher.TryParseCidr(range, out var network), range);
            Assert.True(IpMatcher.IsInternal(network.BaseAddress.ToString()), range);
        }
    }

    [Fact]
    public async Task A_changed_file_reaches_the_firewall_on_the_next_pass()
    {
        var path = Write("drop.txt", $"{Range}\n");
        await using var h = await EngineHarness.StartAsync(T0, s => s.BlocklistFiles = [path]);

        Rewrite(path, "192.0.2.0/24\n");
        await h.Engine.HousekeepOnceAsync();

        Assert.Equal(["192.0.2.0/24"], h.Firewall.Blocked);
    }

    [Fact]
    public async Task A_list_added_while_running_is_enforced()
    {
        var path = Write("drop.txt", $"{Range}\n");
        await using var h = await EngineHarness.StartAsync(T0);

        h.Settings.BlocklistFiles = [path];
        await h.Engine.HousekeepOnceAsync();

        Assert.Equal([Range], h.Firewall.Blocked);
    }

    [Fact]
    public async Task A_list_taken_off_the_settings_is_lifted()
    {
        var path = Write("drop.txt", $"{Range}\n");
        await using var h = await EngineHarness.StartAsync(T0, s => s.BlocklistFiles = [path]);

        h.Settings.BlocklistFiles = [];
        await h.Engine.HousekeepOnceAsync();

        Assert.Empty(h.Firewall.Blocked);
        Assert.Empty(h.Engine.GetBlocklistStatus().Entries);
    }

    [Fact]
    public async Task A_missing_file_does_not_unblock_anything_and_warns_once()
    {
        var path = Write("drop.txt", $"{Range}\n");
        await using var h = await EngineHarness.StartAsync(T0, s => s.BlocklistFiles = [path]);

        File.Delete(path);
        await h.Engine.HousekeepOnceAsync();
        await h.Engine.HousekeepOnceAsync();
        await h.Engine.HousekeepOnceAsync();

        Assert.Contains(Range, h.Firewall.Blocked);
        var warning = Assert.Single(h.Store.Events, e => e.Message.Contains("last good", StringComparison.Ordinal));
        Assert.Equal(LogEventLevel.Warning, warning.Level);
        Assert.Contains(path, warning.Message);
    }

    [Fact]
    public async Task A_file_missing_at_a_restart_keeps_its_rules()
    {
        // Rules survive a reboot; a data drive that comes up after the service must not remove them.
        var path = Write("drop.txt", $"{Range}\n192.0.2.7\n");
        var store = new FakeStore();
        await using (await EngineHarness.StartAsync(T0, s => s.BlocklistFiles = [path], store: store))
        {
        }

        File.Delete(path);
        await using var restarted = await EngineHarness.StartAsync(T0, s => s.BlocklistFiles = [path], store: store);

        var sync = Assert.Single(restarted.Firewall.SyncRulesCalls);
        Assert.Contains(Range, sync);
        Assert.Contains("192.0.2.7", sync);
        Assert.NotNull(Assert.Single(restarted.Engine.GetBlocklistStatus().Files).Problem);
    }

    [Fact]
    public async Task A_failed_save_of_the_entries_is_tried_again_on_the_next_pass()
    {
        var path = Write("drop.txt", $"{Range}\n");
        var store = new FakeStore { FailSettingWrites = true };
        await using var h = await EngineHarness.StartAsync(T0, s => s.BlocklistFiles = [path], store: store);
        Assert.DoesNotContain("blocklist_last_good", store.SettingValues.Keys);

        store.FailSettingWrites = false;
        await h.Engine.HousekeepOnceAsync();

        Assert.Contains(Range, store.SettingValues["blocklist_last_good"]);
    }

    [Fact]
    public async Task At_a_restart_a_readable_file_beats_what_was_saved()
    {
        var path = Write("drop.txt", $"{Range}\n");
        var store = new FakeStore();
        await using (await EngineHarness.StartAsync(T0, s => s.BlocklistFiles = [path], store: store))
        {
        }

        Rewrite(path, "192.0.2.0/24\n");
        await using var restarted = await EngineHarness.StartAsync(T0, s => s.BlocklistFiles = [path], store: store);

        Assert.Equal(["192.0.2.0/24"], restarted.Firewall.Blocked);
    }

    [Fact]
    public async Task An_unreadable_saved_copy_costs_the_copy_not_the_service()
    {
        var path = Write("drop.txt", $"{Range}\n");
        var store = new FakeStore();
        await store.SetSettingAsync("blocklist_last_good", "{ not json");

        await using var h = await EngineHarness.StartAsync(T0, s => s.BlocklistFiles = [path], store: store);

        Assert.Equal([Range], h.Firewall.Blocked);
    }

    [Fact]
    public async Task Loading_reports_counts_and_writes_one_event_per_change()
    {
        var path = Write("drop.txt", $"{Range}\nnonsense\n");
        await using var h = await EngineHarness.StartAsync(T0, s => s.BlocklistFiles = [path]);

        await h.Engine.HousekeepOnceAsync();

        var status = h.Engine.GetBlocklistStatus();
        Assert.Single(status.Entries);
        Assert.Equal(1, status.Skipped);
        Assert.Equal(0, status.Capped);
        var update = Assert.Single(h.Store.Events, e => e.Message.StartsWith("BLOCKLIST updated", StringComparison.Ordinal));
        Assert.Contains("1 loaded, 1 skipped, 0 capped", update.Message);

        Rewrite(path, $"{Range}\n192.0.2.7\nnonsense\n");
        await h.Engine.HousekeepOnceAsync();

        Assert.Equal(2, h.Store.Events.Count(e => e.Message.StartsWith("BLOCKLIST updated", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task Report_only_loads_and_reports_but_changes_no_rule()
    {
        var path = Write("drop.txt", $"{Range}\n");
        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            s.BlocklistFiles = [path];
            s.ReportOnly = true;
        });

        await h.Engine.HousekeepOnceAsync();

        Assert.Empty(h.Firewall.SyncRulesCalls);
        Assert.Empty(h.Firewall.BlockCalls);
        Assert.Single(h.Engine.GetBlocklistStatus().Entries);
        Assert.Contains(h.Store.Events, e => e.Message.StartsWith("BLOCKLIST updated", StringComparison.Ordinal) && e.Message.Contains("report-only", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Switching_report_only_off_enforces_the_list()
    {
        var path = Write("drop.txt", $"{Range}\n");
        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            s.BlocklistFiles = [path];
            s.ReportOnly = true;
        });

        h.Settings.ReportOnly = false;
        await h.Engine.HousekeepOnceAsync();

        Assert.Contains(Range, h.Firewall.Blocked);
    }

    [Fact]
    public async Task Reconcile_restores_an_entry_removed_from_the_firewall()
    {
        var path = Write("drop.txt", $"{Range}\n");
        await using var h = await EngineHarness.StartAsync(T0, s => s.BlocklistFiles = [path]);

        h.Firewall.Unblock(Range);
        await h.Engine.HousekeepOnceAsync();

        Assert.Contains(Range, h.Firewall.Blocked);
    }

    [Fact]
    public async Task An_unchanged_list_writes_nothing_on_later_passes()
    {
        var path = Write("drop.txt", $"{Range}\n");
        await using var h = await EngineHarness.StartAsync(T0, s => s.BlocklistFiles = [path]);
        var saved = h.Store.SettingValues["blocklist_last_good"];

        await h.Engine.HousekeepOnceAsync();
        await h.Engine.HousekeepOnceAsync();

        Assert.Single(h.Firewall.SyncRulesCalls);
        Assert.Equal(saved, h.Store.SettingValues["blocklist_last_good"]);
    }

    [Fact]
    public async Task Clearing_bans_on_start_up_leaves_the_blocklist_enforced()
    {
        var path = Write("drop.txt", $"{Range}\n");

        await using var h = await EngineHarness.StartAsync(
            T0,
            s =>
            {
                s.BlocklistFiles = [path];
                s.ClearBansOnStartup = true;
            },
            seed: store => store.UpsertBanAsync(BanOf(Attacker)));

        Assert.Equal([Range], h.Firewall.Blocked);
    }

    [Fact]
    public async Task Bans_and_list_entries_live_side_by_side()
    {
        var path = Write("drop.txt", $"{Range}\n");
        await using var h = await EngineHarness.StartAsync(T0, s => s.BlocklistFiles = [path]);

        await h.Engine.BanNowAsync(Attacker, TimeSpan.FromHours(1), permanent: false, note: null);
        await h.Engine.HousekeepOnceAsync();

        Assert.Contains(Attacker, h.Firewall.Blocked);
        Assert.Contains(Range, h.Firewall.Blocked);
    }

    [Fact]
    public async Task A_ban_ending_on_a_listed_address_leaves_it_blocked()
    {
        var path = Write("drop.txt", $"{Attacker}\n");
        await using var h = await EngineHarness.StartAsync(T0, s => s.BlocklistFiles = [path]);
        await h.Engine.BanNowAsync(Attacker, TimeSpan.FromHours(1), permanent: false, note: null);

        h.Time.Advance(TimeSpan.FromHours(2));
        await h.Engine.HousekeepOnceAsync();

        Assert.Null(await h.Store.GetBanAsync(Attacker));
        Assert.Empty(h.Firewall.UnblockCalls);
        Assert.Contains(Attacker, h.Firewall.Blocked);
    }

    [Fact]
    public async Task A_manual_unban_of_a_listed_address_leaves_it_blocked()
    {
        var path = Write("drop.txt", $"{Attacker}\n");
        await using var h = await EngineHarness.StartAsync(T0, s => s.BlocklistFiles = [path]);
        await h.Engine.BanNowAsync(Attacker, null, permanent: true, note: null);

        await h.Engine.UnbanAsync(Attacker);
        await h.Engine.HousekeepOnceAsync();

        Assert.Contains(Attacker, h.Firewall.Blocked);
    }

    [Fact]
    public async Task A_narrow_ban_on_a_listed_address_does_not_narrow_the_list()
    {
        var path = Write("drop.txt", $"{Attacker}\n");
        await using var h = await EngineHarness.StartAsync(T0, s =>
        {
            s.BlocklistFiles = [path];
            s.Rdp.BlockedPorts = ["3389"];
        });

        for (var i = 0; i < h.Settings.FailedLoginThreshold; i++)
        {
            await h.ProcessAsync(h.Fail(Attacker, ProtocolSource.Rdp, detector: "4625"));
        }

        Assert.Equal(PortSet.All, h.Firewall.PortsOf(Attacker));
        await h.Engine.HousekeepOnceAsync();
        Assert.Equal(PortSet.All, h.Firewall.PortsOf(Attacker));
    }

    [Fact]
    public async Task An_address_inside_a_list_is_still_counted_like_any_other()
    {
        // Membership blocks at the firewall; it is not the blacklist's permanent ban at first contact.
        var path = Write("drop.txt", "203.0.113.0/24\n");
        await using var h = await EngineHarness.StartAsync(T0, s => s.BlocklistFiles = [path]);

        await h.ProcessAsync(h.Fail(Attacker, ProtocolSource.MsSql));

        Assert.Null(await h.Store.GetBanAsync(Attacker));
    }

    [Fact]
    public async Task A_list_spanning_rules_changes_only_the_rule_that_changed()
    {
        var rules = new WindowsFirewallBatchingTests.FakeRuleStore();
        var path = Write("drop.txt", string.Join('\n', Enumerable.Range(0, 2500).Select(i => $"20.1.{i / 128}.{(i % 128) * 2}")));
        var settings = new WinGuardSettings { BlocklistFiles = [path], HousekeepingInterval = TimeSpan.FromHours(6) };
        var firewall = new WindowsFirewall(NullLogger<WindowsFirewall>.Instance, rules, 1000);
        var engine = new BanEngine(new FakeStore(), firewall, () => settings, NullLogger<BanEngine>.Instance, new FakeTimeProvider(T0));

        await engine.StartAsync(CancellationToken.None);
        try
        {
            Assert.Equal(new[] { "WinGuard_Block_0001", "WinGuard_Block_0002", "WinGuard_Block_0003" }, rules.Rules.Keys.Order());
            Assert.Equal(2500, firewall.ListBlocked()!.Count);
            var writes = rules.UpsertCount;

            await engine.BanNowAsync(Attacker, TimeSpan.FromHours(1), permanent: false, note: null);
            await engine.HousekeepOnceAsync();

            Assert.Equal(writes + 1, rules.UpsertCount);
        }
        finally
        {
            await engine.StopAsync(CancellationToken.None);
        }
    }

    // ---------- helpers ----------

    private static BanEntry BanOf(string ip) => new()
    {
        IpAddress = ip,
        Source = ProtocolSource.MsSql,
        BannedAtUtc = T0.UtcDateTime,
        ExpiresUtc = T0.UtcDateTime.AddDays(1),
    };

    private string Write(string name, string content)
    {
        var path = Path.Combine(_dir, name);
        File.WriteAllText(path, content);
        return path;
    }

    /// <summary>Replaces a file so that its timestamp visibly moves on, however fast the test runs.</summary>
    private static void Rewrite(string path, string content)
    {
        var before = File.GetLastWriteTimeUtc(path);
        File.WriteAllText(path, content);
        File.SetLastWriteTimeUtc(path, before.AddSeconds(5));
    }
}
