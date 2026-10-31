using System.Text.Json;
using Microsoft.Extensions.Logging;
using WinGuard.Core.Config;
using WinGuard.Core.Model;

namespace WinGuard.Core.Engine;

/// <summary>
/// Local blocklist files: ranges known to be bad, blocked on all ports without a failed login first.
/// They reach the firewall the way blacklisted ranges do, through the expected state of reconcile;
/// reading them happens outside the gate, in <see cref="RefreshBlocklistsAsync"/>.
/// </summary>
public sealed partial class BanEngine
{
    // The last good entries of each file, so a file missing at start-up keeps its rules.
    private const string BlocklistCacheSettingKey = "blocklist_last_good";

    private readonly BlocklistLoader _blocklists = new(Defaults.MaxBlocklistEntries);
    private bool _blocklistCacheLoaded;

    // The entries minus what must stay reachable, recomputed only when either side changes.
    private HashSet<string> _blocklistTargets = new(StringComparer.Ordinal);
    private IReadOnlyList<string> _appliedBlocklistEntries = [];
    private string _appliedBlocklistExclusions = string.Empty;

    /// <summary>What the blocklist files contribute right now. Needs no gate.</summary>
    public BlocklistSnapshot GetBlocklistStatus() => _blocklists.Current;

    /// <summary>
    /// Re-reads the blocklist files that changed. Runs outside the gate: the loader does file I/O
    /// and a list can be large. The result is picked up by the next list reload.
    /// </summary>
    private async Task RefreshBlocklistsAsync(CancellationToken ct)
    {
        var paths = _settingsAccessor().BlocklistFiles;
        if (paths.Length == 0 && _blocklists.Current.Files.Count == 0)
        {
            return;
        }

        try
        {
            await LoadBlocklistCacheAsync(ct).ConfigureAwait(false);
            var refresh = _blocklists.Refresh(paths, NowUtc());
            foreach (var warning in refresh.Warnings)
            {
                _logger.LogWarning("Blocklist file problem; its last good entries stay in force: {Problem}", warning);
                await TryAddEventAsync(new LogEvent
                {
                    TimestampUtc = NowUtc(),
                    Level = LogEventLevel.Warning,
                    Message = $"BLOCKLIST problem, last good entries stay in force: {warning}",
                }, ct).ConfigureAwait(false);
            }

            if (refresh.EntriesChanged)
            {
                await SaveBlocklistCacheAsync(ct).ConfigureAwait(false);
            }

            if (refresh.CountsChanged)
            {
                var status = _blocklists.Current;
                await TryAddEventAsync(
                    null,
                    null,
                    $"BLOCKLIST updated: {status.Entries.Count} loaded, {status.Skipped} skipped, {status.Capped} capped.{ReportSuffix()}",
                    ct).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _logger.LogError(ex, "BanEngine failed to refresh the blocklist files.");
        }
    }

    /// <summary>Restores the last good entries once, before the first read of the files.</summary>
    private async Task LoadBlocklistCacheAsync(CancellationToken ct)
    {
        if (_blocklistCacheLoaded)
        {
            return;
        }

        try
        {
            var all = await _store.GetAllSettingsAsync(ct).ConfigureAwait(false);
            if (all.TryGetValue(BlocklistCacheSettingKey, out var json))
            {
                var lastGood = JsonSerializer.Deserialize<Dictionary<string, string[]>>(json);
                _blocklists.Seed(lastGood ?? []);
            }

            _blocklistCacheLoaded = true;
        }
        catch (JsonException ex)
        {
            _blocklistCacheLoaded = true;
            _logger.LogWarning(ex, "Discarding the saved blocklist entries: they cannot be read.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _logger.LogWarning(ex, "Could not read the saved blocklist entries; trying again next pass.");
        }
    }

    private async Task SaveBlocklistCacheAsync(CancellationToken ct)
    {
        try
        {
            await _store.SetSettingAsync(BlocklistCacheSettingKey, JsonSerializer.Serialize(_blocklists.ExportLastGood()), ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _logger.LogWarning(ex, "Could not save the blocklist entries; a file missing at the next start would lose its rules.");
        }
    }

    /// <summary>
    /// Works out what the firewall gets from the blocklists. A block rule beats every allow rule, so
    /// each entry is cut around the whitelist, which holds this server's own addresses. Internal
    /// addresses go too unless they are being processed: published bogon lists hold 10.0.0.0/8, and
    /// that must not lock the LAN out of a server it manages. Call under the gate.
    /// </summary>
    private void ApplyBlocklist(IReadOnlyList<string> whitelist)
    {
        var entries = _blocklists.Current.Entries;
        var processInternal = _settingsAccessor().ProcessInternalIPs;
        var exclusions = processInternal + "\n" + string.Join('\n', whitelist);
        if (ReferenceEquals(entries, _appliedBlocklistEntries) && exclusions == _appliedBlocklistExclusions)
        {
            return;
        }

        var keepReachable = processInternal ? _matcher : new IpMatcher(whitelist.Concat(IpMatcher.InternalRanges), []);
        _blocklistTargets = entries.SelectMany(keepReachable.SubtractWhitelist).ToHashSet(StringComparer.Ordinal);
        _appliedBlocklistEntries = entries;
        _appliedBlocklistExclusions = exclusions;
    }
}
