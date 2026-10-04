using System.Globalization;
using System.IO;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using WinGuard.Core.Engine;
using WinGuard.Core.Ipc;
using WinGuard.Gui.Collections;
using WinGuard.Gui.Services;

namespace WinGuard.Gui.ViewModels;

/// <summary>
/// Blocked IPs view-model (PLAN.md §9.2): a filterable grid of active bans with manual block,
/// Unblock, Unblock &amp; Whitelist, Promote-to-permanent actions and CSV export.
/// </summary>
public sealed partial class BlockedIpsViewModel : ObservableObject
{
    private const string DefaultDuration = "Default tier";
    private const string PermanentDuration = "Permanent";

    private static readonly (string Label, TimeSpan? Duration)[] Durations =
    [
        (DefaultDuration, null),
        ("1 hour", TimeSpan.FromHours(1)),
        ("24 hours", TimeSpan.FromHours(24)),
        ("7 days", TimeSpan.FromDays(7)),
        ("30 days", TimeSpan.FromDays(30)),
        (PermanentDuration, null),
    ];

    private readonly PipeClient _client;
    private List<BanDto> _all = [];

    /// <summary>Creates the view-model.</summary>
    /// <param name="client">Pipe client used to block / unblock IPs.</param>
    public BlockedIpsViewModel(PipeClient client) => _client = client;

    /// <summary>Filtered rows shown in the grid.</summary>
    public BulkObservableCollection<BanRowViewModel> Bans { get; } = new();

    /// <summary>Choices for the manual-block duration.</summary>
    public string[] DurationOptions { get; } = Durations.Select(d => d.Label).ToArray();

    /// <summary>Current selection.</summary>
    [ObservableProperty]
    private BanRowViewModel? _selectedBan;

    /// <summary>Case-insensitive substring filter (IP, source or note).</summary>
    [ObservableProperty]
    private string _filterText = string.Empty;

    /// <summary>Result of the last action (kept until the next action).</summary>
    [ObservableProperty]
    private string _statusMessage = string.Empty;

    /// <summary>How many bans are shown.</summary>
    [ObservableProperty]
    private string _countText = "No blocked IPs.";

    /// <summary>IP typed into the manual-block box.</summary>
    [ObservableProperty]
    private string _newIp = string.Empty;

    /// <summary>Optional note for the manual block.</summary>
    [ObservableProperty]
    private string _newNote = string.Empty;

    /// <summary>Selected manual-block duration.</summary>
    [ObservableProperty]
    private string _selectedDuration = DefaultDuration;

    /// <summary>Replaces the ban list and reapplies the current filter.</summary>
    /// <param name="bans">Fresh ban DTOs.</param>
    public void UpdateBans(IReadOnlyList<BanDto> bans)
    {
        _all = bans.ToList();
        Rebuild();
    }

    partial void OnFilterTextChanged(string value) => Rebuild();

    /// <summary>Blocks the IP typed into the manual-block box.</summary>
    [RelayCommand]
    private async Task BlockNowAsync()
    {
        if (!IpMatcher.TryNormalize(NewIp, out var ip))
        {
            StatusMessage = "Enter a valid IPv4 or IPv6 address to block.";
            return;
        }

        var choice = Durations.FirstOrDefault(d => d.Label == SelectedDuration);
        var permanent = SelectedDuration == PermanentDuration;
        try
        {
            await _client.BlockNowAsync(ip, choice.Duration, permanent, string.IsNullOrWhiteSpace(NewNote) ? "Manual block" : NewNote.Trim());
            StatusMessage = permanent ? $"Blocked {ip} permanently." : $"Blocked {ip} ({SelectedDuration.ToLowerInvariant()}).";
            NewIp = string.Empty;
            NewNote = string.Empty;
            await RefreshAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = "Block failed: " + ex.Message;
        }
    }

    /// <summary>Unblocks the selected/parameter IP.</summary>
    [RelayCommand]
    private Task UnblockAsync(BanRowViewModel? row) => UnblockCoreAsync(row, alsoWhitelist: false);

    /// <summary>Unblocks the IP and adds it to the whitelist.</summary>
    [RelayCommand]
    private Task UnblockAndWhitelistAsync(BanRowViewModel? row) => UnblockCoreAsync(row, alsoWhitelist: true);

    /// <summary>Promotes the IP to a permanent (blacklist-style) ban.</summary>
    [RelayCommand]
    private async Task PromoteToPermanentAsync(BanRowViewModel? row)
    {
        row ??= SelectedBan;
        if (row is null)
        {
            StatusMessage = "Select a row first.";
            return;
        }

        try
        {
            await _client.BlockNowAsync(row.IpAddress, duration: null, permanent: true, note: string.IsNullOrWhiteSpace(row.NoteText) ? "Promoted from Blocked IPs" : row.NoteText);
            StatusMessage = $"Promoted {row.IpAddress} to a permanent ban.";
            await RefreshAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = "Promote failed: " + ex.Message;
        }
    }

    /// <summary>Exports the currently displayed rows to a UTF-8 CSV file.</summary>
    [RelayCommand]
    private void ExportCsv()
    {
        if (Bans.Count == 0)
        {
            StatusMessage = "Nothing to export.";
            return;
        }

        var dialog = new SaveFileDialog
        {
            Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*",
            FileName = "winguard-bans.csv",
            Title = "Export blocked IPs",
        };

        if (dialog.ShowDialog() != true)
        {
            return;
        }

        try
        {
            var builder = new StringBuilder();
            builder.AppendLine("IP,Source,BannedAt(local),Expires(local),OffenseCount,Permanent,Note");
            foreach (var row in Bans)
            {
                builder.Append(CsvText.Escape(row.IpAddress)).Append(',');
                builder.Append(CsvText.Escape(row.SourceText)).Append(',');
                builder.Append(CsvText.Escape(row.BannedText)).Append(',');
                builder.Append(CsvText.Escape(row.ExpiresText)).Append(',');
                builder.Append(row.OffenseCount.ToString(CultureInfo.InvariantCulture)).Append(',');
                builder.Append(row.Dto.IsPermanent ? "yes" : "no").Append(',');
                builder.Append(CsvText.Escape(row.NoteText)).AppendLine();
            }

            File.WriteAllText(dialog.FileName, builder.ToString(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
            StatusMessage = $"Exported {Bans.Count} row(s) to {dialog.FileName}.";
        }
        catch (Exception ex)
        {
            StatusMessage = "Export failed: " + ex.Message;
        }
    }

    private async Task UnblockCoreAsync(BanRowViewModel? row, bool alsoWhitelist)
    {
        row ??= SelectedBan;
        if (row is null)
        {
            StatusMessage = "Select a row first.";
            return;
        }

        try
        {
            await _client.UnblockAsync(row.IpAddress, alsoWhitelist);
            StatusMessage = alsoWhitelist
                ? $"Unblocked {row.IpAddress} and added it to the whitelist."
                : $"Unblocked {row.IpAddress}.";
            await RefreshAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = "Unblock failed: " + ex.Message;
        }
    }

    /// <summary>Fetches the ban list right away instead of waiting for the next poll.</summary>
    private async Task RefreshAsync()
    {
        var bans = await _client.ListBansAsync();
        if (bans is not null)
        {
            UpdateBans(bans);
        }
    }

    private void Rebuild()
    {
        var filter = FilterText?.Trim() ?? string.Empty;
        var wanted = _all
            .Where(ban => filter.Length == 0
                || ban.IpAddress.Contains(filter, StringComparison.OrdinalIgnoreCase)
                || SourceLabels.For(ban.Source).Contains(filter, StringComparison.OrdinalIgnoreCase)
                || (ban.Note ?? string.Empty).Contains(filter, StringComparison.OrdinalIgnoreCase))
            .ToList();

        // The poller delivers the same list every couple of seconds. Only touch the grid when
        // something changed, so the selection and scroll position survive a refresh.
        if (!SameAsShown(wanted))
        {
            var selectedIp = SelectedBan?.IpAddress;
            Bans.ReplaceAll(wanted.Select(ban => new BanRowViewModel(ban)));
            SelectedBan = selectedIp is null ? null : Bans.FirstOrDefault(row => row.IpAddress == selectedIp);
        }

        CountText = _all.Count == 0
            ? "No blocked IPs."
            : Bans.Count == _all.Count
                ? $"{Bans.Count} blocked IP(s)."
                : $"{Bans.Count} of {_all.Count} blocked IP(s) shown.";
    }

    private bool SameAsShown(List<BanDto> wanted)
    {
        if (wanted.Count != Bans.Count)
        {
            return false;
        }

        for (var i = 0; i < wanted.Count; i++)
        {
            var a = wanted[i];
            var b = Bans[i].Dto;
            if (a.IpAddress != b.IpAddress || a.Source != b.Source || a.BannedAtUtc != b.BannedAtUtc
                || a.ExpiresUtc != b.ExpiresUtc || a.OffenseCount != b.OffenseCount
                || a.IsPermanent != b.IsPermanent || a.Note != b.Note)
            {
                return false;
            }
        }

        return true;
    }
}
