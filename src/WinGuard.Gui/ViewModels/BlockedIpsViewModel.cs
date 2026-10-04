using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using WinGuard.Core.Ipc;
using WinGuard.Gui.Services;

namespace WinGuard.Gui.ViewModels;

/// <summary>
/// Blocked IPs view-model (PLAN.md §9.2): a filterable grid of active bans with Unblock,
/// Unblock &amp; Whitelist, Promote-to-permanent context actions and CSV export.
/// </summary>
public sealed partial class BlockedIpsViewModel : ObservableObject
{
    private readonly PipeClient _client;
    private readonly List<BanDto> _all = [];

    /// <summary>Creates the view-model.</summary>
    /// <param name="client">Pipe client used to unblock / re-block IPs.</param>
    public BlockedIpsViewModel(PipeClient client) => _client = client;

    /// <summary>Filtered rows shown in the grid.</summary>
    public ObservableCollection<BanRowViewModel> Bans { get; } = [];

    /// <summary>Current selection.</summary>
    [ObservableProperty]
    private BanRowViewModel? _selectedBan;

    /// <summary>Case-insensitive substring filter (IP, source or note).</summary>
    [ObservableProperty]
    private string _filterText = string.Empty;

    /// <summary>Status / result text shown under the grid.</summary>
    [ObservableProperty]
    private string _statusMessage = string.Empty;

    /// <summary>Replaces the ban list and reapplies the current filter.</summary>
    /// <param name="bans">Fresh ban DTOs.</param>
    public void UpdateBans(IReadOnlyList<BanDto> bans)
    {
        _all.Clear();
        _all.AddRange(bans);
        Rebuild();
    }

    partial void OnFilterTextChanged(string value) => Rebuild();

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
        if (row is null)
        {
            return;
        }

        try
        {
            await _client.BlockNowAsync(row.IpAddress, duration: null, permanent: true, note: string.IsNullOrWhiteSpace(row.NoteText) ? "Promoted from Blocked IPs" : row.NoteText);
            StatusMessage = $"Promoted {row.IpAddress} to a permanent ban.";
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
                builder.Append(EscapeCsv(row.IpAddress)).Append(',');
                builder.Append(EscapeCsv(row.SourceText)).Append(',');
                builder.Append(EscapeCsv(row.BannedText)).Append(',');
                builder.Append(EscapeCsv(row.ExpiresText)).Append(',');
                builder.Append(row.OffenseCount.ToString(CultureInfo.InvariantCulture)).Append(',');
                builder.Append(row.Dto.IsPermanent ? "yes" : "no").Append(',');
                builder.Append(EscapeCsv(row.NoteText)).AppendLine();
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
        if (row is null)
        {
            return;
        }

        try
        {
            await _client.UnblockAsync(row.IpAddress, alsoWhitelist);
            StatusMessage = alsoWhitelist
                ? $"Unblocked {row.IpAddress} and added it to the whitelist."
                : $"Unblocked {row.IpAddress}.";
        }
        catch (Exception ex)
        {
            StatusMessage = "Unblock failed: " + ex.Message;
        }
    }

    private void Rebuild()
    {
        Bans.Clear();
        var filter = FilterText?.Trim() ?? string.Empty;

        foreach (var ban in _all)
        {
            if (filter.Length == 0 ||
                ban.IpAddress.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                ban.Source.ToString().Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                (ban.Note ?? string.Empty).Contains(filter, StringComparison.OrdinalIgnoreCase))
            {
                Bans.Add(new BanRowViewModel(ban));
            }
        }

        StatusMessage = $"{Bans.Count} ban(s) shown.";
    }

    private static string EscapeCsv(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        if (value.Contains(',') || value.Contains('"') || value.Contains('\n') || value.Contains('\r'))
        {
            return "\"" + value.Replace("\"", "\"\"") + "\"";
        }

        return value;
    }
}