using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using WinGuard.Core.Ipc;
using WinGuard.Core.Model;
using WinGuard.Gui.Services;

namespace WinGuard.Gui.ViewModels;

/// <summary>
/// Lists view-model (PLAN.md §9.5): whitelist and blacklist editors (single IPs or CIDR ranges)
/// with validation via <c>WinGuard.Core.Engine.IpMatcher.TryParseCidr</c> and add/remove commands.
/// </summary>
public sealed partial class ListsViewModel : ObservableObject
{
    private readonly PipeClient _client;

    /// <summary>Creates the view-model.</summary>
    /// <param name="client">Pipe client used for list operations.</param>
    public ListsViewModel(PipeClient client) => _client = client;

    /// <summary>Whitelist entries.</summary>
    public ObservableCollection<ListEntryDto> Whitelist { get; } = [];

    /// <summary>Blacklist entries.</summary>
    public ObservableCollection<ListEntryDto> Blacklist { get; } = [];

    /// <summary>Text typed into the whitelist add box.</summary>
    [ObservableProperty]
    private string _newWhitelistValue = string.Empty;

    /// <summary>Text typed into the blacklist add box.</summary>
    [ObservableProperty]
    private string _newBlacklistValue = string.Empty;

    /// <summary>Selected whitelist entry.</summary>
    [ObservableProperty]
    private ListEntryDto? _selectedWhitelistEntry;

    /// <summary>Selected blacklist entry.</summary>
    [ObservableProperty]
    private ListEntryDto? _selectedBlacklistEntry;

    /// <summary>User-visible error message.</summary>
    [ObservableProperty]
    private string _errorMessage = string.Empty;

    /// <summary>User-visible status message.</summary>
    [ObservableProperty]
    private string _statusMessage = string.Empty;

    /// <summary>Reloads both lists from the service.</summary>
    public async Task LoadAsync()
    {
        try
        {
            var entries = await _client.ListListsAsync();
            Whitelist.Clear();
            Blacklist.Clear();
            foreach (var entry in entries)
            {
                if (entry.Kind == ListKind.Whitelist)
                {
                    Whitelist.Add(entry);
                }
                else
                {
                    Blacklist.Add(entry);
                }
            }

            StatusMessage = $"{Whitelist.Count} whitelist, {Blacklist.Count} blacklist entr(ies).";
        }
        catch (Exception ex)
        {
            ErrorMessage = "Could not load lists: " + ex.Message;
        }
    }

    /// <summary>Adds the typed value to the whitelist.</summary>
    [RelayCommand]
    private Task AddWhitelistAsync() => AddCoreAsync(whitelist: true);

    /// <summary>Adds the typed value to the blacklist.</summary>
    [RelayCommand]
    private Task AddBlacklistAsync() => AddCoreAsync(whitelist: false);

    /// <summary>Removes the selected whitelist entry.</summary>
    [RelayCommand]
    private Task RemoveWhitelistAsync(ListEntryDto? entry) => RemoveCoreAsync(ListKind.Whitelist, entry);

    /// <summary>Removes the selected blacklist entry.</summary>
    [RelayCommand]
    private Task RemoveBlacklistAsync(ListEntryDto? entry) => RemoveCoreAsync(ListKind.Blacklist, entry);

    /// <summary>Reloads both lists.</summary>
    [RelayCommand]
    private Task RefreshAsync() => LoadAsync();

    private async Task AddCoreAsync(bool whitelist)
    {
        var value = (whitelist ? NewWhitelistValue : NewBlacklistValue).Trim();
        if (value.Length == 0)
        {
            ErrorMessage = "Enter an IP address or CIDR range (for example 203.0.113.7 or 10.0.0.0/8).";
            return;
        }

        if (!WinGuard.Core.Engine.IpMatcher.TryParseCidr(value, out _))
        {
            ErrorMessage = $"'{value}' is not a valid IP address or CIDR range.";
            return;
        }

        try
        {
            await _client.AddToListAsync(whitelist, value);
            if (whitelist)
            {
                NewWhitelistValue = string.Empty;
            }
            else
            {
                NewBlacklistValue = string.Empty;
            }

            ErrorMessage = string.Empty;
            await LoadAsync();
            StatusMessage = $"Added {value} to the {(whitelist ? "whitelist" : "blacklist")}.";
        }
        catch (Exception ex)
        {
            ErrorMessage = "Add failed: " + ex.Message;
        }
    }

    private async Task RemoveCoreAsync(ListKind kind, ListEntryDto? entry)
    {
        if (entry is null)
        {
            ErrorMessage = "Select an entry to remove.";
            return;
        }

        try
        {
            await _client.RemoveListEntryAsync(kind, entry.Value);
            ErrorMessage = string.Empty;
            await LoadAsync();
            StatusMessage = $"Removed {entry.Value}.";
        }
        catch (Exception ex)
        {
            ErrorMessage = "Remove failed: " + ex.Message;
        }
    }
}