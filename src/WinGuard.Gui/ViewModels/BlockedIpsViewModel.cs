using System.ComponentModel;
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
/// Blocked IPs view-model (PLAN.md §9.2): instant search, numeric-aware sorting, bulk actions with
/// confirmation, a live countdown and CSV export. Filtering and sorting happen here, not in a
/// CollectionView, so they are plain testable code and a poll can apply the smallest possible edit.
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
    private readonly ToastCenter _toasts;
    private readonly DialogCenter _dialogs;
    private readonly Dictionary<string, BanRowViewModel> _rows = new(StringComparer.OrdinalIgnoreCase);

    private IReadOnlyList<BanRowViewModel> _selection = [];
    private string _sortColumn = nameof(BanRowViewModel.BannedUtc);
    private ListSortDirection _sortDirection = ListSortDirection.Descending;
    private bool _hasData;

    /// <summary>Creates the view-model.</summary>
    /// <param name="client">Pipe client used to block / unblock IPs.</param>
    /// <param name="toasts">Where results are reported.</param>
    /// <param name="dialogs">Where destructive actions are confirmed.</param>
    public BlockedIpsViewModel(PipeClient client, ToastCenter toasts, DialogCenter dialogs)
    {
        _client = client;
        _toasts = toasts;
        _dialogs = dialogs;
    }

    /// <summary>Filtered, sorted rows shown in the grid.</summary>
    public BulkObservableCollection<BanRowViewModel> Bans { get; } = new();

    /// <summary>Choices for the manual-block duration.</summary>
    public string[] DurationOptions { get; } = Durations.Select(d => d.Label).ToArray();

    /// <summary>Case-insensitive substring filter (IP, source or note).</summary>
    [ObservableProperty]
    private string _filterText = string.Empty;

    /// <summary>What the grid currently shows, in words.</summary>
    [ObservableProperty]
    private string _countText = string.Empty;

    /// <summary>Which shared state the grid is in.</summary>
    [ObservableProperty]
    private ViewState _state = ViewState.Loading;

    /// <summary>Why the list is unavailable.</summary>
    [ObservableProperty]
    private string _errorText = string.Empty;

    /// <summary>Headline of the empty state.</summary>
    [ObservableProperty]
    private string _emptyTitle = "No blocked addresses";

    /// <summary>Explanation of the empty state.</summary>
    [ObservableProperty]
    private string _emptyText = "Attackers appear here the moment they cross the failed-login threshold.";

    /// <summary>Bans are recorded, not enforced.</summary>
    [ObservableProperty]
    private bool _isReportOnly;

    /// <summary>Selected rows, for the bulk bar.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasSelection))]
    [NotifyPropertyChangedFor(nameof(SelectionText))]
    private int _selectionCount;

    /// <summary>True while a bulk action runs.</summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(UnblockCommand))]
    [NotifyCanExecuteChangedFor(nameof(UnblockAndWhitelistCommand))]
    [NotifyCanExecuteChangedFor(nameof(PromoteToPermanentCommand))]
    private bool _isBusy;

    /// <summary>Progress of a bulk action.</summary>
    [ObservableProperty]
    private string _busyText = string.Empty;

    /// <summary>Whether the manual-block form is open.</summary>
    [ObservableProperty]
    private bool _isBlockFormOpen;

    /// <summary>IP typed into the manual-block box.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(NewIpError))]
    [NotifyPropertyChangedFor(nameof(NewIpHint))]
    [NotifyCanExecuteChangedFor(nameof(BlockNowCommand))]
    private string _newIp = string.Empty;

    /// <summary>Optional note for the manual block.</summary>
    [ObservableProperty]
    private string _newNote = string.Empty;

    /// <summary>Selected manual-block duration.</summary>
    [ObservableProperty]
    private string _selectedDuration = DefaultDuration;

    /// <summary>Whether any row is selected.</summary>
    public bool HasSelection => SelectionCount > 0;

    /// <summary>"3 selected".</summary>
    public string SelectionText => $"{SelectionCount:N0} selected";

    /// <summary>The live validation message for the manual-block box.</summary>
    public string NewIpError
    {
        get
        {
            var text = NewIp?.Trim() ?? string.Empty;
            if (text.Length == 0)
            {
                return string.Empty;
            }

            if (text.Contains('/'))
            {
                return "Block single addresses here. Use the blacklist on the Lists page for a range.";
            }

            if (!IpMatcher.TryNormalize(text, out var ip))
            {
                return "Not a valid IPv4 or IPv6 address.";
            }

            return IpMatcher.IsBannable(ip) ? string.Empty : "This address can never be a remote client, so it cannot be blocked.";
        }
    }

    /// <summary>A caution about an address that is valid, but probably not what was meant.</summary>
    public string NewIpHint => NewIpError.Length == 0 && IpText.IsInternal(NewIp)
        ? "This is a private or loopback address: blocking it can lock out your own network."
        : string.Empty;

    /// <summary>Replaces the ban list, reusing every row that still exists.</summary>
    /// <param name="bans">Fresh ban DTOs.</param>
    public void UpdateBans(IReadOnlyList<BanDto> bans)
    {
        _hasData = true;

        var incoming = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var changed = false;
        foreach (var dto in bans)
        {
            incoming.Add(dto.IpAddress);
            if (_rows.TryGetValue(dto.IpAddress, out var row))
            {
                changed |= row.Update(dto);
            }
            else
            {
                _rows[dto.IpAddress] = new BanRowViewModel(dto);
                changed = true;
            }
        }

        foreach (var gone in _rows.Keys.Where(key => !incoming.Contains(key)).ToList())
        {
            _rows.Remove(gone);
            changed = true;
        }

        if (changed || State != ViewState.Ready)
        {
            Rebuild();
        }
    }

    /// <summary>Marks the list unavailable; rows on hand stay visible.</summary>
    public void SetDisconnected(string reason)
    {
        if (!_hasData)
        {
            ErrorText = reason;
            State = ViewState.Error;
        }
    }

    /// <summary>Marks the first load as running.</summary>
    public void SetConnecting()
    {
        if (!_hasData)
        {
            State = ViewState.Loading;
        }
    }

    /// <summary>Called by the view with the grid's current selection.</summary>
    public void SetSelection(IEnumerable<BanRowViewModel> rows)
    {
        _selection = rows.ToList();
        SelectionCount = _selection.Count;
    }

    /// <summary>Sorts by a column; the same column again flips the direction.</summary>
    /// <param name="column">A <see cref="BanRowViewModel"/> property name.</param>
    /// <returns>The direction now in effect.</returns>
    public ListSortDirection SortBy(string column)
    {
        _sortDirection = column == _sortColumn && _sortDirection == ListSortDirection.Ascending
            ? ListSortDirection.Descending
            : column == _sortColumn ? ListSortDirection.Ascending : DefaultDirection(column);
        _sortColumn = column;
        Rebuild(userSort: true);
        return _sortDirection;
    }

    /// <summary>Re-reads the visible countdowns (once a second while the page is on screen).</summary>
    public void Tick()
    {
        foreach (var row in Bans)
        {
            row.Tick();
        }
    }

    /// <summary>Shows one address: used by links from the dashboard and the event log.</summary>
    public void Show(string ip) => FilterText = ip;

    partial void OnFilterTextChanged(string value) => Rebuild();

    /// <summary>Opens or closes the manual-block form.</summary>
    [RelayCommand]
    private void ToggleBlockForm() => IsBlockFormOpen = !IsBlockFormOpen;

    /// <summary>Clears the search.</summary>
    [RelayCommand]
    private void ClearFilter() => FilterText = string.Empty;

    /// <summary>Blocks the IP typed into the manual-block box.</summary>
    [RelayCommand(CanExecute = nameof(CanBlockNow))]
    private async Task BlockNowAsync()
    {
        if (!IpMatcher.TryNormalize(NewIp, out var ip))
        {
            return;
        }

        var choice = Durations.FirstOrDefault(d => d.Label == SelectedDuration);
        var permanent = SelectedDuration == PermanentDuration;
        try
        {
            await _client.BlockNowAsync(ip, choice.Duration, permanent, string.IsNullOrWhiteSpace(NewNote) ? "Manual block" : NewNote.Trim());
            _toasts.Success(permanent ? $"Blocked {ip} permanently" : $"Blocked {ip}", permanent ? string.Empty : SelectedDuration);
            NewIp = string.Empty;
            NewNote = string.Empty;
            IsBlockFormOpen = false;
            await RefreshAsync();
        }
        catch (Exception ex)
        {
            _toasts.Error("Block failed", ex.Message);
        }
    }

    /// <summary>Unblocks the given row, or the selection.</summary>
    [RelayCommand(CanExecute = nameof(CanAct))]
    private async Task UnblockAsync(BanRowViewModel? row)
    {
        var targets = Targets(row);
        if (targets.Count == 0)
        {
            return;
        }

        var permanent = targets.Count(target => target.IsPermanent);
        var notes = new List<string>();
        if (permanent > 0)
        {
            notes.Add(targets.Count == 1
                ? "This is a permanent ban."
                : permanent == 1 ? "1 of these is a permanent ban." : $"{permanent:N0} of these are permanent bans.");
        }

        AddPrefixNote(targets, notes);
        notes.Add("If the attack continues, they will be banned again.");

        if (!await _dialogs.ConfirmAsync(
                Tone.Attack,
                targets.Count == 1 ? $"Unblock {targets[0].IpAddress}?" : $"Unblock {targets.Count:N0} addresses?",
                "The firewall rule is removed now, and these addresses can reach this server again.",
                targets.Count == 1 ? "Unblock" : $"Unblock {targets.Count:N0}",
                targets.Select(target => target.IpAddress).ToList(),
                notes))
        {
            return;
        }

        await RunBulkAsync(targets, "Unblocking", "Unblocked", target => _client.UnblockAsync(target.IpAddress, alsoWhitelist: false));
    }

    /// <summary>Unblocks the given row, or the selection, and adds it to the whitelist.</summary>
    [RelayCommand(CanExecute = nameof(CanAct))]
    private async Task UnblockAndWhitelistAsync(BanRowViewModel? row)
    {
        var targets = Targets(row);
        if (targets.Count == 0)
        {
            return;
        }

        var notes = new List<string> { "Whitelisted addresses are never banned again, however often they fail to log in." };
        AddPrefixNote(targets, notes);

        if (!await _dialogs.ConfirmAsync(
                Tone.Attack,
                targets.Count == 1 ? $"Whitelist {targets[0].IpAddress}?" : $"Whitelist {targets.Count:N0} addresses?",
                "These addresses are unblocked now and excluded from detection until you remove them from the whitelist.",
                targets.Count == 1 ? "Unblock and whitelist" : $"Whitelist {targets.Count:N0}",
                targets.Select(target => target.IpAddress).ToList(),
                notes))
        {
            return;
        }

        await RunBulkAsync(targets, "Whitelisting", "Whitelisted", target => _client.UnblockAsync(target.IpAddress, alsoWhitelist: true));
    }

    /// <summary>Promotes the given row, or the selection, to a permanent ban.</summary>
    [RelayCommand(CanExecute = nameof(CanAct))]
    private async Task PromoteToPermanentAsync(BanRowViewModel? row)
    {
        var targets = Targets(row).Where(target => !target.IsPermanent).ToList();
        if (targets.Count == 0)
        {
            _toasts.Info("Already permanent", "Every selected ban is permanent.");
            return;
        }

        var notes = new List<string>();
        AddPrefixNote(targets, notes);

        if (!await _dialogs.ConfirmAsync(
                Tone.Warn,
                targets.Count == 1 ? $"Make {targets[0].IpAddress} permanent?" : $"Make {targets.Count:N0} bans permanent?",
                "These bans stop expiring. They stay in force until someone unblocks them by hand.",
                targets.Count == 1 ? "Make permanent" : $"Make {targets.Count:N0} permanent",
                targets.Select(target => target.IpAddress).ToList(),
                notes))
        {
            return;
        }

        await RunBulkAsync(
            targets,
            "Promoting",
            "Made permanent:",
            target => _client.BlockNowAsync(
                target.IpAddress,
                duration: null,
                permanent: true,
                note: string.IsNullOrWhiteSpace(target.NoteText) ? "Promoted from Blocked IPs" : target.NoteText));
    }

    /// <summary>Copies the given row's address, or those of the selection.</summary>
    [RelayCommand]
    private void CopyIp(BanRowViewModel? row)
    {
        var targets = Targets(row);
        if (targets.Count == 0)
        {
            return;
        }

        var text = string.Join(Environment.NewLine, targets.Select(target => target.IpAddress));
        if (ClipboardText.TrySet(text))
        {
            _toasts.Success(targets.Count == 1 ? $"Copied {targets[0].IpAddress}" : $"Copied {targets.Count:N0} addresses");
        }
        else
        {
            _toasts.Warning("Could not copy", "Another program is holding the clipboard.");
        }
    }

    /// <summary>Exports the currently displayed rows to a UTF-8 CSV file.</summary>
    [RelayCommand]
    private void ExportCsv()
    {
        if (Bans.Count == 0)
        {
            _toasts.Info("Nothing to export");
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
            File.WriteAllText(dialog.FileName, BuildCsv(Bans), new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
            _toasts.Success($"Exported {Bans.Count:N0} rows", dialog.FileName);
        }
        catch (Exception ex)
        {
            _toasts.Error("Export failed", ex.Message);
        }
    }

    /// <summary>The CSV text of a set of rows.</summary>
    public static string BuildCsv(IEnumerable<BanRowViewModel> rows)
    {
        var builder = new StringBuilder();
        builder.AppendLine("IP,Kind,Source,BannedAt(local),Expires(local),OffenseCount,Permanent,Note");
        foreach (var row in rows)
        {
            builder.Append(CsvText.Escape(row.IpAddress)).Append(',');
            builder.Append(CsvText.Escape(row.KindText)).Append(',');
            builder.Append(CsvText.Escape(row.SourceText)).Append(',');
            builder.Append(CsvText.Escape(row.BannedText)).Append(',');
            builder.Append(CsvText.Escape(row.ExpiresText)).Append(',');
            builder.Append(row.OffenseCount.ToString(CultureInfo.InvariantCulture)).Append(',');
            builder.Append(row.IsPermanent ? "yes" : "no").Append(',');
            builder.Append(CsvText.Escape(row.NoteText)).AppendLine();
        }

        return builder.ToString();
    }

    /// <summary>Whether a row matches the filter text.</summary>
    public static bool Matches(BanRowViewModel row, string filter) =>
        filter.Length == 0
        || row.IpAddress.Contains(filter, StringComparison.OrdinalIgnoreCase)
        || row.SourceText.Contains(filter, StringComparison.OrdinalIgnoreCase)
        || row.KindText.Contains(filter, StringComparison.OrdinalIgnoreCase)
        || row.NoteText.Contains(filter, StringComparison.OrdinalIgnoreCase);

    private static ListSortDirection DefaultDirection(string column) =>
        column is nameof(BanRowViewModel.BannedUtc) or nameof(BanRowViewModel.OffenseCount)
            ? ListSortDirection.Descending
            : ListSortDirection.Ascending;

    private static void AddPrefixNote(IReadOnlyCollection<BanRowViewModel> targets, List<string> notes)
    {
        var prefixes = targets.Count(target => target.IsPrefix);
        if (prefixes > 0)
        {
            notes.Add(prefixes == 1
                ? "One entry is a whole IPv6 prefix, not a single address."
                : $"{prefixes:N0} entries are whole IPv6 prefixes, not single addresses.");
        }
    }

    private bool CanBlockNow() => !string.IsNullOrWhiteSpace(NewIp) && NewIpError.Length == 0;

    private bool CanAct(BanRowViewModel? row) => !IsBusy;

    /// <summary>The row a command was invoked on, or the selection when that row is part of it.</summary>
    private List<BanRowViewModel> Targets(BanRowViewModel? row)
    {
        if (row is null || _selection.Contains(row))
        {
            return _selection.ToList();
        }

        return [row];
    }

    private async Task RunBulkAsync(IReadOnlyList<BanRowViewModel> targets, string doing, string done, Func<BanRowViewModel, Task> action)
    {
        IsBusy = true;
        var succeeded = 0;
        string? firstError = null;
        try
        {
            for (var i = 0; i < targets.Count; i++)
            {
                BusyText = targets.Count == 1 ? $"{doing}…" : $"{doing} {i + 1:N0} of {targets.Count:N0}…";
                try
                {
                    await action(targets[i]);
                    succeeded++;
                }
                catch (Exception ex)
                {
                    firstError ??= ex.Message;

                    // A dead pipe would fail every remaining row the same way, one timeout at a time.
                    if (!_client.IsConnected)
                    {
                        break;
                    }
                }
            }
        }
        finally
        {
            IsBusy = false;
            BusyText = string.Empty;
        }

        var subject = targets.Count == 1 ? targets[0].IpAddress : $"{succeeded:N0} of {targets.Count:N0} addresses";
        if (firstError is null)
        {
            _toasts.Success($"{done} {subject}");
        }
        else if (succeeded > 0)
        {
            _toasts.Warning($"{done} {subject}", firstError);
        }
        else
        {
            _toasts.Error("Nothing changed", firstError);
        }

        await RefreshAsync();
    }

    /// <summary>Fetches the ban list right away instead of waiting for the next poll.</summary>
    public async Task RefreshAsync()
    {
        var bans = await _client.ListBansAsync();
        if (bans is not null)
        {
            UpdateBans(bans);
        }
    }

    private void Rebuild(bool userSort = false)
    {
        var filter = FilterText?.Trim() ?? string.Empty;
        var wanted = Sort(_rows.Values.Where(row => Matches(row, filter))).ToList();

        if (userSort)
        {
            Bans.ReplaceAll(wanted);
        }
        else
        {
            Bans.SyncTo(wanted);
        }

        CountText = _rows.Count == 0
            ? string.Empty
            : Bans.Count == _rows.Count
                ? $"{Bans.Count:N0} blocked"
                : $"{Bans.Count:N0} of {_rows.Count:N0} shown";

        if (Bans.Count > 0)
        {
            State = ViewState.Ready;
        }
        else if (_hasData)
        {
            EmptyTitle = _rows.Count == 0 ? "No blocked addresses" : "No matches";
            EmptyText = _rows.Count == 0
                ? "Attackers appear here the moment they cross the failed-login threshold."
                : $"Nothing matches \"{filter}\". Search looks at the address, engine and note.";
            State = ViewState.Empty;
        }
    }

    private IEnumerable<BanRowViewModel> Sort(IEnumerable<BanRowViewModel> rows)
    {
        var ascending = _sortDirection == ListSortDirection.Ascending;
        IOrderedEnumerable<BanRowViewModel> Order<TKey>(Func<BanRowViewModel, TKey> key) =>
            ascending ? rows.OrderBy(key) : rows.OrderByDescending(key);

        var ordered = _sortColumn switch
        {
            nameof(BanRowViewModel.IpSortKey) => Order(row => row.IpSortKey),
            nameof(BanRowViewModel.SourceText) => Order(row => row.SourceText),
            nameof(BanRowViewModel.ExpiresSortKey) => Order(row => row.ExpiresSortKey),
            nameof(BanRowViewModel.OffenseCount) => Order(row => row.OffenseCount),
            nameof(BanRowViewModel.NoteText) => Order(row => row.NoteText),
            _ => Order(row => row.BannedUtc),
        };

        // A stable tiebreak: equal keys must not trade places from one poll to the next.
        return ordered.ThenBy(row => row.IpSortKey);
    }
}
