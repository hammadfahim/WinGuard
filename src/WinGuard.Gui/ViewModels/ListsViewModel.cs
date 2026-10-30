using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using WinGuard.Core.Engine;
using WinGuard.Core.Ipc;
using WinGuard.Core.Model;
using WinGuard.Gui.Collections;
using WinGuard.Gui.Services;

namespace WinGuard.Gui.ViewModels;

/// <summary>One whitelist or blacklist entry.</summary>
public sealed partial class ListRowViewModel : ObservableObject
{
    /// <summary>Creates a row.</summary>
    public ListRowViewModel(string value)
    {
        Value = value;
        var shape = IpText.Shape(value);
        KindText = IpText.KindLabel(shape);
        CoverageText = IpText.CoverageLabel(shape);
    }

    /// <summary>The address or range, as stored.</summary>
    public string Value { get; }

    /// <summary>Family and prefix.</summary>
    public string KindText { get; }

    /// <summary>How many addresses it covers.</summary>
    public string CoverageText { get; }

    /// <summary>On the blacklist, part of this entry is also whitelisted.</summary>
    [ObservableProperty]
    private bool _overlapsWhitelist;

    /// <summary>Tooltip for the row.</summary>
    public string ToolTipText => OverlapsWhitelist
        ? $"{Value} overlaps the whitelist. Whitelisted addresses stay reachable; the rest of this entry is blocked."
        : $"{Value}: {CoverageText}";

    partial void OnOverlapsWhitelistChanged(bool value) => OnPropertyChanged(nameof(ToolTipText));
}

/// <summary>What a paste or an import would do, shown for review before anything is sent.</summary>
public sealed partial class BulkAddViewModel : ObservableObject
{
    private readonly Func<BulkAddViewModel, Task> _commit;
    private readonly Action _cancel;

    /// <summary>Creates a review.</summary>
    public BulkAddViewModel(ListKind kind, IReadOnlyList<ParsedEntry> entries, Func<string, bool> overlapsWhitelist, Func<BulkAddViewModel, Task> commit, Action cancel)
    {
        Kind = kind;
        _commit = commit;
        _cancel = cancel;

        ToAdd = entries.Where(entry => entry.Status == EntryStatus.Valid).Select(entry => entry.Canonical).ToList();
        InvalidCount = entries.Count(entry => entry.Status == EntryStatus.Invalid);
        TooBroadCount = entries.Count(entry => entry.Status == EntryStatus.TooBroad);
        DuplicateCount = entries.Count(entry => entry.Status == EntryStatus.Duplicate);
        OverlapCount = kind == ListKind.Blacklist ? ToAdd.Count(overlapsWhitelist) : 0;
        Rejected = entries
            .Where(entry => entry.Status is EntryStatus.Invalid or EntryStatus.TooBroad)
            .Take(6)
            .Select(entry => $"{entry.Text}: {ListEntryParser.Explain(entry.Status)}")
            .ToList();
        Preview = ToAdd.Take(6).ToList();
    }

    /// <summary>The list being added to.</summary>
    public ListKind Kind { get; }

    /// <summary>Entries that will be added.</summary>
    public IReadOnlyList<string> ToAdd { get; }

    /// <summary>The first few of them.</summary>
    public IReadOnlyList<string> Preview { get; }

    /// <summary>Why the first few rejected values were rejected.</summary>
    public IReadOnlyList<string> Rejected { get; }

    /// <summary>Values that are not addresses.</summary>
    public int InvalidCount { get; }

    /// <summary>Ranges wider than the service accepts.</summary>
    public int TooBroadCount { get; }

    /// <summary>Values already on the list.</summary>
    public int DuplicateCount { get; }

    /// <summary>Blacklist values overlapping the whitelist.</summary>
    public int OverlapCount { get; }

    /// <summary>The review's heading.</summary>
    public string Title => $"Add {ToAdd.Count:N0} {(ToAdd.Count == 1 ? "entry" : "entries")} to the {(Kind == ListKind.Whitelist ? "whitelist" : "blacklist")}?";

    /// <summary>What was left out, and why.</summary>
    public string Summary
    {
        get
        {
            var parts = new List<string>();
            if (DuplicateCount > 0)
            {
                parts.Add($"{DuplicateCount:N0} already listed");
            }

            if (InvalidCount > 0)
            {
                parts.Add($"{InvalidCount:N0} not valid");
            }

            if (TooBroadCount > 0)
            {
                parts.Add($"{TooBroadCount:N0} too broad");
            }

            return parts.Count == 0 ? "Everything pasted is valid." : "Skipping " + string.Join(", ", parts) + ".";
        }
    }

    /// <summary>Which entries will be added, in short.</summary>
    public string PreviewText => ToAdd.Count <= Preview.Count
        ? string.Join(", ", Preview)
        : $"{string.Join(", ", Preview)} and {ToAdd.Count - Preview.Count:N0} more";

    /// <summary>The whitelist caution.</summary>
    public string OverlapText => OverlapCount == 0
        ? string.Empty
        : $"{OverlapCount:N0} of these overlap the whitelist. The whitelist wins: those addresses stay reachable.";

    /// <summary>Label of the commit button.</summary>
    public string CommitText => $"Add {ToAdd.Count:N0}";

    /// <summary>Whether there is anything to add.</summary>
    public bool CanCommit => ToAdd.Count > 0;

    /// <summary>True while adding.</summary>
    [ObservableProperty]
    private bool _isBusy;

    /// <summary>Adds the entries.</summary>
    [RelayCommand]
    private Task CommitAsync() => _commit(this);

    /// <summary>Abandons the review.</summary>
    [RelayCommand]
    private void Cancel() => _cancel();
}

/// <summary>One list: its entries, the inline add box and its live validation.</summary>
public sealed partial class ListPanelViewModel : ObservableObject
{
    private readonly ListsViewModel _owner;
    private readonly HashSet<string> _values = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, ListRowViewModel> _rows = new(StringComparer.OrdinalIgnoreCase);
    private IReadOnlyList<ListRowViewModel> _selection = [];

    /// <summary>Creates a panel.</summary>
    public ListPanelViewModel(ListsViewModel owner, ListKind kind, string title, string description, string addLabel)
    {
        _owner = owner;
        Kind = kind;
        Title = title;
        Description = description;
        AddLabel = addLabel;
    }

    /// <summary>Which list this is.</summary>
    public ListKind Kind { get; }

    /// <summary>Heading.</summary>
    public string Title { get; }

    /// <summary>What membership means.</summary>
    public string Description { get; }

    /// <summary>Caption of the add button.</summary>
    public string AddLabel { get; }

    /// <summary>Entries matching the filter.</summary>
    public BulkObservableCollection<ListRowViewModel> Entries { get; } = new();

    /// <summary>Canonical values on this list.</summary>
    public IReadOnlyCollection<string> Values => _values;

    /// <summary>Text in the add box.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Feedback))]
    [NotifyPropertyChangedFor(nameof(FeedbackTone))]
    [NotifyPropertyChangedFor(nameof(HasError))]
    [NotifyCanExecuteChangedFor(nameof(AddCommand))]
    private string _newValue = string.Empty;

    /// <summary>Filter over the entries.</summary>
    [ObservableProperty]
    private string _filterText = string.Empty;

    /// <summary>Row count, in words.</summary>
    [ObservableProperty]
    private string _countText = string.Empty;

    /// <summary>Which shared state the list is in.</summary>
    [ObservableProperty]
    private ViewState _state = ViewState.Loading;

    /// <summary>Headline of the empty state.</summary>
    [ObservableProperty]
    private string _emptyTitle = string.Empty;

    /// <summary>Selected rows, for the bulk remove.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(RemoveSelectedText))]
    [NotifyPropertyChangedFor(nameof(HasSelection))]
    private int _selectionCount;

    /// <summary>Whether any row is selected.</summary>
    public bool HasSelection => SelectionCount > 0;

    /// <summary>Caption of the bulk-remove button.</summary>
    public string RemoveSelectedText => $"Remove {SelectionCount:N0}";

    /// <summary>The live verdict on the add box.</summary>
    public string Feedback => _owner.Judge(this, NewValue).Text;

    /// <summary>What the verdict means.</summary>
    public Tone FeedbackTone => _owner.Judge(this, NewValue).Tone;

    /// <summary>Whether the add box holds something unusable.</summary>
    public bool HasError => FeedbackTone == Tone.Attack;

    /// <summary>Replaces the list.</summary>
    public void SetValues(IEnumerable<string> values)
    {
        _values.Clear();
        foreach (var value in values)
        {
            _values.Add(value);
        }

        foreach (var gone in _rows.Keys.Where(key => !_values.Contains(key)).ToList())
        {
            _rows.Remove(gone);
        }

        foreach (var value in _values)
        {
            if (!_rows.ContainsKey(value))
            {
                _rows[value] = new ListRowViewModel(value);
            }
        }

        Rebuild();
        RefreshFeedback();
    }

    /// <summary>Marks each entry that overlaps the given whitelist.</summary>
    public void MarkOverlaps(IpMatcher whitelist)
    {
        foreach (var row in _rows.Values)
        {
            row.OverlapsWhitelist = whitelist.OverlapsWhitelist(row.Value);
        }
    }

    /// <summary>Called by the view with the list's current selection.</summary>
    public void SetSelection(IEnumerable<ListRowViewModel> rows)
    {
        _selection = rows.ToList();
        SelectionCount = _selection.Count;
    }

    /// <summary>Re-reads the verdict after either list changed.</summary>
    public void RefreshFeedback()
    {
        OnPropertyChanged(nameof(Feedback));
        OnPropertyChanged(nameof(FeedbackTone));
        OnPropertyChanged(nameof(HasError));
        AddCommand.NotifyCanExecuteChanged();
    }

    /// <summary>Handles text pasted into the add box; returns true when it held several values.</summary>
    public bool TryPasteMany(string text)
    {
        if (ListEntryParser.Split(text).Count < 2)
        {
            return false;
        }

        _owner.BeginReview(this, text);
        return true;
    }

    partial void OnFilterTextChanged(string value) => Rebuild();

    private bool CanAdd() => NewValue.Trim().Length > 0 && !HasError;

    /// <summary>Adds the typed value.</summary>
    [RelayCommand(CanExecute = nameof(CanAdd))]
    private Task AddAsync() => _owner.AddAsync(this);

    /// <summary>Removes one entry, or the selection when it belongs to it.</summary>
    [RelayCommand]
    private Task RemoveAsync(ListRowViewModel? row)
    {
        if (row is null || !_selection.Contains(row))
        {
            return row is null ? Task.CompletedTask : _owner.RemoveAsync(this, [row]);
        }

        return _owner.RemoveAsync(this, _selection.ToList());
    }

    /// <summary>Removes the selection.</summary>
    [RelayCommand]
    private Task RemoveSelectedAsync() => _owner.RemoveAsync(this, _selection.ToList());

    /// <summary>Copies an entry.</summary>
    [RelayCommand]
    private void Copy(ListRowViewModel? row) => _owner.Copy(row);

    /// <summary>Reviews the clipboard's content for adding.</summary>
    [RelayCommand]
    private void PasteMany() => _owner.PasteFromClipboard(this);

    /// <summary>Reviews a text or CSV file for adding.</summary>
    [RelayCommand]
    private void Import() => _owner.Import(this);

    /// <summary>Saves the list to a text file.</summary>
    [RelayCommand]
    private void Export() => _owner.Export(this);

    private void Rebuild()
    {
        var filter = FilterText?.Trim() ?? string.Empty;
        var wanted = _rows.Values
            .Where(row => filter.Length == 0 || row.Value.Contains(filter, StringComparison.OrdinalIgnoreCase))
            .OrderBy(row => IpText.SortKey(row.Value))
            .ToList();

        Entries.SyncTo(wanted);
        CountText = _rows.Count == Entries.Count ? $"{Entries.Count:N0}" : $"{Entries.Count:N0} of {_rows.Count:N0}";
        EmptyTitle = _rows.Count == 0 ? "This list is empty" : "No matches";
        State = Entries.Count > 0 ? ViewState.Ready : ViewState.Empty;
    }
}

/// <summary>
/// Lists view-model (PLAN.md §9.5): whitelist and blacklist editors with live IP/CIDR validation,
/// paste of many entries, import/export and a warning when a blacklist entry overlaps the whitelist.
/// </summary>
public sealed partial class ListsViewModel : ObservableObject
{
    private readonly PipeClient _client;
    private readonly ToastCenter _toasts;
    private readonly DialogCenter _dialogs;
    private bool _hasData;

    /// <summary>Creates the view-model.</summary>
    /// <param name="client">Pipe client used for list operations.</param>
    /// <param name="toasts">Where results are reported.</param>
    /// <param name="dialogs">Where removals are confirmed.</param>
    public ListsViewModel(PipeClient client, ToastCenter toasts, DialogCenter dialogs)
    {
        _client = client;
        _toasts = toasts;
        _dialogs = dialogs;

        Whitelist = new ListPanelViewModel(
            this,
            ListKind.Whitelist,
            "Whitelist",
            "Never detected, never banned. The whitelist always wins.",
            "Allow");
        Blacklist = new ListPanelViewModel(
            this,
            ListKind.Blacklist,
            "Blacklist",
            "Blocked for good. A range is enforced as a whole-range firewall rule.",
            "Block");
    }

    /// <summary>The whitelist.</summary>
    public ListPanelViewModel Whitelist { get; }

    /// <summary>The blacklist.</summary>
    public ListPanelViewModel Blacklist { get; }

    /// <summary>A paste or import waiting for review, or null.</summary>
    [ObservableProperty]
    private BulkAddViewModel? _review;

    /// <summary>Which shared state the page is in.</summary>
    [ObservableProperty]
    private ViewState _state = ViewState.Loading;

    /// <summary>Why the lists are unavailable.</summary>
    [ObservableProperty]
    private string _errorText = string.Empty;

    /// <summary>The overlap warning across the two lists; empty when there is none.</summary>
    [ObservableProperty]
    private string _overlapWarning = string.Empty;

    /// <summary>Reloads both lists from the service.</summary>
    public async Task LoadAsync()
    {
        if (!_hasData)
        {
            State = ViewState.Loading;
        }

        try
        {
            var entries = await _client.ListListsAsync();
            if (entries is null)
            {
                // Keep what is shown: an unanswered request is not an empty list.
                SetDisconnected("The lists come from the service, which is not answering.");
                return;
            }

            Apply(entries);
        }
        catch (Exception ex)
        {
            SetDisconnected("Could not load the lists: " + ex.Message);
        }
    }

    /// <summary>Shows a loaded response.</summary>
    public void Apply(IReadOnlyList<ListEntryDto> entries)
    {
        _hasData = true;
        Whitelist.SetValues(entries.Where(entry => entry.Kind == ListKind.Whitelist).Select(entry => entry.Value));
        Blacklist.SetValues(entries.Where(entry => entry.Kind == ListKind.Blacklist).Select(entry => entry.Value));

        var matcher = WhitelistMatcher();
        Blacklist.MarkOverlaps(matcher);
        var overlapping = Blacklist.Values.Count(matcher.OverlapsWhitelist);
        OverlapWarning = overlapping == 0
            ? string.Empty
            : overlapping == 1
                ? "1 blacklist entry overlaps the whitelist. The whitelist wins: those addresses stay reachable."
                : $"{overlapping:N0} blacklist entries overlap the whitelist. The whitelist wins: those addresses stay reachable.";
        State = ViewState.Ready;
    }

    /// <summary>Marks the page unavailable; entries on hand stay visible.</summary>
    public void SetDisconnected(string reason)
    {
        if (!_hasData)
        {
            ErrorText = reason;
            State = ViewState.Error;
        }
    }

    /// <summary>The live verdict on a typed value.</summary>
    public (string Text, Tone Tone) Judge(ListPanelViewModel panel, string? text)
    {
        var value = text?.Trim() ?? string.Empty;
        if (value.Length == 0)
        {
            return (string.Empty, Tone.Neutral);
        }

        var existing = new HashSet<string>(panel.Values, StringComparer.OrdinalIgnoreCase);
        var entry = ListEntryParser.Parse(value, existing);
        if (entry.Status is EntryStatus.Invalid or EntryStatus.TooBroad or EntryStatus.Duplicate)
        {
            return (ListEntryParser.Explain(entry.Status), Tone.Attack);
        }

        var shape = IpText.Shape(entry.Canonical);
        var description = $"{IpText.KindLabel(shape)}, {IpText.CoverageLabel(shape)}";
        if (panel.Kind == ListKind.Blacklist)
        {
            if (WhitelistMatcher().OverlapsWhitelist(entry.Canonical))
            {
                return ($"{description}. Overlaps the whitelist: those addresses stay reachable.", Tone.Warn);
            }
        }
        else if (Blacklist.Values.Contains(entry.Canonical, StringComparer.OrdinalIgnoreCase))
        {
            return ($"{description}. Also on the blacklist: the whitelist wins.", Tone.Warn);
        }

        return (description, Tone.Protected);
    }

    /// <summary>Opens the review for a block of text.</summary>
    public void BeginReview(ListPanelViewModel panel, string text)
    {
        var entries = ListEntryParser.ParseMany(text, panel.Values);
        if (entries.Count == 0)
        {
            _toasts.Info("Nothing to add", "No addresses were found.");
            return;
        }

        var matcher = WhitelistMatcher();
        Review = new BulkAddViewModel(
            panel.Kind,
            entries,
            matcher.OverlapsWhitelist,
            review => CommitReviewAsync(panel, review),
            () => Review = null);
    }

    /// <summary>Adds the panel's typed value.</summary>
    public async Task AddAsync(ListPanelViewModel panel)
    {
        var entry = ListEntryParser.Parse(panel.NewValue);
        if (entry.Status != EntryStatus.Valid)
        {
            return;
        }

        try
        {
            await _client.AddToListAsync(panel.Kind == ListKind.Whitelist, entry.Canonical);
            panel.NewValue = string.Empty;
            await LoadAsync();
            _toasts.Success($"Added {entry.Canonical}", $"To the {panel.Title.ToLowerInvariant()}.");
        }
        catch (Exception ex)
        {
            _toasts.Error("Could not add the entry", ex.Message);
        }
    }

    /// <summary>Removes entries after confirmation.</summary>
    public async Task RemoveAsync(ListPanelViewModel panel, IReadOnlyList<ListRowViewModel> rows)
    {
        if (rows.Count == 0)
        {
            return;
        }

        var message = panel.Kind == ListKind.Whitelist
            ? "These addresses go back to being counted, and can be banned again."
            : "Permanent bans these entries created are lifted, unless another blacklist entry still covers them.";

        if (!await _dialogs.ConfirmAsync(
                Tone.Attack,
                rows.Count == 1 ? $"Remove {rows[0].Value}?" : $"Remove {rows.Count:N0} entries?",
                message,
                rows.Count == 1 ? "Remove" : $"Remove {rows.Count:N0}",
                rows.Select(row => row.Value).ToList()))
        {
            return;
        }

        var removed = 0;
        string? error = null;
        foreach (var row in rows)
        {
            try
            {
                await _client.RemoveListEntryAsync(panel.Kind, row.Value);
                removed++;
            }
            catch (Exception ex)
            {
                error ??= ex.Message;
                if (!_client.IsConnected)
                {
                    break;
                }
            }
        }

        await LoadAsync();
        if (error is null)
        {
            _toasts.Success(rows.Count == 1 ? $"Removed {rows[0].Value}" : $"Removed {removed:N0} entries");
        }
        else
        {
            _toasts.Error($"Removed {removed:N0} of {rows.Count:N0}", error);
        }
    }

    /// <summary>Copies an entry.</summary>
    public void Copy(ListRowViewModel? row)
    {
        if (row is null)
        {
            return;
        }

        if (ClipboardText.TrySet(row.Value))
        {
            _toasts.Success($"Copied {row.Value}");
        }
        else
        {
            _toasts.Warning("Could not copy", "Another program is holding the clipboard.");
        }
    }

    /// <summary>Reviews the clipboard's text.</summary>
    public void PasteFromClipboard(ListPanelViewModel panel)
    {
        var text = ClipboardText.Get();
        if (string.IsNullOrWhiteSpace(text))
        {
            _toasts.Info("The clipboard holds no text");
            return;
        }

        BeginReview(panel, text);
    }

    /// <summary>Reviews a file's content.</summary>
    public void Import(ListPanelViewModel panel)
    {
        var dialog = new OpenFileDialog
        {
            Filter = "Text or CSV files (*.txt;*.csv)|*.txt;*.csv|All files (*.*)|*.*",
            Title = $"Import into the {panel.Title.ToLowerInvariant()}",
        };

        if (dialog.ShowDialog() != true)
        {
            return;
        }

        try
        {
            BeginReview(panel, File.ReadAllText(dialog.FileName));
        }
        catch (Exception ex)
        {
            _toasts.Error("Could not read the file", ex.Message);
        }
    }

    /// <summary>Writes a list to a text file, one entry per line.</summary>
    public void Export(ListPanelViewModel panel)
    {
        if (panel.Values.Count == 0)
        {
            _toasts.Info("Nothing to export");
            return;
        }

        var dialog = new SaveFileDialog
        {
            Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*",
            FileName = $"winguard-{panel.Title.ToLowerInvariant()}.txt",
            Title = $"Export the {panel.Title.ToLowerInvariant()}",
        };

        if (dialog.ShowDialog() != true)
        {
            return;
        }

        try
        {
            File.WriteAllLines(dialog.FileName, panel.Values.OrderBy(IpText.SortKey));
            _toasts.Success($"Exported {panel.Values.Count:N0} entries", dialog.FileName);
        }
        catch (Exception ex)
        {
            _toasts.Error("Export failed", ex.Message);
        }
    }

    /// <summary>Reloads both lists.</summary>
    [RelayCommand]
    private Task RefreshAsync() => LoadAsync();

    private IpMatcher WhitelistMatcher() => new(Whitelist.Values, []);

    private async Task CommitReviewAsync(ListPanelViewModel panel, BulkAddViewModel review)
    {
        review.IsBusy = true;
        var added = 0;
        string? error = null;
        foreach (var value in review.ToAdd)
        {
            try
            {
                await _client.AddToListAsync(panel.Kind == ListKind.Whitelist, value);
                added++;
            }
            catch (Exception ex)
            {
                error ??= ex.Message;
                if (!_client.IsConnected)
                {
                    break;
                }
            }
        }

        Review = null;
        await LoadAsync();
        if (error is null)
        {
            _toasts.Success($"Added {added:N0} entries", $"To the {panel.Title.ToLowerInvariant()}.");
        }
        else
        {
            _toasts.Error($"Added {added:N0} of {review.ToAdd.Count:N0}", error);
        }
    }
}
