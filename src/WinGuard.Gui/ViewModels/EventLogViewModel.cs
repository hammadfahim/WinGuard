using System.IO;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using WinGuard.Core.Ipc;
using WinGuard.Core.Model;
using WinGuard.Gui.Collections;
using WinGuard.Gui.Services;

namespace WinGuard.Gui.ViewModels;

/// <summary>A toggleable filter with a live count.</summary>
public sealed partial class FilterChip : ObservableObject
{
    private readonly Action _changed;

    /// <summary>Creates a chip that starts on.</summary>
    public FilterChip(string label, Action changed)
    {
        Label = label;
        _changed = changed;
    }

    /// <summary>What it filters on.</summary>
    public string Label { get; }

    /// <summary>Whether matching rows are shown.</summary>
    [ObservableProperty]
    private bool _isOn = true;

    /// <summary>How many rows in the feed carry this value, as text.</summary>
    [ObservableProperty]
    private string _countText = "0";

    /// <summary>Sets the state without re-filtering, for changing several chips at once.</summary>
    public void Set(bool on)
    {
        _suppress = true;
        IsOn = on;
        _suppress = false;
    }

    private bool _suppress;

    partial void OnIsOnChanged(bool value)
    {
        if (!_suppress)
        {
            _changed();
        }
    }
}

/// <summary>
/// Event Log view-model (PLAN.md §9.3): a capped live tail with level and engine chips, search,
/// pause/resume and a "N new events" pill. Pausing freezes the list and queues what arrives;
/// scrolling up keeps appending but stops following. Either way the pill says how much is waiting.
/// </summary>
public sealed partial class EventLogViewModel : ObservableObject
{
    /// <summary>Label for events no engine produced.</summary>
    public const string SystemSource = "System";

    // Several pages of ListEvents: a recovered burst has to fit, or fetching it would be for nothing.
    private const int MaxEntries = 10_000;

    // Beyond this many rows at once a single Reset redraws faster than individual inserts.
    private const int ResetThreshold = 128;

    private readonly ToastCenter _toasts;
    private readonly List<EventRowViewModel> _all = [];
    private readonly List<EventDto> _pending = [];
    private readonly HashSet<string> _seen = [];
    private readonly Queue<string> _seenOrder = [];

    private bool _everConnected;
    private int _pendingDropped;

    /// <summary>Creates the view-model.</summary>
    /// <param name="toasts">Where results are reported.</param>
    public EventLogViewModel(ToastCenter toasts)
    {
        _toasts = toasts;

        LevelChips =
        [
            new FilterChip("Info", Rebuild),
            new FilterChip("Warning", Rebuild),
            new FilterChip("Error", Rebuild),
        ];

        SourceChips =
        [
            new FilterChip(SourceLabels.Rdp, Rebuild),
            new FilterChip(SourceLabels.MsSql, Rebuild),
            new FilterChip(SourceLabels.Ftp, Rebuild),
            new FilterChip(SourceLabels.Custom, Rebuild),
            new FilterChip(SystemSource, Rebuild),
        ];
    }

    /// <summary>Raised when the view should jump to the newest row.</summary>
    public event Action? ScrollToEndRequested;

    /// <summary>Rows currently visible after filtering, oldest first.</summary>
    public BulkObservableCollection<EventRowViewModel> Events { get; } = new();

    /// <summary>Severity filter chips.</summary>
    public IReadOnlyList<FilterChip> LevelChips { get; }

    /// <summary>Engine filter chips.</summary>
    public IReadOnlyList<FilterChip> SourceChips { get; }

    /// <summary>Case-insensitive text filter over the IP and the message.</summary>
    [ObservableProperty]
    private string _searchText = string.Empty;

    /// <summary>Number of entries currently shown, as text.</summary>
    [ObservableProperty]
    private string _countText = string.Empty;

    /// <summary>Which shared state the list is in.</summary>
    [ObservableProperty]
    private ViewState _state = ViewState.Loading;

    /// <summary>Why the feed is unavailable.</summary>
    [ObservableProperty]
    private string _errorText = string.Empty;

    /// <summary>Headline of the empty state.</summary>
    [ObservableProperty]
    private string _emptyTitle = "No events yet";

    /// <summary>Explanation of the empty state.</summary>
    [ObservableProperty]
    private string _emptyText = "Blocks, unblocks and service messages appear here as they happen.";

    /// <summary>True while the tail is frozen.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PauseGlyph))]
    [NotifyPropertyChangedFor(nameof(PauseText))]
    [NotifyPropertyChangedFor(nameof(PillText))]
    private bool _isPaused;

    /// <summary>True while the newest row is in view (set by the view).</summary>
    [ObservableProperty]
    private bool _isFollowing = true;

    /// <summary>Rows added below the view, or queued by a pause.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasUnseen))]
    [NotifyPropertyChangedFor(nameof(PillText))]
    private int _unseenCount;

    /// <summary>Whether the pill shows.</summary>
    public bool HasUnseen => UnseenCount > 0;

    /// <summary>"12 new events".</summary>
    public string PillText => UnseenCount == 1 ? "1 new event" : $"{UnseenCount:N0} new events";

    /// <summary>Icon of the pause button.</summary>
    public string PauseGlyph => IsPaused ? "" : "";

    /// <summary>Caption of the pause button.</summary>
    public string PauseText => IsPaused ? "Resume" : "Pause";

    /// <summary>Adds a batch from the poller.</summary>
    /// <param name="batch">Events oldest-first, plus how many could not be fetched.</param>
    public void AddEvents(EventBatch batch)
    {
        _everConnected = true;
        var events = batch.Events;

        if (batch.Skipped > 0)
        {
            // Say so in the feed itself, at the place where the rows are missing.
            var notice = new EventDto
            {
                TimestampUtc = events[0].TimestampUtc,
                Level = LogEventLevel.Warning,
                Message = $"{batch.Skipped:N0} older events are not shown: more arrived at once than the service returns in one request.",
            };
            events = [notice, .. events];
            _toasts.Warning("Some events were skipped", $"{batch.Skipped:N0} older events arrived too fast to fetch.");
        }

        if (IsPaused)
        {
            _pending.AddRange(events);
            // One short of the feed's capacity: the notice of what was dropped has to fit in it.
            if (_pending.Count >= MaxEntries)
            {
                var dropped = _pending.Count - MaxEntries + 1;
                _pendingDropped += dropped;
                _pending.RemoveRange(0, dropped);
            }

            UnseenCount = _pending.Count;
            return;
        }

        Append(events);
        UpdateState();
    }

    /// <summary>Adds events in any order; used on the first fill.</summary>
    public void AddEvents(IReadOnlyList<EventDto> events) =>
        AddEvents(new EventBatch(events.OrderBy(dto => dto.Id).ToList(), 0));

    /// <summary>Marks the feed unavailable; rows on hand stay visible.</summary>
    public void SetDisconnected(string reason)
    {
        if (!_everConnected)
        {
            ErrorText = reason;
            State = ViewState.Error;
        }
    }

    /// <summary>Connected: an empty feed is now an answer, not a wait.</summary>
    public void SetConnected()
    {
        _everConnected = true;
        UpdateState();
    }


    /// <summary>Called by the view as the list scrolls.</summary>
    public void SetFollowing(bool following)
    {
        IsFollowing = following;
        if (following && !IsPaused)
        {
            UnseenCount = 0;
        }
    }

    /// <summary>Shows one engine only: used by the dashboard's engine tiles.</summary>
    public void ShowEngine(ProtocolSource source)
    {
        var label = SourceLabels.For(source);
        foreach (var chip in SourceChips)
        {
            chip.Set(chip.Label == label);
        }

        foreach (var chip in LevelChips)
        {
            chip.Set(true);
        }

        SearchText = string.Empty;
        Rebuild();
        ScrollToEndRequested?.Invoke();
    }

    /// <summary>Shows one address across every level and engine: used by the dashboard's alerts.</summary>
    public void ShowAddress(string ip)
    {
        foreach (var chip in LevelChips.Concat(SourceChips))
        {
            chip.Set(true);
        }

        SearchText = ip;
        Rebuild();
        ScrollToEndRequested?.Invoke();
    }

    /// <summary>Shows everything again.</summary>
    [RelayCommand]
    private void ResetFilters()
    {
        foreach (var chip in LevelChips.Concat(SourceChips))
        {
            chip.Set(true);
        }

        SearchText = string.Empty;
        Rebuild();
    }

    /// <summary>Freezes or resumes the tail.</summary>
    [RelayCommand]
    private void TogglePause()
    {
        if (IsPaused)
        {
            Resume();
        }
        else
        {
            IsPaused = true;
        }
    }

    /// <summary>The pill: resumes if paused, and jumps to the newest row.</summary>
    [RelayCommand]
    private void JumpToLatest()
    {
        if (IsPaused)
        {
            Resume();
        }

        UnseenCount = 0;
        ScrollToEndRequested?.Invoke();
    }

    /// <summary>Clears the in-memory feed (the service history is unaffected).</summary>
    [RelayCommand]
    private void Clear()
    {
        _all.Clear();
        _pending.Clear();
        _pendingDropped = 0;
        Events.Clear();
        UnseenCount = 0;
        CountChips();
        UpdateState();
    }

    /// <summary>Copies one line, or the given rows.</summary>
    [RelayCommand]
    private void CopyRow(EventRowViewModel? row)
    {
        if (row is not null)
        {
            Copy(row.CopyText, "Copied the event");
        }
    }

    /// <summary>Copies a row's address.</summary>
    [RelayCommand]
    private void CopyIp(EventRowViewModel? row)
    {
        if (row is { IpAddress.Length: > 0 })
        {
            Copy(row.IpAddress, $"Copied {row.IpAddress}");
        }
    }

    /// <summary>Filters the feed to a row's address.</summary>
    [RelayCommand]
    private void SearchIp(EventRowViewModel? row)
    {
        if (row is { IpAddress.Length: > 0 })
        {
            SearchText = row.IpAddress;
        }
    }

    /// <summary>Exports the rows currently shown to a UTF-8 CSV file.</summary>
    [RelayCommand]
    private void ExportCsv()
    {
        if (Events.Count == 0)
        {
            _toasts.Info("Nothing to export");
            return;
        }

        var dialog = new SaveFileDialog
        {
            Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*",
            FileName = "winguard-events.csv",
            Title = "Export events",
        };

        if (dialog.ShowDialog() != true)
        {
            return;
        }

        try
        {
            File.WriteAllText(dialog.FileName, BuildCsv(Events), new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
            _toasts.Success($"Exported {Events.Count:N0} events", dialog.FileName);
        }
        catch (Exception ex)
        {
            _toasts.Error("Export failed", ex.Message);
        }
    }

    /// <summary>The CSV text of a set of rows.</summary>
    public static string BuildCsv(IEnumerable<EventRowViewModel> rows)
    {
        var builder = new StringBuilder();
        builder.AppendLine("Time(local),Level,Source,IP,Message");
        foreach (var row in rows)
        {
            builder.Append(CsvText.Escape(row.TimeText)).Append(',');
            builder.Append(CsvText.Escape(row.LevelText)).Append(',');
            builder.Append(CsvText.Escape(row.SourceText)).Append(',');
            builder.Append(CsvText.Escape(row.IpAddress)).Append(',');
            builder.Append(CsvText.Escape(row.Message)).AppendLine();
        }

        return builder.ToString();
    }

    partial void OnSearchTextChanged(string value) => Rebuild();

    private void Resume()
    {
        IsPaused = false;
        var queued = _pending.ToList();
        _pending.Clear();
        if (_pendingDropped > 0 && queued.Count > 0)
        {
            // Say so at the place where the rows are missing, as for a gap in the feed itself.
            queued.Insert(0, new EventDto
            {
                TimestampUtc = queued[0].TimestampUtc,
                Level = LogEventLevel.Warning,
                Message = $"{_pendingDropped:N0} events from this pause are not shown: the list holds the newest {MaxEntries:N0}. The service still has them.",
            });
            _pendingDropped = 0;
        }

        Append(queued);
        UnseenCount = 0;
        UpdateState();
        ScrollToEndRequested?.Invoke();
    }

    private void Copy(string text, string done)
    {
        if (ClipboardText.TrySet(text))
        {
            _toasts.Success(done);
        }
        else
        {
            _toasts.Warning("Could not copy", "Another program is holding the clipboard.");
        }
    }

    private void Append(IReadOnlyList<EventDto> events)
    {
        var visibleNew = new List<EventRowViewModel>();
        foreach (var dto in events)
        {
            var key = dto.Id > 0 ? "#" + dto.Id : dto.TimestampUtc.Ticks + "|" + dto.Message;
            if (!_seen.Add(key))
            {
                continue;
            }

            _seenOrder.Enqueue(key);
            while (_seenOrder.Count > MaxEntries * 2)
            {
                _seen.Remove(_seenOrder.Dequeue());
            }

            var row = new EventRowViewModel(dto);
            _all.Add(row);
            if (Matches(row))
            {
                visibleNew.Add(row);
            }
        }

        var dropped = _all.Count > MaxEntries ? _all.GetRange(0, _all.Count - MaxEntries) : null;
        if (dropped is not null)
        {
            _all.RemoveRange(0, dropped.Count);
        }

        if (visibleNew.Count == 0 && dropped is null)
        {
            return;
        }

        if (visibleNew.Count + (dropped?.Count ?? 0) > ResetThreshold)
        {
            Events.ReplaceAll(_all.Where(Matches));
        }
        else
        {
            // Rows that fell off the feed leave the view too, even when a filter hid the newcomers.
            if (dropped is not null)
            {
                var gone = dropped.ToHashSet();
                for (var i = Events.Count - 1; i >= 0; i--)
                {
                    if (gone.Contains(Events[i]))
                    {
                        Events.RemoveAt(i);
                    }
                }
            }

            foreach (var row in visibleNew)
            {
                Events.Add(row);
            }
        }

        if (!IsFollowing)
        {
            UnseenCount += visibleNew.Count;
        }

        CountChips();
    }

    private void Rebuild()
    {
        Events.ReplaceAll(_all.Where(Matches));
        UpdateState();
    }

    private void UpdateState()
    {
        CountText = Events.Count == _all.Count
            ? $"{Events.Count:N0} events"
            : $"{Events.Count:N0} of {_all.Count:N0} events";

        if (Events.Count > 0)
        {
            State = ViewState.Ready;
        }
        else if (_everConnected)
        {
            EmptyTitle = _all.Count == 0 ? "No events yet" : "No matches";
            EmptyText = _all.Count == 0
                ? "Blocks, unblocks and service messages appear here as they happen."
                : "Nothing matches these filters. Turn a chip back on, or clear the search.";
            State = ViewState.Empty;
        }
    }

    private void CountChips()
    {
        foreach (var chip in LevelChips)
        {
            chip.CountText = _all.Count(row => row.LevelText == chip.Label).ToString("N0");
        }

        foreach (var chip in SourceChips)
        {
            chip.CountText = _all.Count(row => row.SourceText == chip.Label).ToString("N0");
        }
    }

    private bool Matches(EventRowViewModel row)
    {
        if (!LevelChips.Any(chip => chip.IsOn && chip.Label == row.LevelText))
        {
            return false;
        }

        if (!SourceChips.Any(chip => chip.IsOn && chip.Label == row.SourceText))
        {
            return false;
        }

        var search = SearchText?.Trim();
        return string.IsNullOrEmpty(search)
            || row.Message.Contains(search, StringComparison.OrdinalIgnoreCase)
            || row.IpAddress.Contains(search, StringComparison.OrdinalIgnoreCase);
    }
}
