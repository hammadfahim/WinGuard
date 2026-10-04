using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using WinGuard.Core.Ipc;

namespace WinGuard.Gui.ViewModels;

/// <summary>
/// Event Log view-model (PLAN.md §9.3): a live, capped (1000-entry) feed with level and source
/// filters. The view auto-scrolls to the newest row while the user is already at the bottom.
/// </summary>
public sealed partial class EventLogViewModel : ObservableObject
{
    private const int MaxEntries = 1000;

    private readonly List<EventRowViewModel> _all = [];
    private readonly HashSet<string> _seen = [];
    private readonly Queue<string> _seenOrder = [];

    /// <summary>Rows currently visible after filtering, oldest first.</summary>
    public ObservableCollection<EventRowViewModel> Events { get; } = [];

    /// <summary>Available level filter options.</summary>
    public ObservableCollection<string> LevelFilters { get; } = ["All", "Info", "Warning", "Error"];

    /// <summary>Available source filter options.</summary>
    public ObservableCollection<string> SourceFilters { get; } = ["All", "RDP", "MS SQL", "FTP", "Custom"];

    /// <summary>Selected level filter.</summary>
    [ObservableProperty]
    private string _selectedLevelFilter = "All";

    /// <summary>Selected source filter.</summary>
    [ObservableProperty]
    private string _selectedSourceFilter = "All";

    /// <summary>Number of entries currently shown.</summary>
    [ObservableProperty]
    private int _visibleCount;

    /// <summary>When true, the view keeps the newest row in sight.</summary>
    [ObservableProperty]
    private bool _autoScroll = true;

    /// <summary>Appends newly received events (newest-first input), deduplicating and capping.</summary>
    /// <param name="events">Events from the poller.</param>
    public void AddEvents(IReadOnlyList<EventDto> events)
    {
        foreach (var dto in events.Reverse())
        {
            var key = dto.TimestampUtc.Ticks.ToString() + "|" + dto.Message;
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
            if (_all.Count > MaxEntries)
            {
                _all.RemoveAt(0);
            }

            if (Matches(row))
            {
                Events.Add(row);
            }
        }

        while (Events.Count > MaxEntries)
        {
            Events.RemoveAt(0);
        }

        VisibleCount = Events.Count;
    }

    partial void OnSelectedLevelFilterChanged(string value) => Rebuild();

    partial void OnSelectedSourceFilterChanged(string value) => Rebuild();

    /// <summary>Clears the in-memory feed (the service history is unaffected).</summary>
    [RelayCommand]
    private void Clear()
    {
        _all.Clear();
        _seen.Clear();
        _seenOrder.Clear();
        Events.Clear();
        VisibleCount = 0;
    }

    private void Rebuild()
    {
        Events.Clear();
        foreach (var row in _all)
        {
            if (Matches(row))
            {
                Events.Add(row);
            }
        }

        VisibleCount = Events.Count;
    }

    private bool Matches(EventRowViewModel row)
    {
        if (SelectedLevelFilter != "All" && row.LevelText != SelectedLevelFilter)
        {
            return false;
        }

        if (SelectedSourceFilter != "All" && row.SourceText != SelectedSourceFilter)
        {
            return false;
        }

        return true;
    }
}