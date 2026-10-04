using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;

namespace WinGuard.Gui.Collections;

/// <summary>
/// ObservableCollection with bulk edits that raise a single Reset notification instead of one
/// event per item, so the UI re-renders once per batch.
/// </summary>
public sealed class BulkObservableCollection<T> : ObservableCollection<T>
{
    /// <summary>Replaces the whole content with <paramref name="items"/> (one notification).</summary>
    public void ReplaceAll(IEnumerable<T> items)
    {
        Items.Clear();
        foreach (var item in items)
        {
            Items.Add(item);
        }

        RaiseReset();
    }

    /// <summary>Appends items and drops the oldest so at most <paramref name="max"/> remain (one notification).</summary>
    public void AddRangeCapped(IEnumerable<T> items, int max)
    {
        var added = false;
        foreach (var item in items)
        {
            Items.Add(item);
            added = true;
        }

        if (Items.Count > max)
        {
            var excess = Items.Count - max;
            if (Items is List<T> list)
            {
                list.RemoveRange(0, excess);
            }

            added = true;
        }

        if (added)
        {
            RaiseReset();
        }
    }

    private void RaiseReset()
    {
        OnPropertyChanged(new PropertyChangedEventArgs(nameof(Count)));
        OnPropertyChanged(new PropertyChangedEventArgs("Item[]"));
        OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
    }
}
