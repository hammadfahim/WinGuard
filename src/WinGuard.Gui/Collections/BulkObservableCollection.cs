using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;

namespace WinGuard.Gui.Collections;

/// <summary>
/// ObservableCollection with bulk edits. <see cref="ReplaceAll"/> raises a single Reset, for
/// user-driven changes such as a new filter. <see cref="SyncTo"/> makes the smallest set of individual
/// edits instead, for polling: a Reset rebuilds the visible rows, which flickers and can jump the
/// scroll position, so a poll must not raise one.
/// </summary>
public sealed class BulkObservableCollection<T> : ObservableCollection<T>
    where T : class
{
    // Above this many individual edits a single Reset is the cheaper redraw.
    private const int ResetThreshold = 256;

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

    /// <summary>
    /// Makes this collection hold <paramref name="target"/>, in that order, by removing, moving and
    /// inserting only what differs. Items that stay keep their identity, which is what keeps a grid's
    /// selection and scroll position through a refresh. Returns whether anything changed.
    /// </summary>
    public bool SyncTo(IReadOnlyList<T> target)
    {
        if (Items.Count == target.Count)
        {
            var same = true;
            for (var i = 0; i < target.Count; i++)
            {
                if (!ReferenceEquals(Items[i], target[i]))
                {
                    same = false;
                    break;
                }
            }

            if (same)
            {
                return false;
            }
        }

        var wanted = new HashSet<T>(target, ReferenceEqualityComparer.Instance as IEqualityComparer<T>);
        var removals = Items.Count(item => !wanted.Contains(item));
        var insertions = target.Count - (Items.Count - removals);
        if (removals + insertions > ResetThreshold)
        {
            ReplaceAll(target);
            return true;
        }

        for (var i = Items.Count - 1; i >= 0; i--)
        {
            if (!wanted.Contains(Items[i]))
            {
                RemoveAt(i);
            }
        }

        for (var i = 0; i < target.Count; i++)
        {
            if (i < Items.Count && ReferenceEquals(Items[i], target[i]))
            {
                continue;
            }

            var from = -1;
            for (var j = i + 1; j < Items.Count; j++)
            {
                if (ReferenceEquals(Items[j], target[i]))
                {
                    from = j;
                    break;
                }
            }

            if (from >= 0)
            {
                Move(from, i);
            }
            else
            {
                Insert(i, target[i]);
            }
        }

        return true;
    }

    private void RaiseReset()
    {
        OnPropertyChanged(new PropertyChangedEventArgs(nameof(Count)));
        OnPropertyChanged(new PropertyChangedEventArgs("Item[]"));
        OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
    }
}
