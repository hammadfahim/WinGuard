using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.Input;
using WinGuard.Gui.ViewModels;

namespace WinGuard.Gui.Services;

/// <summary>One in-app notification.</summary>
public sealed class ToastItem
{
    /// <summary>Creates a toast.</summary>
    public ToastItem(Tone tone, string glyph, string title, string message, DateTime expiresUtc)
    {
        Tone = tone;
        Glyph = glyph;
        Title = title;
        Message = message;
        ExpiresUtc = expiresUtc;
    }

    /// <summary>What the toast means.</summary>
    public Tone Tone { get; }

    /// <summary>Icon, so the meaning never rests on colour alone.</summary>
    public string Glyph { get; }

    /// <summary>Headline.</summary>
    public string Title { get; }

    /// <summary>Detail; may be empty.</summary>
    public string Message { get; }

    /// <summary>When it leaves on its own.</summary>
    public DateTime ExpiresUtc { get; }
}

/// <summary>
/// The console's feedback channel: the result of an action appears here instead of in a status line
/// per page. Pure apart from the collection the shell binds to; the shell's clock calls <see cref="Prune"/>.
/// </summary>
public sealed partial class ToastCenter
{
    private const int MaxVisible = 4;

    /// <summary>Visible toasts, oldest first.</summary>
    public ObservableCollection<ToastItem> Items { get; } = [];

    /// <summary>Reports success.</summary>
    public void Success(string title, string message = "") =>
        Add(Tone.Protected, "", title, message, TimeSpan.FromSeconds(4));

    /// <summary>Reports something neutral.</summary>
    public void Info(string title, string message = "") =>
        Add(Tone.Accent, "", title, message, TimeSpan.FromSeconds(5));

    /// <summary>Reports something that needs attention.</summary>
    public void Warning(string title, string message = "") =>
        Add(Tone.Warn, "", title, message, TimeSpan.FromSeconds(8));

    /// <summary>Reports a failure; these stay longest because they carry the reason.</summary>
    public void Error(string title, string message = "") =>
        Add(Tone.Attack, "", title, message, TimeSpan.FromSeconds(12));

    /// <summary>Removes toasts whose time is up.</summary>
    public void Prune(DateTime nowUtc)
    {
        for (var i = Items.Count - 1; i >= 0; i--)
        {
            if (Items[i].ExpiresUtc <= nowUtc)
            {
                Items.RemoveAt(i);
            }
        }
    }

    [RelayCommand]
    private void Dismiss(ToastItem? item)
    {
        if (item is not null)
        {
            Items.Remove(item);
        }
    }

    private void Add(Tone tone, string glyph, string title, string message, TimeSpan lifetime)
    {
        // A repeated failure (say, one per poll) must not stack up identical toasts.
        if (Items.Any(item => item.Title == title && item.Message == message))
        {
            return;
        }

        Items.Add(new ToastItem(tone, glyph, title, message, DateTime.UtcNow + lifetime));
        while (Items.Count > MaxVisible)
        {
            Items.RemoveAt(0);
        }
    }
}
