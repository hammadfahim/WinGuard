using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using WinGuard.Gui.ViewModels;

namespace WinGuard.Gui.Services;

/// <summary>How a dialog was answered.</summary>
public enum DialogChoice
{
    /// <summary>Dismissed; nothing should happen.</summary>
    Cancel,

    /// <summary>The primary action.</summary>
    Confirm,

    /// <summary>The optional middle action.</summary>
    Alternate,
}

/// <summary>Content of one confirmation.</summary>
public sealed partial class DialogRequest
{
    private readonly TaskCompletionSource<DialogChoice> _answer = new();

    /// <summary>Creates a request.</summary>
    /// <param name="tone">Attack marks a destructive action.</param>
    /// <param name="title">The question.</param>
    /// <param name="message">What will happen, in plain words.</param>
    /// <param name="confirmText">Label of the primary button, naming the action.</param>
    public DialogRequest(Tone tone, string title, string message, string confirmText)
    {
        Tone = tone;
        Title = title;
        Message = message;
        ConfirmText = confirmText;
    }

    /// <summary>Attack marks a destructive action.</summary>
    public Tone Tone { get; }

    /// <summary>The question.</summary>
    public string Title { get; }

    /// <summary>What will happen, in plain words.</summary>
    public string Message { get; }

    /// <summary>Label of the primary button.</summary>
    public string ConfirmText { get; }

    /// <summary>Label of the cancel button.</summary>
    public string CancelText { get; init; } = "Cancel";

    /// <summary>Label of an optional middle button; empty hides it.</summary>
    public string AlternateText { get; init; } = string.Empty;

    /// <summary>Exactly what the action touches.</summary>
    public IReadOnlyList<string> Items { get; init; } = [];

    /// <summary>Short notes such as "2 are permanent bans".</summary>
    public IReadOnlyList<string> Notes { get; init; } = [];

    /// <summary>"and 12 more", when <see cref="Items"/> was cut short.</summary>
    public string MoreText { get; init; } = string.Empty;

    /// <summary>The answer, once given.</summary>
    public Task<DialogChoice> Answer => _answer.Task;

    /// <summary>Whether the primary button should be styled as destructive.</summary>
    public bool IsDestructive => Tone == Tone.Attack;

    [RelayCommand]
    private void Confirm() => _answer.TrySetResult(DialogChoice.Confirm);

    [RelayCommand]
    private void Alternate() => _answer.TrySetResult(DialogChoice.Alternate);

    [RelayCommand]
    private void Cancel() => _answer.TrySetResult(DialogChoice.Cancel);
}

/// <summary>
/// Shows confirmations as an in-app overlay. View-models await <see cref="ShowAsync"/> and never touch
/// a window, which keeps every destructive flow testable and every dialog on-theme.
/// </summary>
public sealed partial class DialogCenter : ObservableObject
{
    private const int MaxListed = 8;

    private readonly Queue<DialogRequest> _waiting = new();

    /// <summary>The dialog on screen, or null.</summary>
    [ObservableProperty]
    private DialogRequest? _current;

    /// <summary>Shows a dialog and waits for its answer. Dialogs queue, so one never replaces another.</summary>
    public async Task<DialogChoice> ShowAsync(DialogRequest request)
    {
        if (Current is null)
        {
            Current = request;
        }
        else
        {
            _waiting.Enqueue(request);
        }

        var choice = await request.Answer.ConfigureAwait(true);
        Current = _waiting.Count > 0 ? _waiting.Dequeue() : null;
        return choice;
    }

    /// <summary>Asks a yes/no question about a list of targets.</summary>
    public async Task<bool> ConfirmAsync(Tone tone, string title, string message, string confirmText, IReadOnlyCollection<string>? targets = null, IReadOnlyList<string>? notes = null)
    {
        var list = targets ?? [];
        var request = new DialogRequest(tone, title, message, confirmText)
        {
            Items = list.Take(MaxListed).ToList(),
            MoreText = list.Count > MaxListed ? $"and {list.Count - MaxListed:N0} more" : string.Empty,
            Notes = notes ?? [],
        };
        return await ShowAsync(request).ConfigureAwait(true) == DialogChoice.Confirm;
    }
}
