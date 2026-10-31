namespace WinGuard.Core.Abstractions;

/// <summary>
/// Optional side of an <see cref="IStore"/> whose files can keep a value after it was overwritten.
/// SQLite does: the old row stays readable in the main file until a checkpoint, and in free pages
/// or the slack of a page after that.
/// </summary>
public interface ISecretScrubbingStore
{
    /// <summary>
    /// Writes a setting that replaces a secret stored in the clear, and removes the old value from
    /// the files as far as that can be done. A failed write throws. A failed clean-up does not: the
    /// new value is stored by then, so it is logged and the caller carries on.
    /// </summary>
    /// <param name="key">Settings key.</param>
    /// <param name="value">The new value.</param>
    /// <param name="ct">Cancellation token.</param>
    Task SetSettingAndScrubAsync(string key, string value, CancellationToken ct = default);
}
