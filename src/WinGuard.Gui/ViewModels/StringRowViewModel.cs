using CommunityToolkit.Mvvm.ComponentModel;

namespace WinGuard.Gui.ViewModels;

/// <summary>
/// Editable single-line text row used by the settings list editors (ban tiers, RDP exclusions,
/// MSSQL ignore patterns). A class wrapper is needed because raw strings are immutable.
/// </summary>
public sealed partial class StringRowViewModel : ObservableObject
{
    /// <summary>Creates a row with the given initial value.</summary>
    /// <param name="value">Initial text.</param>
    public StringRowViewModel(string value = "") => Value = value;

    /// <summary>The editable text.</summary>
    [ObservableProperty]
    private string _value = string.Empty;
}