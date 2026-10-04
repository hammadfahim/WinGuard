namespace WinGuard.Gui.ViewModels;

/// <summary>Editable row for one custom log source in the Settings DataGrid.</summary>
public sealed class CustomSourceRow
{
    /// <summary>Display name.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Whether the source is active.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>File path or folder+glob.</summary>
    public string PathGlob { get; set; } = string.Empty;

    /// <summary>Regex with named groups <c>ipaddress</c> (required) and <c>username</c> (optional).</summary>
    public string Regex { get; set; } = string.Empty;
}