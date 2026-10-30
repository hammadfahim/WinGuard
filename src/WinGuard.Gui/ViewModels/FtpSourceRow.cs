using CommunityToolkit.Mvvm.ComponentModel;
using WinGuard.Core.Config;

namespace WinGuard.Gui.ViewModels;

/// <summary>Editable row for one FTP log source.</summary>
public sealed partial class FtpSourceRow : ObservableObject
{
    private readonly Action _changed;

    /// <summary>Creates a row.</summary>
    /// <param name="changed">Called on every edit.</param>
    public FtpSourceRow(Action changed) => _changed = changed;

    /// <summary>Display name.</summary>
    [ObservableProperty]
    private string _name = string.Empty;

    /// <summary>IIS FTP or FileZilla.</summary>
    [ObservableProperty]
    private FtpServerKind _kind = FtpServerKind.IisFtp;

    /// <summary>IIS log folder, or FileZilla file/folder.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PathError))]
    [NotifyPropertyChangedFor(nameof(HasError))]
    private string _path = string.Empty;

    /// <summary>Why the path is refused.</summary>
    public string PathError => SettingChecks.PathError(Path);

    /// <summary>Whether the row is invalid.</summary>
    public bool HasError => PathError.Length > 0;

    partial void OnNameChanged(string value) => _changed();

    partial void OnKindChanged(FtpServerKind value) => _changed();

    partial void OnPathChanged(string value) => _changed();
}
