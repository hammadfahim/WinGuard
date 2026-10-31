using CommunityToolkit.Mvvm.ComponentModel;
using WinGuard.Core.Config;

namespace WinGuard.Gui.ViewModels;

/// <summary>Editable row for one FTP log source.</summary>
public sealed partial class FtpSourceRow : ObservableObject
{
    private readonly Action _changed;
    private readonly FtpLogSource? _origin;

    /// <summary>Creates a row.</summary>
    /// <param name="changed">Called on every edit.</param>
    /// <param name="origin">The source this row edits; null for a new one.</param>
    public FtpSourceRow(Action changed, FtpLogSource? origin = null)
    {
        _changed = changed;
        _origin = origin;
    }

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

    /// <summary>The source to save: what was loaded, with this row's edits on top.</summary>
    public FtpLogSource ToSource()
    {
        var source = _origin is null ? new FtpLogSource() : SettingChecks.Copy(_origin);
        source.Name = Name.Trim();
        source.Kind = Kind;
        source.Path = Path.Trim();
        return source;
    }

    partial void OnNameChanged(string value) => _changed();

    partial void OnKindChanged(FtpServerKind value) => _changed();

    partial void OnPathChanged(string value) => _changed();
}
