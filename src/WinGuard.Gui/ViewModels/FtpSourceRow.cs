using WinGuard.Core.Config;

namespace WinGuard.Gui.ViewModels;

/// <summary>Editable row for one FTP log source in the Settings DataGrid.</summary>
public sealed class FtpSourceRow
{
    /// <summary>Display name.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>IIS FTP or FileZilla.</summary>
    public FtpServerKind Kind { get; set; } = FtpServerKind.IisFtp;

    /// <summary>IIS log folder, or FileZilla file/folder.</summary>
    public string Path { get; set; } = string.Empty;
}