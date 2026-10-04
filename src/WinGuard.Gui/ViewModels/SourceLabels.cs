using WinGuard.Core.Model;

namespace WinGuard.Gui.ViewModels;

/// <summary>
/// Display names for the detection engines, shared by every view so filters and rows agree.
/// The Windows engine is labelled "RDP / logon": it watches Security event 4625, which also
/// covers failed SMB and other network logons, not only Remote Desktop.
/// </summary>
public static class SourceLabels
{
    /// <summary>Label for the Windows logon engine.</summary>
    public const string Rdp = "RDP / logon";

    /// <summary>Label for the SQL Server engine.</summary>
    public const string MsSql = "MS SQL";

    /// <summary>Label for the FTP engine.</summary>
    public const string Ftp = "FTP";

    /// <summary>Label for custom log sources.</summary>
    public const string Custom = "Custom";

    /// <summary>The label for a source, or an empty string when there is none.</summary>
    public static string For(ProtocolSource? source) => source switch
    {
        ProtocolSource.Rdp => Rdp,
        ProtocolSource.MsSql => MsSql,
        ProtocolSource.Ftp => Ftp,
        ProtocolSource.Custom => Custom,
        _ => string.Empty,
    };
}
