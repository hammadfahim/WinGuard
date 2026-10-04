using WinGuard.Core.Ipc;
using WinGuard.Core.Model;

namespace WinGuard.Gui.ViewModels;

/// <summary>Presentation wrapper for one <see cref="EventDto"/> in the live event feed.</summary>
public sealed class EventRowViewModel
{
    /// <summary>Creates a row from the DTO.</summary>
    /// <param name="dto">Event received from the service.</param>
    public EventRowViewModel(EventDto dto) => Dto = dto;

    /// <summary>The underlying DTO.</summary>
    public EventDto Dto { get; }

    /// <summary>Timestamp converted to local time.</summary>
    public DateTime TimestampLocal => Dto.TimestampUtc.Kind == DateTimeKind.Utc
        ? Dto.TimestampUtc.ToLocalTime()
        : DateTime.SpecifyKind(Dto.TimestampUtc, DateTimeKind.Utc).ToLocalTime();

    /// <summary>Local timestamp text.</summary>
    public string TimeText => TimestampLocal.ToString("yyyy-MM-dd HH:mm:ss");

    /// <summary>Severity.</summary>
    public LogEventLevel Level => Dto.Level;

    /// <summary>Severity as text.</summary>
    public string LevelText => Dto.Level switch
    {
        LogEventLevel.Error => "Error",
        LogEventLevel.Warning => "Warning",
        _ => "Info",
    };

    /// <summary>Protocol source name, or an empty string.</summary>
    public string SourceText => Dto.Source switch
    {
        ProtocolSource.Rdp => "RDP",
        ProtocolSource.MsSql => "MS SQL",
        ProtocolSource.Ftp => "FTP",
        ProtocolSource.Custom => "Custom",
        _ => string.Empty,
    };

    /// <summary>IP address, or an empty string.</summary>
    public string IpAddress => Dto.IpAddress ?? string.Empty;

    /// <summary>Event message.</summary>
    public string Message => Dto.Message;
}