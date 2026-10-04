namespace WinGuard.Core.Model;

/// <summary>Severity of a WinGuard event-log entry.</summary>
public enum LogEventLevel
{
    Info = 0,
    Warning = 1,
    Error = 2,
}

/// <summary>One entry of the WinGuard event feed shown in the GUI.</summary>
public sealed class LogEvent
{
    /// <summary>Store-assigned monotonically increasing id (0 for events not yet persisted).</summary>
    public long Id { get; set; }

    public DateTime TimestampUtc { get; set; }

    public LogEventLevel Level { get; set; } = LogEventLevel.Info;

    /// <summary>Engine that produced the event, when applicable.</summary>
    public ProtocolSource? Source { get; set; }

    /// <summary>Normalized IP the event refers to, when applicable.</summary>
    public string? IpAddress { get; set; }

    public string Message { get; set; } = string.Empty;
}
