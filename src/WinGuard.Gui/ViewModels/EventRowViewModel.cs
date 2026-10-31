using WinGuard.Core.Ipc;
using WinGuard.Core.Model;
using WinGuard.Gui.Services;

namespace WinGuard.Gui.ViewModels;

/// <summary>Presentation wrapper for one <see cref="EventDto"/> in the live event feed.</summary>
public sealed class EventRowViewModel
{
    private const string CompromisePrefix = "POSSIBLE COMPROMISE:";

    /// <summary>Creates a row from the DTO.</summary>
    /// <param name="dto">Event received from the service.</param>
    public EventRowViewModel(EventDto dto)
    {
        Dto = dto;
        IsCompromise = IsCompromiseEvent(dto);
    }

    /// <summary>The underlying DTO.</summary>
    public EventDto Dto { get; }

    /// <summary>A logon that may mean an attacker got in: the most prominent row in the feed.</summary>
    public bool IsCompromise { get; }

    /// <summary>Local timestamp text.</summary>
    public string TimeText => Services.TimeText.Stamp(Dto.TimestampUtc);

    /// <summary>Severity.</summary>
    public LogEventLevel Level => Dto.Level;

    /// <summary>Severity as text.</summary>
    public string LevelText => Dto.Level switch
    {
        LogEventLevel.Error => "Error",
        LogEventLevel.Warning => "Warning",
        _ => "Info",
    };

    /// <summary>What the level column shows. The filters keep going by <see cref="LevelText"/>.</summary>
    public string LevelLabel => IsCompromise ? "Alert" : LevelText;

    /// <summary>Severity as a meaning, so colour and icon stay consistent with the rest of the console.</summary>
    public Tone Tone => IsCompromise ? Tone.Attack : Dto.Level switch
    {
        LogEventLevel.Error => Tone.Attack,
        LogEventLevel.Warning => Tone.Warn,
        _ => Tone.Neutral,
    };

    /// <summary>Severity icon.</summary>
    public string Glyph => Dto.Level switch
    {
        LogEventLevel.Error => "",
        LogEventLevel.Warning => "",
        _ => "",
    };

    /// <summary>Protocol source name, or "System".</summary>
    public string SourceText => Dto.Source is null ? EventLogViewModel.SystemSource : SourceLabels.For(Dto.Source);

    /// <summary>IP address, or an empty string.</summary>
    public string IpAddress => Dto.IpAddress ?? string.Empty;

    /// <summary>Event message.</summary>
    public string Message => Dto.Message;

    /// <summary>The line as plain text, for the clipboard.</summary>
    public string CopyText => string.Join('\t', TimeText, LevelText, SourceText, IpAddress, Message);

    /// <summary>
    /// True for an event recording a new ban. The feed has no structured kind for this, so it follows
    /// the engine's own message prefixes.
    /// </summary>
    public static bool IsBlock(EventDto dto) =>
        dto.Message.StartsWith("BLOCKED ", StringComparison.Ordinal)
        || dto.Message.StartsWith("MANUAL BLOCK ", StringComparison.Ordinal);

    /// <summary>
    /// True for a logon the engine found suspicious. Like <see cref="IsBlock"/> this follows the
    /// engine's message prefix. It starts the message, so an attacker's chosen user name cannot fake it.
    /// </summary>
    public static bool IsCompromiseEvent(EventDto dto) =>
        dto.Message.StartsWith(CompromisePrefix, StringComparison.Ordinal);

    /// <summary>The message of a compromise event without its prefix, as a sentence of its own.</summary>
    public static string CompromiseText(EventDto dto) =>
        IsCompromiseEvent(dto) ? dto.Message[CompromisePrefix.Length..].Trim() : dto.Message;
}
