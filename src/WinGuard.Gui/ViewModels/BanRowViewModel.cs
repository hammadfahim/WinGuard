using System.Globalization;
using WinGuard.Core.Ipc;

namespace WinGuard.Gui.ViewModels;

/// <summary>Presentation wrapper for one <see cref="BanDto"/> in the Blocked IPs grid.</summary>
public sealed class BanRowViewModel
{
    /// <summary>Creates a row from the DTO.</summary>
    /// <param name="dto">Ban received from the service.</param>
    public BanRowViewModel(BanDto dto) => Dto = dto;

    /// <summary>The underlying DTO.</summary>
    public BanDto Dto { get; }

    /// <summary>Blocked IP address.</summary>
    public string IpAddress => Dto.IpAddress;

    /// <summary>Protocol that triggered the ban.</summary>
    public string SourceText => SourceLabels.For(Dto.Source);

    /// <summary>Ban creation time in local time.</summary>
    public string BannedText => ToLocalText(Dto.BannedAtUtc);

    /// <summary>Expiry in local time, or "permanent".</summary>
    public string ExpiresText => Dto.IsPermanent || Dto.ExpiresUtc == DateTime.MaxValue
        ? "permanent"
        : ToLocalText(Dto.ExpiresUtc);

    /// <summary>Number of threshold crossings.</summary>
    public int OffenseCount => Dto.OffenseCount;

    /// <summary>Free-text note, or an empty string.</summary>
    public string NoteText => Dto.Note ?? string.Empty;

    private static string ToLocalText(DateTime utc)
    {
        if (utc == default || utc == DateTime.MaxValue)
        {
            return utc == DateTime.MaxValue ? "permanent" : string.Empty;
        }

        var value = utc.Kind == DateTimeKind.Utc
            ? utc.ToLocalTime()
            : DateTime.SpecifyKind(utc, DateTimeKind.Utc).ToLocalTime();
        return value.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.CurrentCulture);
    }
}