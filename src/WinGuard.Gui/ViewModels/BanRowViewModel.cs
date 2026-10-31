using CommunityToolkit.Mvvm.ComponentModel;
using WinGuard.Core.Ipc;
using WinGuard.Gui.Services;

namespace WinGuard.Gui.ViewModels;

/// <summary>
/// Presentation wrapper for one <see cref="BanDto"/> in the Blocked IPs grid. A row lives as long as
/// its ban: polling updates it in place, so the grid keeps its selection and scroll position.
/// </summary>
public sealed partial class BanRowViewModel : ObservableObject
{
    private BanDto _dto;
    private IpShape _shape;
    private UInt128 _ipSortKey;

    /// <summary>Creates a row from the DTO.</summary>
    /// <param name="dto">Ban received from the service.</param>
    public BanRowViewModel(BanDto dto)
    {
        _dto = dto;
        _shape = IpText.Shape(dto.IpAddress);
        _ipSortKey = IpText.SortKey(dto.IpAddress);
    }

    /// <summary>The underlying DTO.</summary>
    public BanDto Dto => _dto;

    /// <summary>The ban target: one address, or a whole prefix such as 2001:db8:1:2::/64.</summary>
    public string IpAddress => _dto.IpAddress;

    /// <summary>True when this row bans a range, not a single address.</summary>
    public bool IsPrefix => _shape.IsRange;

    /// <summary>Family and prefix: IPv4, IPv6, IPv6 /64.</summary>
    public string KindText => IpText.KindLabel(_shape);

    /// <summary>Numeric ordering key for the address column.</summary>
    public UInt128 IpSortKey => _ipSortKey;

    /// <summary>Tooltip for the address column.</summary>
    public string IpToolTip => _shape.IsRange
        ? $"{IpAddress}: a whole prefix, {IpText.CoverageLabel(_shape)}"
        : IpAddress;

    /// <summary>Protocol that triggered the ban.</summary>
    public string SourceText => SourceLabels.For(_dto.Source);

    /// <summary>True while the ban blocks every port, the default.</summary>
    public bool IsAllPorts => string.IsNullOrEmpty(_dto.Ports);

    /// <summary>The ports this ban blocks: "All ports", or the list.</summary>
    public string PortsText => IsAllPorts ? "All ports" : _dto.Ports.Replace(",", ", ", StringComparison.Ordinal);

    /// <summary>What the ban blocks and leaves open, in a sentence, for the row details.</summary>
    public string PortsDetail => IsAllPorts
        ? "All ports: this address reaches nothing on this server."
        : $"Only {PortsText}, TCP and UDP. Every other service on this server stays reachable from this address.";

    /// <summary>When the ban started, in local time.</summary>
    public string BannedText => TimeText.Stamp(_dto.BannedAtUtc);

    /// <summary>When the ban started, as UTC.</summary>
    public DateTime BannedUtc => TimeText.AsUtc(_dto.BannedAtUtc);

    /// <summary>True for a ban that never expires.</summary>
    public bool IsPermanent => _dto.IsPermanent || _dto.ExpiresUtc == DateTime.MaxValue;

    /// <summary>Expiry in local time, or "permanent".</summary>
    public string ExpiresText => IsPermanent ? "permanent" : TimeText.Stamp(_dto.ExpiresUtc);

    /// <summary>Orders permanent bans after every timed one.</summary>
    public DateTime ExpiresSortKey => IsPermanent ? DateTime.MaxValue : TimeText.AsUtc(_dto.ExpiresUtc);

    /// <summary>The live countdown.</summary>
    public string CountdownText => IsPermanent ? "Permanent" : TimeText.Countdown(ExpiresSortKey - DateTime.UtcNow);

    /// <summary>Tooltip of the expiry column.</summary>
    public string ExpiresToolTip => IsPermanent ? "Never expires" : "Expires " + TimeText.Full(_dto.ExpiresUtc);

    /// <summary>Number of threshold crossings.</summary>
    public int OffenseCount => _dto.OffenseCount;

    /// <summary>Free-text note, or an empty string.</summary>
    public string NoteText => _dto.Note ?? string.Empty;

    /// <summary>Applies a fresh DTO; returns whether a sortable or shown value changed.</summary>
    public bool Update(BanDto dto)
    {
        if (Same(_dto, dto))
        {
            return false;
        }

        _dto = dto;
        _shape = IpText.Shape(dto.IpAddress);
        _ipSortKey = IpText.SortKey(dto.IpAddress);
        OnPropertyChanged(string.Empty);
        return true;
    }

    /// <summary>Re-reads the countdown. Only rows on screen are bound, so this costs nothing for the rest.</summary>
    public void Tick()
    {
        if (!IsPermanent)
        {
            OnPropertyChanged(nameof(CountdownText));
        }
    }

    private static bool Same(BanDto a, BanDto b) =>
        a.IpAddress == b.IpAddress && a.Source == b.Source && a.BannedAtUtc == b.BannedAtUtc
        && a.ExpiresUtc == b.ExpiresUtc && a.OffenseCount == b.OffenseCount
        && a.IsPermanent == b.IsPermanent && a.Note == b.Note && a.Ports == b.Ports;
}
