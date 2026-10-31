using System.Globalization;
using System.Security;
using Microsoft.Win32;
using WinGuard.Core.Model;

namespace WinGuard.Core.Config;

/// <summary>A ready-made port list for an engine's <see cref="ProtocolSettings.BlockedPorts"/>.</summary>
/// <param name="Name">What the preset is for, as shown to an administrator.</param>
/// <param name="Ports">The list to store. Blocking always covers TCP and UDP.</param>
/// <param name="Note">Something the administrator has to know or decide, or <see langword="null"/>.</param>
public sealed record PortPreset(string Name, string[] Ports, string? Note = null);

/// <summary>
/// Common port lists for the settings UI. They only suggest: nothing is applied until an
/// administrator stores one in a profile.
/// </summary>
public static class PortPresets
{
    private const int DefaultRdpPort = 3389;
    private const string RdpRegistryKey = @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";
    private const string RdpRegistryValue = "PortNumber";

    /// <summary>Every preset. FTP takes its passive range from <see cref="FtpSettings.PassivePortRange"/>.</summary>
    public static IReadOnlyList<PortPreset> All(WinGuardSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        return [Rdp(), MsSql(), Ftp(settings.Ftp.PassivePortRange), Ssh()];
    }

    /// <summary>RDP on the port this machine really listens on, TCP and UDP.</summary>
    public static PortPreset Rdp() => Rdp(ReadRdpPort());

    /// <summary>MS SQL Server's default instance.</summary>
    public static PortPreset MsSql() => new(
        "MS SQL",
        ["1433"],
        "A named instance usually listens on a dynamic port: add it if yours does.");

    /// <summary>
    /// The FTP control port, plus the passive range when one is given. Nothing is assumed when it
    /// is not: every FTP server picks its own range, so the preset says it is missing instead.
    /// </summary>
    /// <param name="passiveRange">The server's passive data range, e.g. <c>50000-50100</c>.</param>
    public static PortPreset Ftp(string? passiveRange)
    {
        if (string.IsNullOrWhiteSpace(passiveRange))
        {
            return new PortPreset(
                "FTP",
                ["21"],
                "No passive range is set, so a banned client can still reach passive data connections.");
        }

        return PortSet.TryParseRange(passiveRange, out _, out _)
            ? new PortPreset("FTP", ["21", passiveRange.Trim()])
            : new PortPreset("FTP", ["21"], $"'{passiveRange.Trim()}' is not a port range, so it was left out.");
    }

    /// <summary>OpenSSH.</summary>
    public static PortPreset Ssh() => new("SSH", ["22"]);

    /// <summary>The port in the RDP listener's registry key, or <see langword="null"/> when it cannot be read.</summary>
    public static int? ReadRdpPort()
    {
        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RdpRegistryKey, writable: false);
            return ParseRdpPort(key?.GetValue(RdpRegistryValue));
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or IOException)
        {
            return null;
        }
    }

    internal static PortPreset Rdp(int? listeningPort) => listeningPort is { } port
        ? new PortPreset("RDP", [port.ToString(CultureInfo.InvariantCulture)])
        : new PortPreset(
            "RDP",
            [DefaultRdpPort.ToString(CultureInfo.InvariantCulture)],
            $"Could not read the listening port, so this is the default {DefaultRdpPort}.");

    /// <summary>A registry DWORD holding a usable port number, or <see langword="null"/>.</summary>
    internal static int? ParseRdpPort(object? value) => value is int port && port is > 0 and <= ushort.MaxValue ? port : null;
}
