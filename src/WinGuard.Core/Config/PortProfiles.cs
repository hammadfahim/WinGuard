using WinGuard.Core.Detection;
using WinGuard.Core.Model;

namespace WinGuard.Core.Config;

/// <summary>
/// Turns a ban's port scope into the ports it blocks. A scope names engines rather than ports, so
/// changing a profile changes what the active bans of that engine block: reconcile rewrites them.
/// <para>
/// The text in <see cref="BanEntry.PortScope"/> is one of: <see langword="null"/> (a ban from before
/// profiles existed, which follows <see cref="WinGuardSettings.BlockedPorts"/>), <see cref="AllPorts"/>
/// (manual and blacklist bans), or one engine per line. An engine without a profile uses
/// <see cref="WinGuardSettings.BlockedPorts"/>, and when that is empty as well it blocks every port.
/// </para>
/// </summary>
public static class PortProfiles
{
    /// <summary>The scope of a ban that blocks every port whatever the settings say.</summary>
    public const string AllPorts = "*";

    private const char Separator = '\n';
    private const string CustomPrefix = "Custom:";

    // Stands for the global list in a widened older ban, which has no engine of its own.
    private const string GlobalScope = "Global";

    /// <summary>The scope of a ban issued by one engine; <paramref name="detector"/> tells custom sources apart.</summary>
    public static string ScopeFor(ProtocolSource source, string? detector) => source == ProtocolSource.Custom
        ? CustomPrefix + CustomName(detector)
        : source.ToString();

    /// <summary>
    /// A scope that also covers <paramref name="engineScope"/>. It only ever grows: a ban blocking
    /// every port keeps doing so, and an older ban keeps following the global list too.
    /// </summary>
    public static string Widen(string? scope, string engineScope)
    {
        if (scope == AllPorts)
        {
            return AllPorts;
        }

        var engines = Engines(scope).Append(engineScope).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal);
        return string.Join(Separator, engines);
    }

    /// <summary>The ports a ban of this scope blocks under the given settings.</summary>
    public static PortSet Resolve(string? scope, WinGuardSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (scope == AllPorts)
        {
            return PortSet.All;
        }

        PortSet? ports = null;
        foreach (var engine in Engines(scope))
        {
            var own = PortsOf(engine, settings);
            if (own.IsAll)
            {
                return PortSet.All;
            }

            ports = ports is null ? own : ports.Union(own);
        }

        return ports ?? PortSet.All;
    }

    private static IEnumerable<string> Engines(string? scope) =>
        string.IsNullOrEmpty(scope) ? [GlobalScope] : scope.Split(Separator, StringSplitOptions.RemoveEmptyEntries);

    private static PortSet PortsOf(string engine, WinGuardSettings settings)
    {
        var profile = ProfileOf(engine, settings);
        return PortSet.Parse(profile.Length > 0 ? profile : settings.BlockedPorts);
    }

    private static string[] ProfileOf(string engine, WinGuardSettings settings)
    {
        if (engine == nameof(ProtocolSource.Rdp))
        {
            return settings.Rdp.BlockedPorts;
        }

        if (engine == nameof(ProtocolSource.MsSql))
        {
            return settings.MsSql.BlockedPorts;
        }

        if (engine == nameof(ProtocolSource.Ftp))
        {
            // Passive data connections are part of FTP once FTP has a profile at all.
            return settings.Ftp.BlockedPorts.Length > 0 && settings.Ftp.PassivePortRange.Length > 0
                ? [.. settings.Ftp.BlockedPorts, settings.Ftp.PassivePortRange]
                : settings.Ftp.BlockedPorts;
        }

        if (engine.StartsWith(CustomPrefix, StringComparison.Ordinal))
        {
            // Sources that share a name are one engine to the detector, so they share a profile. A
            // source deleted since the ban has no profile, which falls back to the global setting.
            var name = engine[CustomPrefix.Length..];
            return settings.CustomSources
                .Where(source => source is not null && string.Equals(CustomName(source.Name), name, StringComparison.OrdinalIgnoreCase))
                .SelectMany(source => source.BlockedPorts)
                .ToArray();
        }

        return [];
    }

    /// <summary>The name <see cref="CustomLogDetector"/> reports for a source, safe to keep on one line.</summary>
    private static string CustomName(string? name) => string.IsNullOrWhiteSpace(name)
        ? CustomLogDetector.DefaultDetectorName
        : name.ReplaceLineEndings(" ");
}
