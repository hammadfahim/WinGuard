using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace WinGuard.Core.Detection;

/// <summary>
/// The event-log provider names of the SQL Server instances installed on this machine: the default
/// instance logs as <c>MSSQLSERVER</c>, a named one as <c>MSSQL$NAME</c>. The list is kept for
/// <see cref="RefreshInterval"/>, because an event storm must not turn into a registry storm, and
/// read again after that, so an instance installed later is noticed without a restart. The registry
/// is only ever read.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class SqlServerInstances
{
    /// <summary>How long a reading of the installed instances stays good.</summary>
    internal static readonly TimeSpan RefreshInterval = TimeSpan.FromMinutes(5);

    private const string InstanceNamesKey = @"SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL";
    private const string DefaultInstance = "MSSQLSERVER";

    private static readonly IReadOnlySet<string> None = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    private readonly Func<IReadOnlySet<string>> _read;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger _logger;
    private readonly object _lock = new();
    private IReadOnlySet<string> _current = None;
    private DateTimeOffset _nextReadUtc = DateTimeOffset.MinValue;

    /// <summary>Creates the cache.</summary>
    /// <param name="read">Reads the provider names; tests pass their own.</param>
    /// <param name="timeProvider">Clock for <see cref="RefreshInterval"/>.</param>
    /// <param name="logger">Diagnostic logger.</param>
    internal SqlServerInstances(Func<IReadOnlySet<string>> read, TimeProvider timeProvider, ILogger logger)
    {
        _read = read;
        _timeProvider = timeProvider;
        _logger = logger;
    }

    /// <summary>
    /// The provider names as of the last reading. A reading that fails keeps the previous list: an
    /// instance does not vanish because the registry could not be read, and until a first reading
    /// succeeds nothing counts as SQL Server.
    /// </summary>
    internal IReadOnlySet<string> Current
    {
        get
        {
            lock (_lock)
            {
                var now = _timeProvider.GetUtcNow();
                if (now < _nextReadUtc)
                {
                    return _current;
                }

                _nextReadUtc = now + RefreshInterval;
                try
                {
                    var read = _read();
                    if (!read.SetEquals(_current))
                    {
                        _logger.LogInformation(
                            "SQL Server instances on this machine: {Instances}.",
                            read.Count == 0 ? "none, so 18456 events are ignored" : string.Join(", ", read));
                    }

                    _current = read;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Could not read the installed SQL Server instances; keeping the last known list.");
                }

                return _current;
            }
        }
    }

    /// <summary>
    /// Reads the instance names from the registry, in both views: a 32-bit SQL Server on 64-bit
    /// Windows registers under Wow6432Node. A machine without SQL Server has no such key.
    /// </summary>
    public static IReadOnlySet<string> ReadInstalledProviders()
    {
        var instanceNames = new List<string>();
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var hive = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using var key = hive.OpenSubKey(InstanceNamesKey, writable: false);
            if (key is not null)
            {
                instanceNames.AddRange(key.GetValueNames());
            }
        }

        return ToProviderNames(instanceNames);
    }

    /// <summary>Turns instance names, as the registry holds them, into event-log provider names.</summary>
    internal static IReadOnlySet<string> ToProviderNames(IEnumerable<string> instanceNames)
    {
        var providers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in instanceNames)
        {
            if (!string.IsNullOrWhiteSpace(name))
            {
                providers.Add(string.Equals(name, DefaultInstance, StringComparison.OrdinalIgnoreCase) ? DefaultInstance : "MSSQL$" + name);
            }
        }

        return providers;
    }
}
