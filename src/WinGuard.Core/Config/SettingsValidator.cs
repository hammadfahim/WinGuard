using System.Text.RegularExpressions;
using WinGuard.Core.Detection;
using WinGuard.Core.Monitoring;

namespace WinGuard.Core.Config;

/// <summary>
/// Checks settings that <see cref="WinGuardSettings.Normalize"/> cannot silently repair, so the
/// service can refuse an update with a message instead of accepting something that will never work
/// (an invalid regex) or that is unsafe (a network path read by the SYSTEM service).
/// </summary>
public static class SettingsValidator
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(2);

    /// <summary>Returns one message per problem; empty when the settings are acceptable.</summary>
    public static IReadOnlyList<string> Validate(WinGuardSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var errors = new List<string>();

        foreach (var name in settings.Rules?.HoneypotUsernames ?? [])
        {
            if (name?.IndexOfAny(['*', '?']) >= 0)
            {
                errors.Add($"Honeypot user name '{name}': wildcards are not supported; list exact account names.");
            }
        }

        foreach (var source in settings.Ftp?.Sources ?? [])
        {
            if (source is null || string.IsNullOrWhiteSpace(source.Path))
            {
                continue;
            }

            if (!LogFileTailer.IsLocalPath(source.Path))
            {
                errors.Add($"FTP source '{Label(source.Name)}': network (UNC) and device paths are not allowed; use a path on a local drive.");
            }
        }

        foreach (var source in settings.CustomSources ?? [])
        {
            if (source is null)
            {
                continue;
            }

            var label = Label(source.Name);
            if (!string.IsNullOrWhiteSpace(source.PathGlob) && !LogFileTailer.IsLocalPath(source.PathGlob))
            {
                errors.Add($"Custom source '{label}': network (UNC) and device paths are not allowed; use a path on a local drive.");
            }

            if (string.IsNullOrWhiteSpace(source.Regex))
            {
                if (source.Enabled && !string.IsNullOrWhiteSpace(source.PathGlob))
                {
                    errors.Add($"Custom source '{label}': a regex is required.");
                }

                continue;
            }

            try
            {
                var regex = new Regex(source.Regex, RegexOptions.CultureInvariant, RegexTimeout);
                if (regex.GroupNumberFromName("ipaddress") < 0)
                {
                    errors.Add($"Custom source '{label}': the regex must contain a named group (?<ipaddress>...).");
                }
            }
            catch (ArgumentException ex)
            {
                errors.Add($"Custom source '{label}': invalid regex ({ex.Message}).");
            }
        }

        if (!string.IsNullOrWhiteSpace(settings.PrometheusTextfilePath)
            && PrometheusTextfileWriter.PathProblem(settings.PrometheusTextfilePath) is { } textfileProblem)
        {
            errors.Add($"Prometheus textfile: {textfileProblem}");
        }

        if (settings.Notifications?.Syslog is { Enabled: true } syslog)
        {
            if (string.IsNullOrWhiteSpace(syslog.Host))
            {
                errors.Add("Syslog: a host is required.");
            }
            else if (syslog.Host.Any(c => char.IsWhiteSpace(c) || char.IsControl(c)))
            {
                errors.Add("Syslog: the host must be a host name or an address.");
            }
        }

        return errors;
    }

    private static string Label(string? name) => string.IsNullOrWhiteSpace(name) ? "(unnamed)" : name.Trim();
}
