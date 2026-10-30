using System.Text.RegularExpressions;
using WinGuard.Core.Detection;

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

        return errors;
    }

    private static string Label(string? name) => string.IsNullOrWhiteSpace(name) ? "(unnamed)" : name.Trim();
}
