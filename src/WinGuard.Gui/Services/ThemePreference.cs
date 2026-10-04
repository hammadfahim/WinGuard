using System.IO;
using Microsoft.Win32;

namespace WinGuard.Gui.Services;

/// <summary>Which theme the user asked for.</summary>
public enum ThemeChoice
{
    /// <summary>Follow the Windows app-mode setting (and keep following it when it changes).</summary>
    System,

    /// <summary>Always light.</summary>
    Light,

    /// <summary>Always dark.</summary>
    Dark,
}

/// <summary>
/// Loads and saves the user's theme choice under %LOCALAPPDATA%\WinGuard and resolves it against
/// the Windows "app mode" setting.
/// </summary>
public static class ThemePreference
{
    private static string FilePath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WinGuard", "theme.txt");

    /// <summary>The saved choice; <see cref="ThemeChoice.System"/> when nothing was saved.</summary>
    public static ThemeChoice Load()
    {
        try
        {
            if (File.Exists(FilePath) && Enum.TryParse<ThemeChoice>(File.ReadAllText(FilePath).Trim(), ignoreCase: true, out var choice))
            {
                return choice;
            }
        }
        catch (Exception)
        {
            // Fall through to the default.
        }

        return ThemeChoice.System;
    }

    /// <summary>Persists the choice (best effort).</summary>
    public static void Save(ThemeChoice choice)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.WriteAllText(FilePath, choice.ToString().ToLowerInvariant());
        }
        catch (Exception)
        {
            // Preference is a convenience only.
        }
    }

    /// <summary>True when the choice means dark right now.</summary>
    public static bool ResolveDark(ThemeChoice choice) => choice switch
    {
        ThemeChoice.Dark => true,
        ThemeChoice.Light => false,
        _ => IsSystemDark(),
    };

    /// <summary>Reads the Windows app-mode setting; defaults to dark when unreadable.</summary>
    public static bool IsSystemDark()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return key?.GetValue("AppsUseLightTheme") is int light ? light == 0 : true;
        }
        catch (Exception)
        {
            return true;
        }
    }
}
