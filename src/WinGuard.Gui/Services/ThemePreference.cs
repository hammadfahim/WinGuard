using System.IO;
using Microsoft.Win32;

namespace WinGuard.Gui.Services;

/// <summary>
/// Resolves the startup theme: the user's saved choice if any, otherwise the Windows
/// "app mode" setting (light/dark). The choice is saved under %LOCALAPPDATA%\WinGuard.
/// </summary>
public static class ThemePreference
{
    private static string FilePath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WinGuard", "theme.txt");

    /// <summary>True when dark should be used at startup.</summary>
    public static bool ResolveDark()
    {
        try
        {
            if (File.Exists(FilePath))
            {
                var saved = File.ReadAllText(FilePath).Trim();
                if (saved.Equals("dark", StringComparison.OrdinalIgnoreCase)) return true;
                if (saved.Equals("light", StringComparison.OrdinalIgnoreCase)) return false;
            }
        }
        catch (Exception)
        {
            // Fall through to the system setting.
        }

        return IsSystemDark();
    }

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

    /// <summary>Persists the user's choice (best effort).</summary>
    public static void Save(bool dark)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.WriteAllText(FilePath, dark ? "dark" : "light");
        }
        catch (Exception)
        {
            // Preference is a convenience only.
        }
    }
}
