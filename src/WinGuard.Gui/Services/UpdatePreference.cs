using System.IO;

namespace WinGuard.Gui.Services;

/// <summary>
/// Whether the console looks for a newer release when it starts. Kept per user under
/// %LOCALAPPDATA%\WinGuard, next to the theme choice; on unless the user turned it off.
/// </summary>
public static class UpdatePreference
{
    private static string FilePath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WinGuard", "update-check.txt");

    /// <summary>Gets or sets the choice. Saving is best effort.</summary>
    public static bool CheckAtStart
    {
        get
        {
            try
            {
                return !File.Exists(FilePath) || !string.Equals(File.ReadAllText(FilePath).Trim(), "off", StringComparison.OrdinalIgnoreCase);
            }
            catch (Exception)
            {
                return true;
            }
        }

        set
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
                File.WriteAllText(FilePath, value ? "on" : "off");
            }
            catch (Exception)
            {
                // A convenience only.
            }
        }
    }
}
