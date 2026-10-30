using System.Runtime.InteropServices;
using System.Windows;

namespace WinGuard.Gui.Services;

/// <summary>Clipboard access that survives contention, which is routine over RDP.</summary>
public static class ClipboardText
{
    /// <summary>Copies text; returns false when the clipboard stayed locked by another process.</summary>
    public static bool TrySet(string text)
    {
        for (var attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                Clipboard.SetDataObject(text, copy: true);
                return true;
            }
            catch (COMException)
            {
                Thread.Sleep(30);
            }
            catch (ExternalException)
            {
                Thread.Sleep(30);
            }
        }

        return false;
    }

    /// <summary>Reads text; empty when there is none or the clipboard stayed locked.</summary>
    public static string Get()
    {
        for (var attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                return Clipboard.ContainsText() ? Clipboard.GetText() : string.Empty;
            }
            catch (COMException)
            {
                Thread.Sleep(30);
            }
            catch (ExternalException)
            {
                Thread.Sleep(30);
            }
        }

        return string.Empty;
    }
}
