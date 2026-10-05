using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace WinGuard.Gui;

/// <summary>
/// Shell window. Closing hides the window to the tray (PLAN.md §9); a real exit is performed by the
/// tray "Exit" command, which sets <see cref="AllowClose"/> before shutting the application down.
/// </summary>
public partial class MainWindow : System.Windows.Window
{
    private const int DwmUseImmersiveDarkMode = 20; // DWMWA_USE_IMMERSIVE_DARK_MODE

    /// <summary>When true the window closes for real instead of hiding to the tray.</summary>
    public bool AllowClose { get; set; }

    /// <summary>Initializes the window.</summary>
    public MainWindow() => InitializeComponent();

    /// <summary>
    /// Asks Windows to draw the title bar dark (or light) so it matches the theme. No effect on
    /// Windows versions without the attribute, or before the window has a handle.
    /// </summary>
    public void SetDarkTitleBar(bool dark)
    {
        try
        {
            var handle = new WindowInteropHelper(this).Handle;
            if (handle == IntPtr.Zero)
            {
                return;
            }

            var value = dark ? 1 : 0;
            _ = DwmSetWindowAttribute(handle, DwmUseImmersiveDarkMode, ref value, sizeof(int));
        }
        catch (Exception)
        {
            // Cosmetic only.
        }
    }

    /// <inheritdoc />
    protected override void OnClosing(CancelEventArgs e)
    {
        if (!AllowClose)
        {
            e.Cancel = true;
            Hide();
            return;
        }

        base.OnClosing(e);
    }

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);
}
