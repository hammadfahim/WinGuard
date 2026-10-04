using System.ComponentModel;
using System.Windows;

namespace WinGuard.Gui;

/// <summary>
/// Shell window. Closing hides the window to the tray (PLAN.md §9); a real exit is performed by the
/// tray "Exit" command, which sets <see cref="AllowClose"/> before shutting the application down.
/// </summary>
public partial class MainWindow : System.Windows.Window
{
    /// <summary>When true the window closes for real instead of hiding to the tray.</summary>
    public bool AllowClose { get; set; }

    /// <summary>Initializes the window.</summary>
    public MainWindow() => InitializeComponent();

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
}