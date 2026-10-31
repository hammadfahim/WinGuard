using System.Drawing;
using System.Windows.Forms;

namespace WinGuard.Gui.Services;

/// <summary>
/// Owns the system-tray <see cref="NotifyIcon"/> (PLAN.md §9). The icons are embedded in the program
/// (tools/IconGen draws them) and differ in shape as well as colour: a solid shield with a keyhole,
/// a hollow one, and a red one with an exclamation mark. Double-click (or the Show menu item) raises
/// <see cref="ShowRequested"/>; Exit raises <see cref="ExitRequested"/>.
/// </summary>
public sealed class TrayIconService : IDisposable
{
    private readonly NotifyIcon _notifyIcon;
    private readonly Icon _icon = LoadIcon("tray-protected.ico");
    private readonly Icon _offlineIcon = LoadIcon("tray-offline.ico");
    private readonly Icon _alertIcon = LoadIcon("tray-alert.ico");
    private bool _disposed;

    /// <summary>Raised when the user asks to show the main window.</summary>
    public event EventHandler? ShowRequested;

    /// <summary>Raised when the user asks to fully exit the application.</summary>
    public event EventHandler? ExitRequested;

    /// <summary>Creates the tray icon and its context menu on the current (UI) thread.</summary>
    public TrayIconService()
    {
        var menu = new ContextMenuStrip();
        var showItem = new ToolStripMenuItem("Show WinGuard");
        showItem.Click += (_, _) => ShowRequested?.Invoke(this, EventArgs.Empty);
        var exitItem = new ToolStripMenuItem("Exit");
        exitItem.Click += (_, _) => ExitRequested?.Invoke(this, EventArgs.Empty);
        menu.Items.Add(showItem);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(exitItem);

        // Hollow until the first connection is confirmed.
        _notifyIcon = new NotifyIcon
        {
            Icon = _offlineIcon,
            Visible = true,
            Text = "WinGuard - connecting...",
            ContextMenuStrip = menu,
        };
        _notifyIcon.DoubleClick += (_, _) => ShowRequested?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Shows the console's overall state: the solid icon while connected, the hollow one otherwise,
    /// and the red one while bans have no effect, with the same words as the banner, so the tray
    /// never says "protecting" while nothing is being enforced.
    /// </summary>
    /// <param name="connected">Whether the service is answering.</param>
    /// <param name="status">The state in words.</param>
    /// <param name="notEnforcing">Bans are doing nothing right now, which outranks the connection.</param>
    public void SetStatus(bool connected, string status, bool notEnforcing = false)
    {
        if (_disposed)
        {
            return;
        }

        _notifyIcon.Icon = notEnforcing ? _alertIcon : connected ? _icon : _offlineIcon;
        _notifyIcon.Text = "WinGuard - " + status;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _notifyIcon.Visible = false;
        _notifyIcon.Dispose();
        _icon.Dispose();
        _offlineIcon.Dispose();
        _alertIcon.Dispose();
    }

    /// <summary>Loads the frame for this display's tray size, so the icon stays sharp at any scaling.</summary>
    private static Icon LoadIcon(string name)
    {
        using var stream = typeof(TrayIconService).Assembly.GetManifestResourceStream(name)
            ?? throw new InvalidOperationException($"The tray icon '{name}' is missing from the program.");
        return new Icon(stream, SystemInformation.SmallIconSize);
    }
}
