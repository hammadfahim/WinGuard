using System.Drawing;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace WinGuard.Gui.Services;

/// <summary>
/// Owns the system-tray <see cref="NotifyIcon"/> (PLAN.md §9). The icon is drawn at runtime with
/// <c>System.Drawing</c> — a blue shield with a white "W" — so no binary asset is committed.
/// Double-click (or the Show menu item) raises <see cref="ShowRequested"/>; Exit raises
/// <see cref="ExitRequested"/>. The HICON handle is destroyed on dispose.
/// </summary>
public sealed class TrayIconService : IDisposable
{
    private readonly NotifyIcon _notifyIcon;
    private readonly Icon _icon;
    private readonly IntPtr _iconHandle;
    private readonly Icon _offlineIcon;
    private readonly IntPtr _offlineHandle;
    private bool _disposed;

    /// <summary>Raised when the user asks to show the main window.</summary>
    public event EventHandler? ShowRequested;

    /// <summary>Raised when the user asks to fully exit the application.</summary>
    public event EventHandler? ExitRequested;

    /// <summary>Creates the tray icon and its context menu on the current (UI) thread.</summary>
    public TrayIconService()
    {
        _iconHandle = CreateShieldIconHandle(Color.FromArgb(59, 130, 246));
        _icon = Icon.FromHandle(_iconHandle);
        _offlineHandle = CreateShieldIconHandle(Color.FromArgb(120, 120, 130));
        _offlineIcon = Icon.FromHandle(_offlineHandle);

        var menu = new ContextMenuStrip();
        var showItem = new ToolStripMenuItem("Show WinGuard");
        showItem.Click += (_, _) => ShowRequested?.Invoke(this, EventArgs.Empty);
        var exitItem = new ToolStripMenuItem("Exit");
        exitItem.Click += (_, _) => ExitRequested?.Invoke(this, EventArgs.Empty);
        menu.Items.Add(showItem);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(exitItem);

        // Grey until the first connection is confirmed.
        _notifyIcon = new NotifyIcon
        {
            Icon = _offlineIcon,
            Visible = true,
            Text = "WinGuard - connecting...",
            ContextMenuStrip = menu,
        };
        _notifyIcon.DoubleClick += (_, _) => ShowRequested?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>Switches the icon and tooltip between connected (blue) and service-offline (grey).</summary>
    public void SetConnected(bool connected)
    {
        if (_disposed)
        {
            return;
        }

        _notifyIcon.Icon = connected ? _icon : _offlineIcon;
        _notifyIcon.Text = connected ? "WinGuard - protecting" : "WinGuard - service not running";
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
        DestroyIcon(_iconHandle);
        _offlineIcon.Dispose();
        DestroyIcon(_offlineHandle);
    }

    private static IntPtr CreateShieldIconHandle(Color fill)
    {
        using var bitmap = new Bitmap(32, 32);
        using (var graphics = Graphics.FromImage(bitmap))
        {
            graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            graphics.Clear(Color.Transparent);

            using var shield = new System.Drawing.Drawing2D.GraphicsPath();
            shield.AddLines(new[]
            {
                new Point(16, 2),
                new Point(28, 7),
                new Point(28, 17),
                new Point(16, 30),
                new Point(4, 17),
                new Point(4, 7),
            });
            shield.CloseFigure();
            using var shieldBrush = new SolidBrush(fill);
            graphics.FillPath(shieldBrush, shield);

            using var font = new Font("Segoe UI", 11f, FontStyle.Bold, GraphicsUnit.Pixel);
            using var textBrush = new SolidBrush(Color.White);
            using var format = new StringFormat
            {
                Alignment = StringAlignment.Center,
                LineAlignment = StringAlignment.Center,
            };
            graphics.DrawString("W", font, textBrush, new RectangleF(0, 3, 32, 24), format);
        }

        return bitmap.GetHicon();
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr hIcon);
}