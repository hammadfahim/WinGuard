using System.IO;
using System.Windows;
using System.Windows.Threading;
using WinGuard.Gui.Services;
using WinGuard.Gui.ViewModels;

namespace WinGuard.Gui;

/// <summary>
/// Application entry point. Composes the (small) object graph by hand — no DI container — wires the
/// named-pipe client, the tray icon and the main window, applies the theme and installs global
/// exception handlers (PLAN.md §9).
/// </summary>
public partial class App : System.Windows.Application
{
    private PipeClient? _pipeClient;
    private MainViewModel? _mainViewModel;
    private TrayIconService? _trayIcon;
    private MainWindow? _mainWindow;

    /// <inheritdoc />
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        RegisterExceptionHandlers();
        ApplyTheme(dark: true);

        _pipeClient = new PipeClient();
        _pipeClient.Start();

        _mainViewModel = new MainViewModel(_pipeClient, Dispatcher);
        _mainViewModel.ThemeChanged += ApplyTheme;

        _mainWindow = new MainWindow { DataContext = _mainViewModel };

        _trayIcon = new TrayIconService();
        _trayIcon.ShowRequested += (_, _) => ShowMainWindow();
        _trayIcon.ExitRequested += (_, _) => ExitApplication();

        MainWindow = _mainWindow;
        _mainWindow.Show();
    }

    /// <inheritdoc />
    protected override void OnExit(ExitEventArgs e)
    {
        _trayIcon?.Dispose();
        _pipeClient?.Dispose();
        _mainViewModel?.Dispose();
        base.OnExit(e);
    }

    /// <summary>Swaps the active theme resource dictionary (Dark.xaml / Light.xaml).</summary>
    /// <param name="dark">True for the dark theme, false for the light theme.</param>
    public void ApplyTheme(bool dark)
    {
        var uri = new Uri(dark ? "Themes/Dark.xaml" : "Themes/Light.xaml", UriKind.Relative);
        var theme = new ResourceDictionary { Source = uri };

        var merged = Resources.MergedDictionaries;
        for (var i = merged.Count - 1; i >= 0; i--)
        {
            var source = merged[i].Source?.OriginalString ?? string.Empty;
            if (source.Contains("Themes/Dark.xaml", StringComparison.OrdinalIgnoreCase) ||
                source.Contains("Themes/Light.xaml", StringComparison.OrdinalIgnoreCase))
            {
                merged.RemoveAt(i);
            }
        }

        merged.Insert(0, theme);
    }

    private void ShowMainWindow()
    {
        if (_mainWindow is null)
        {
            return;
        }

        _mainWindow.Show();
        if (_mainWindow.WindowState == WindowState.Minimized)
        {
            _mainWindow.WindowState = WindowState.Normal;
        }

        _mainWindow.Activate();
    }

    private void ExitApplication()
    {
        if (_mainWindow is not null)
        {
            _mainWindow.AllowClose = true;
        }

        Shutdown();
    }

    private void RegisterExceptionHandlers()
    {
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
        AppDomain.CurrentDomain.UnhandledException += OnDomainUnhandledException;
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        LogError("DispatcherUnhandledException", e.Exception);
        System.Windows.MessageBox.Show(
            "WinGuard encountered an unexpected error:\n\n" + e.Exception.Message,
            "WinGuard",
            MessageBoxButton.OK,
            MessageBoxImage.Error);
        e.Handled = true;
    }

    private void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        LogError("UnobservedTaskException", e.Exception);
        e.SetObserved();
    }

    private void OnDomainUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        if (e.ExceptionObject is Exception exception)
        {
            LogError("UnhandledException", exception);
        }
        else
        {
            LogError("UnhandledException", new Exception(e.ExceptionObject?.ToString() ?? "Unknown error"));
        }
    }

    private static void LogError(string origin, Exception exception)
    {
        try
        {
            var folder = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "WinGuard");
            Directory.CreateDirectory(folder);
            var line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {origin}: {exception}{Environment.NewLine}";
            File.AppendAllText(Path.Combine(folder, "gui-error.log"), line);
        }
        catch
        {
            // Logging must never throw.
        }
    }
}