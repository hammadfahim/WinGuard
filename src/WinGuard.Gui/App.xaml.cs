using Microsoft.Extensions.DependencyInjection;
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
    private ServiceProvider? _services;
    private bool _currentDark = true;

    /// <inheritdoc />
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        RegisterExceptionHandlers();
        var startDark = ThemePreference.ResolveDark();
        ApplyTheme(startDark);
        SystemParameters.StaticPropertyChanged += OnSystemParameterChanged;

        var services = new ServiceCollection();
        services.AddSingleton<PipeClient>();
        services.AddSingleton(sp => new MainViewModel(sp.GetRequiredService<PipeClient>(), Dispatcher));
        services.AddSingleton<TrayIconService>();
        services.AddSingleton(sp => new MainWindow { DataContext = sp.GetRequiredService<MainViewModel>() });
        _services = services.BuildServiceProvider();

        _pipeClient = _services.GetRequiredService<PipeClient>();
        _pipeClient.Start();

        _mainViewModel = _services.GetRequiredService<MainViewModel>();
        _mainViewModel.IsDarkTheme = startDark;
        _mainViewModel.ThemeChanged += dark =>
        {
            ApplyTheme(dark);
            ThemePreference.Save(dark);
        };

        _mainWindow = _services.GetRequiredService<MainWindow>();

        _trayIcon = _services.GetRequiredService<TrayIconService>();
        _trayIcon.ShowRequested += (_, _) => ShowMainWindow();
        _trayIcon.ExitRequested += (_, _) => ExitApplication();

        // Poll only while the window is actually on screen.
        _mainWindow.IsVisibleChanged += (_, _) => UpdatePolling();
        _mainWindow.StateChanged += (_, _) => UpdatePolling();
        _pipeClient.StateChanged += connected => Dispatcher.BeginInvoke(() => _trayIcon?.SetConnected(connected));

        MainWindow = _mainWindow;
        _mainWindow.Show();
    }

    /// <inheritdoc />
    protected override void OnExit(ExitEventArgs e)
    {
        SystemParameters.StaticPropertyChanged -= OnSystemParameterChanged;
        _services?.Dispose(); // disposes tray icon, view-model and pipe client
        base.OnExit(e);
    }

    /// <summary>Swaps the active theme resource dictionary (Dark.xaml / Light.xaml).</summary>
    /// <param name="dark">True for the dark theme, false for the light theme.</param>
    public void ApplyTheme(bool dark)
    {
        _currentDark = dark;

        // Windows high-contrast mode always wins so the user's accessibility palette is honored.
        var themeFile = SystemParameters.HighContrast ? "Themes/HighContrast.xaml" : dark ? "Themes/Dark.xaml" : "Themes/Light.xaml";
        var uri = new Uri(themeFile, UriKind.Relative);
        var theme = new ResourceDictionary { Source = uri };

        var merged = Resources.MergedDictionaries;
        for (var i = merged.Count - 1; i >= 0; i--)
        {
            var source = merged[i].Source?.OriginalString ?? string.Empty;
            if (source.Contains("Themes/Dark.xaml", StringComparison.OrdinalIgnoreCase) ||
                source.Contains("Themes/Light.xaml", StringComparison.OrdinalIgnoreCase) ||
                source.Contains("Themes/HighContrast.xaml", StringComparison.OrdinalIgnoreCase))
            {
                merged.RemoveAt(i);
            }
        }

        merged.Insert(0, theme);
    }

    private void OnSystemParameterChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(SystemParameters.HighContrast))
        {
            Dispatcher.BeginInvoke(() => ApplyTheme(_currentDark));
        }
    }

    private void UpdatePolling()
    {
        if (_mainWindow is null || _mainViewModel is null)
        {
            return;
        }

        _mainViewModel.SetWindowActive(_mainWindow.IsVisible && _mainWindow.WindowState != WindowState.Minimized);
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