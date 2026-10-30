using Microsoft.Extensions.DependencyInjection;
using Microsoft.Win32;
using System.IO;
using System.Windows;
using System.Windows.Threading;
using WinGuard.Core.Ipc;
using WinGuard.Gui.Services;
using WinGuard.Gui.ViewModels;

namespace WinGuard.Gui;

/// <summary>
/// Application entry point. Builds the small object graph in a service container, wires the
/// named-pipe client, the tray icon and the main window, applies the theme and installs global
/// exception handlers (PLAN.md §9). Only one instance runs per session: a second launch brings the
/// first one's window to the front and exits.
/// </summary>
public partial class App : System.Windows.Application
{
    private const string InstanceMutexName = @"Local\WinGuard.Gui.Instance";
    private const string ShowSignalName = @"Local\WinGuard.Gui.Show";

    private PipeClient? _pipeClient;
    private MainViewModel? _mainViewModel;
    private TrayIconService? _trayIcon;
    private MainWindow? _mainWindow;
    private ServiceProvider? _services;
    private Mutex? _instanceMutex;
    private EventWaitHandle? _showSignal;
    private RegisteredWaitHandle? _showSignalWait;
    private ThemeChoice _themeChoice = ThemeChoice.System;
    private bool _currentDark = true;

    /// <inheritdoc />
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        if (!TryBecomeSingleInstance())
        {
            Shutdown();
            return;
        }

        RegisterExceptionHandlers();
        Controls.Motion.ApplyTokens(Resources);
        _themeChoice = ThemePreference.Load();
        ApplyTheme(ThemePreference.ResolveDark(_themeChoice));
        SystemParameters.StaticPropertyChanged += OnSystemParameterChanged;
        SystemEvents.UserPreferenceChanged += OnUserPreferenceChanged;

        var services = new ServiceCollection();
        services.AddSingleton<PipeClient>();
        services.AddSingleton(sp => new MainViewModel(sp.GetRequiredService<PipeClient>(), Dispatcher));
        services.AddSingleton<TrayIconService>();
        services.AddSingleton(sp => new MainWindow { DataContext = sp.GetRequiredService<MainViewModel>() });
        _services = services.BuildServiceProvider();

        _pipeClient = _services.GetRequiredService<PipeClient>();

        _mainViewModel = _services.GetRequiredService<MainViewModel>();
        _mainViewModel.ThemeChoice = _themeChoice;
        _mainViewModel.ThemeChoiceChanged += choice =>
        {
            _themeChoice = choice;
            ThemePreference.Save(choice);
            ApplyTheme(ThemePreference.ResolveDark(choice));
        };

        _mainWindow = _services.GetRequiredService<MainWindow>();
        _mainWindow.SourceInitialized += (_, _) => _mainWindow?.SetDarkTitleBar(_currentDark && !SystemParameters.HighContrast);

        _trayIcon = _services.GetRequiredService<TrayIconService>();
        _trayIcon.ShowRequested += (_, _) => ShowMainWindow();
        _trayIcon.ExitRequested += (_, _) => _ = ExitApplicationAsync();

        // Poll only while the window is actually on screen.
        _mainWindow.IsVisibleChanged += (_, _) => UpdatePolling();
        _mainWindow.StateChanged += (_, _) => UpdatePolling();
        _mainViewModel.Dashboard.PropertyChanged += (_, args) =>
        {
            if (args.PropertyName == nameof(DashboardViewModel.Protection))
            {
                UpdateTray();
            }
        };

        MainWindow = _mainWindow;
        _mainWindow.Show();

        // Started last, after every listener is attached, so the first connection is not missed.
        _pipeClient.Start();

        // If the service is down nothing ever "changes": settle the tray text after a moment.
        var settle = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
        settle.Tick += (_, _) =>
        {
            settle.Stop();
            UpdateTray();
            if (_pipeClient?.IsConnected != true && _mainViewModel is not null)
            {
                _mainViewModel.Dashboard.ConnectionSettled = true;
                _mainViewModel.MarkDisconnected("The WinGuard service is not connected. It will be picked up as soon as it runs.");
            }
        };
        settle.Start();
    }

    /// <inheritdoc />
    protected override void OnExit(ExitEventArgs e)
    {
        SystemParameters.StaticPropertyChanged -= OnSystemParameterChanged;
        SystemEvents.UserPreferenceChanged -= OnUserPreferenceChanged;
        _showSignalWait?.Unregister(null);
        _showSignal?.Dispose();
        _services?.Dispose(); // disposes tray icon, view-model and pipe client
        if (_instanceMutex is not null)
        {
            try
            {
                _instanceMutex.ReleaseMutex();
            }
            catch (ApplicationException)
            {
                // Not owned (second instance that never took it).
            }

            _instanceMutex.Dispose();
        }

        base.OnExit(e);
    }

    /// <summary>
    /// Takes the per-session instance mutex. When another instance already holds it, that instance
    /// is asked to show its window and this one reports false.
    /// </summary>
    private bool TryBecomeSingleInstance()
    {
        try
        {
            var mutex = new Mutex(initiallyOwned: true, InstanceMutexName, out var createdNew);
            if (!createdNew)
            {
                mutex.Dispose();
                try
                {
                    using var signal = EventWaitHandle.OpenExisting(ShowSignalName);
                    signal.Set();
                }
                catch (Exception)
                {
                    // The first instance is still starting or already exiting.
                }

                return false;
            }

            _instanceMutex = mutex;
            _showSignal = new EventWaitHandle(false, EventResetMode.AutoReset, ShowSignalName);
            _showSignalWait = ThreadPool.RegisterWaitForSingleObject(
                _showSignal,
                (_, _) => Dispatcher.BeginInvoke(ShowMainWindow),
                null,
                Timeout.Infinite,
                executeOnlyOnce: false);
            return true;
        }
        catch (Exception)
        {
            // Never let the instance check itself keep the console from starting.
            return true;
        }
    }

    /// <summary>Swaps the active theme resource dictionary.</summary>
    /// <param name="dark">True for the dark theme, false for the light theme.</param>
    public void ApplyTheme(bool dark)
    {
        _currentDark = dark;

        // Windows high-contrast mode always wins so the user's accessibility palette is honored.
        ApplyThemeFile(SystemParameters.HighContrast ? "HighContrast" : dark ? "Dark" : "Light");
        _mainWindow?.SetDarkTitleBar(dark && !SystemParameters.HighContrast);
    }

    /// <summary>Loads one of the theme dictionaries by name (Dark, Light or HighContrast).</summary>
    /// <param name="name">The theme's file name, without extension.</param>
    public void ApplyThemeFile(string name)
    {
        // An absolute pack URI, so this also resolves when another assembly hosts these resources.
        var uri = new Uri($"pack://application:,,,/winguard-gui;component/Themes/{name}.xaml", UriKind.Absolute);
        var theme = new ResourceDictionary { Source = uri };

        var merged = Resources.MergedDictionaries;
        for (var i = merged.Count - 1; i >= 0; i--)
        {
            var source = merged[i].Source?.OriginalString ?? string.Empty;
            if (source.EndsWith("/Dark.xaml", StringComparison.OrdinalIgnoreCase) ||
                source.EndsWith("/Light.xaml", StringComparison.OrdinalIgnoreCase) ||
                source.EndsWith("/HighContrast.xaml", StringComparison.OrdinalIgnoreCase))
            {
                merged.RemoveAt(i);
            }
        }

        merged.Insert(0, theme);
    }

    /// <summary>Follows a Windows light/dark switch while the user's choice is "System".</summary>
    private void OnUserPreferenceChanged(object sender, UserPreferenceChangedEventArgs e)
    {
        if (e.Category == UserPreferenceCategory.General && _themeChoice == ThemeChoice.System)
        {
            Dispatcher.BeginInvoke(() =>
            {
                var dark = ThemePreference.IsSystemDark();
                if (dark != _currentDark)
                {
                    ApplyTheme(dark);
                }
            });
        }
    }

    private void OnSystemParameterChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(SystemParameters.HighContrast))
        {
            Dispatcher.BeginInvoke(() => ApplyTheme(_currentDark));
        }
    }

    private void UpdateTray()
    {
        if (_mainViewModel is { } main)
        {
            _trayIcon?.SetStatus(main.Dashboard.IsConnected, main.Dashboard.Protection.Title);
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

    private async Task ExitApplicationAsync()
    {
        // Unsaved settings get a say first, which needs the window on screen.
        if (_mainViewModel?.Settings.IsDirty == true)
        {
            ShowMainWindow();
            if (!await _mainViewModel.ConfirmExitAsync())
            {
                return;
            }
        }

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