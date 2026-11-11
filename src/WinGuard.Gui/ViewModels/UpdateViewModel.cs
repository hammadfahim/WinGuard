using System.Diagnostics;
using System.IO;
using System.Net.Http;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using WinGuard.Core.Updates;
using WinGuard.Gui.Services;

namespace WinGuard.Gui.ViewModels;

/// <summary>
/// The "Check for updates" button in the rail. Asks the project's GitHub releases for a newer
/// version, and on request downloads its installer, has it checked (<see cref="UpdateClient"/>)
/// and runs it. Nothing is installed without a click: the check at start only says that a newer
/// version exists. A portable copy has no installer to run, so it is pointed at the release page.
/// </summary>
public sealed partial class UpdateViewModel : ObservableObject, IDisposable
{
    private const string IdleText = "Check for updates";
    private const string InfoGlyph = "";
    private static readonly TimeSpan StartDelay = TimeSpan.FromSeconds(20);

    private readonly ToastCenter _toasts;
    private readonly DialogCenter _dialogs;
    private readonly Func<Task<bool>> _confirmExit;
    private readonly HttpClient _http;
    private readonly UpdateClient _client;
    private readonly CancellationTokenSource _closing = new();

    private UpdateManifest? _available;
    private bool _installing;

    /// <summary>Creates the view-model.</summary>
    /// <param name="toasts">Where results are reported.</param>
    /// <param name="dialogs">Where the offer is made.</param>
    /// <param name="confirmExit">Asks about unsaved settings before the console closes for Setup.</param>
    public UpdateViewModel(ToastCenter toasts, DialogCenter dialogs, Func<Task<bool>> confirmExit)
    {
        _toasts = toasts;
        _dialogs = dialogs;
        _confirmExit = confirmExit;
        _http = UpdateClient.CreateHttpClient(CurrentVersion.ToString(3));
        _client = new UpdateClient(_http);
    }

    /// <summary>Raised once Setup is running: the console has to close so its files can be replaced.</summary>
    public event Action? ExitRequested;

    /// <summary>The version of this console.</summary>
    public static Version CurrentVersion { get; } =
        typeof(UpdateViewModel).Assembly.GetName().Version ?? new Version(0, 0, 0);

    /// <summary>Whether this copy was put there by Setup, which leaves its uninstaller next to it.</summary>
    public static bool IsInstalled => File.Exists(Path.Combine(AppContext.BaseDirectory, "unins000.exe"));

    /// <summary>Caption of the rail button; it carries the state.</summary>
    [ObservableProperty]
    private string _buttonText = IdleText;

    /// <summary>Whether a newer release is known.</summary>
    [ObservableProperty]
    private bool _hasUpdate;

    /// <summary>
    /// Looks for a newer release a little after start, when the user has not turned that off. It
    /// only reports: a failure is silent, and nothing is downloaded.
    /// </summary>
    public async Task CheckAtStartAsync()
    {
        if (!UpdatePreference.CheckAtStart)
        {
            return;
        }

        try
        {
            await Task.Delay(StartDelay, _closing.Token);
            if (_available is null && !CheckCommand.IsRunning && await _client.CheckAsync(CurrentVersion, _closing.Token) is { } manifest)
            {
                Remember(manifest);
                _toasts.Info($"WinGuard {manifest.VersionText} is available", "Choose the update button at the bottom left to install it.");
            }
        }
        catch (Exception ex) when (ex is UpdateException or OperationCanceledException)
        {
            // The button still works; a console that starts offline should not complain about it.
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _closing.Cancel();
        _closing.Dispose();
        _http.Dispose();
    }

    /// <summary>The rail button: check, then offer what was found.</summary>
    [RelayCommand]
    private async Task CheckAsync()
    {
        try
        {
            if (_available is null)
            {
                ButtonText = "Checking...";
                var manifest = await _client.CheckAsync(CurrentVersion, _closing.Token);
                ButtonText = IdleText;
                if (manifest is null)
                {
                    await ShowUpToDateAsync();
                    return;
                }

                Remember(manifest);
            }

            _installing = false;
            await OfferAsync(_available!);
        }
        catch (UpdateException ex)
        {
            _toasts.Error(_installing ? "The update was not installed" : "Could not check for updates", ex.Message);
        }
        catch (OperationCanceledException)
        {
            // The console is closing.
        }
        finally
        {
            ButtonText = _available is null ? IdleText : $"Update to {_available.VersionText}";
        }
    }

    private void Remember(UpdateManifest manifest)
    {
        _available = manifest;
        HasUpdate = true;
        ButtonText = $"Update to {manifest.VersionText}";
    }

    private async Task ShowUpToDateAsync()
    {
        var atStart = UpdatePreference.CheckAtStart;
        var choice = await _dialogs.ShowAsync(new DialogRequest(
            Tone.Protected,
            "WinGuard is up to date",
            $"Version {CurrentVersion.ToString(3)} is the newest release.",
            "OK")
        {
            Glyph = InfoGlyph,
            CancelText = "Close",
            AlternateText = atStart ? "Stop checking at start" : "Check at start",
            Notes =
            [
                atStart
                    ? "This console asks GitHub for a newer release each time it starts. It only tells you; nothing is installed on its own."
                    : "This console does not look for new releases on its own.",
            ],
        });

        if (choice == DialogChoice.Alternate)
        {
            UpdatePreference.CheckAtStart = !atStart;
            _toasts.Info(atStart ? "No more checks at start" : "Checking at start", "Check for updates still works at any time.");
        }
    }

    private async Task OfferAsync(UpdateManifest manifest)
    {
        var releasePage = _client.Source.ReleasePageUrl(manifest.Version);
        var installed = IsInstalled;
        var choice = await _dialogs.ShowAsync(new DialogRequest(
            Tone.Accent,
            $"WinGuard {manifest.VersionText} is available",
            installed
                ? $"This is version {CurrentVersion.ToString(3)}. The installer is downloaded from the project's GitHub releases, checked against the project's signature, and run."
                : $"This is version {CurrentVersion.ToString(3)}, a portable copy. It is not updated from here: download the new version from the release page and replace the files.",
            installed ? "Download and install" : "Copy release link")
        {
            Glyph = InfoGlyph,
            CancelText = "Later",
            AlternateText = installed ? "Copy release link" : string.Empty,
            Items = [releasePage],
            Notes = installed
                ?
                [
                    "The service restarts during the update. Addresses already banned stay blocked in the firewall.",
                    "This console closes and opens again when Setup has finished.",
                ]
                : [],
        });

        if (choice == DialogChoice.Alternate || (choice == DialogChoice.Confirm && !installed))
        {
            if (ClipboardText.TrySet(releasePage))
            {
                _toasts.Success("Link copied", releasePage);
            }
            else
            {
                _toasts.Warning("The link could not be copied", releasePage);
            }
        }
        else if (choice == DialogChoice.Confirm && await _confirmExit())
        {
            await InstallAsync(manifest);
        }
    }

    private async Task InstallAsync(UpdateManifest manifest)
    {
        _installing = true;
        ButtonText = "Downloading 0%";
        var folder = await Task.Run(() => UpdateFolder.Prepare(UpdateFolder.DefaultPath), _closing.Token);
        var progress = new Progress<double>(share => ButtonText = $"Downloading {share:P0}");
        using var package = await _client.DownloadAsync(manifest, folder, progress, _closing.Token);

        ButtonText = "Starting Setup...";
        try
        {
            // /SILENT shows Setup's progress window and its error messages, and asks no questions.
            // /RELAUNCH=1 has it open this console again at the end.
            using var setup = Process.Start(new ProcessStartInfo
            {
                FileName = package.Path,
                Arguments = $"/SILENT /NORESTART /RELAUNCH=1 /LOG=\"{Path.Combine(folder, "setup.log")}\"",
                UseShellExecute = false,
                WorkingDirectory = folder,
            });
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            throw new UpdateException($"Setup could not be started: {ex.Message}", ex);
        }

        ExitRequested?.Invoke();
    }
}
