using CommunityToolkit.Mvvm.ComponentModel;
using WinGuard.Core.Ipc;
using WinGuard.Core.Model;

namespace WinGuard.Gui.ViewModels;

/// <summary>
/// Backing model for one protocol tile on the Dashboard (RDP / MS SQL / FTP / Custom). Shows the
/// status reported by <see cref="ServiceStatusDto.Engines"/> and, when the user flips the toggle,
/// invokes the supplied callback to persist the change via UpdateSettings.
/// </summary>
public sealed partial class EngineTileViewModel : ObservableObject
{
    private readonly Func<EngineTileViewModel, bool, Task> _toggleAsync;
    private bool _suppressToggle;

    /// <summary>Creates the tile for one protocol.</summary>
    /// <param name="source">Protocol this tile represents.</param>
    /// <param name="displayName">Human-readable protocol name.</param>
    /// <param name="glyph">Icon.</param>
    /// <param name="settingsSection">The Settings section that configures this engine.</param>
    /// <param name="toggleAsync">Callback invoked when the user flips the enabled toggle.</param>
    public EngineTileViewModel(ProtocolSource source, string displayName, string glyph, string settingsSection, Func<EngineTileViewModel, bool, Task> toggleAsync)
    {
        Source = source;
        Name = displayName;
        Glyph = glyph;
        SettingsSection = settingsSection;
        _toggleAsync = toggleAsync;
    }

    /// <summary>Protocol this tile represents.</summary>
    public ProtocolSource Source { get; }

    /// <summary>Human-readable protocol name.</summary>
    public string Name { get; }

    /// <summary>Icon.</summary>
    public string Glyph { get; }

    /// <summary>The Settings section that configures this engine.</summary>
    public string SettingsSection { get; }

    /// <summary>Whether the engine is enabled in settings.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(RunningText))]
    [NotifyPropertyChangedFor(nameof(Tone))]
    private bool _enabled;

    /// <summary>Whether the engine is currently running.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(RunningText))]
    [NotifyPropertyChangedFor(nameof(Tone))]
    private bool _running;

    /// <summary>Failed logins detected today (local day) for this protocol.</summary>
    [ObservableProperty]
    private int _detectionsToday;

    /// <summary>Active bans attributed to this protocol.</summary>
    [ObservableProperty]
    private int _activeBans;

    /// <summary>Text shown under the tile title.</summary>
    public string RunningText => !Enabled ? "Disabled" : Running ? "Running" : "Stopped";

    /// <summary>What the tile's state means.</summary>
    public Tone Tone => !Enabled ? Tone.Neutral : Running ? Tone.Protected : Tone.Attack;

    /// <summary>What a screen reader announces for the tile.</summary>
    public string AccessibleName => $"{Name}, {RunningText}, {DetectionsToday} detections today, {ActiveBans} active bans. Opens this engine's events.";

    /// <summary>Applies a status snapshot without re-triggering the settings push.</summary>
    /// <param name="status">Engine status from the service.</param>
    public void Update(EngineStatusDto status)
    {
        _suppressToggle = true;
        try
        {
            Enabled = status.Enabled;
            Running = status.Running;
            DetectionsToday = status.DetectionsToday;
            ActiveBans = status.ActiveBans;
        }
        finally
        {
            _suppressToggle = false;
        }

        OnPropertyChanged(nameof(AccessibleName));
    }

    /// <summary>Puts the toggle back without pushing anything (a cancelled or failed change).</summary>
    public void Revert(bool enabled)
    {
        _suppressToggle = true;
        Enabled = enabled;
        _suppressToggle = false;
    }

    partial void OnEnabledChanged(bool value)
    {
        if (_suppressToggle)
        {
            return;
        }

        _ = _toggleAsync(this, value);
    }
}
