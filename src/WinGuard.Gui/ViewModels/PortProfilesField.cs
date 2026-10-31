using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using WinGuard.Core.Config;
using WinGuard.Core.Model;

namespace WinGuard.Gui.ViewModels;

/// <summary>A ready-made port list offered as one click.</summary>
/// <param name="Label">What the button says.</param>
/// <param name="Ports">The list it stores.</param>
/// <param name="Note">Something to know once it is chosen.</param>
public sealed record PortChoice(string Label, string[] Ports, string? Note);

/// <summary>What one engine's bans block, with its effect spelled out.</summary>
public sealed partial class PortProfileRow : ObservableObject
{
    private readonly Action _changed;

    /// <summary>Creates a row.</summary>
    /// <param name="title">The engine.</param>
    /// <param name="changed">Called on every edit.</param>
    public PortProfileRow(string title, Action changed)
    {
        _title = title;
        _changed = changed;
    }

    /// <summary>The engine.</summary>
    [ObservableProperty]
    private string _title;

    /// <summary>The list as typed. Empty follows the global list.</summary>
    [ObservableProperty]
    private string _text = string.Empty;

    /// <summary>The validation message.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasError))]
    private string _error = string.Empty;

    /// <summary>"All ports", or which ports.</summary>
    [ObservableProperty]
    private string _effectLabel = "All ports";

    /// <summary>All ports reads as safe, anything narrower as a choice to look at.</summary>
    [ObservableProperty]
    private Tone _effectTone = Tone.Protected;

    /// <summary>What that means.</summary>
    [ObservableProperty]
    private string _effectText = string.Empty;

    /// <summary>What the chosen preset wants known.</summary>
    [ObservableProperty]
    private string _note = string.Empty;

    /// <summary>The one-click lists.</summary>
    [ObservableProperty]
    private IReadOnlyList<PortChoice> _presets = [];

    /// <summary>Caption of the button that clears the row.</summary>
    [ObservableProperty]
    private string _defaultLabel = "All ports (default)";

    /// <summary>Whether the row is invalid.</summary>
    public bool HasError => Error.Length > 0;

    /// <summary>The list to store.</summary>
    public string[] Values => SettingChecks.SplitPorts(Text);

    /// <summary>Re-reads what this row blocks.</summary>
    /// <param name="global">The global list, which an empty row follows.</param>
    /// <param name="presets">The current one-click lists.</param>
    /// <param name="alsoBlocked">What is blocked along with a list of this row's own.</param>
    public void Refresh(PortSet global, IReadOnlyList<PortChoice> presets, string? alsoBlocked = null)
    {
        Presets = presets;
        DefaultLabel = global.IsAll ? "All ports (default)" : "Use the global list";

        var own = PortSet.Parse(Values);
        var effective = own.IsAll ? global : PortSet.Parse([.. Values, alsoBlocked ?? string.Empty]);
        EffectTone = effective.IsAll ? Tone.Protected : Tone.Warn;
        EffectLabel = effective.IsAll ? "All ports" : "Only " + Shorten(effective);
        EffectText = (own.IsAll, effective.IsAll) switch
        {
            (true, true) => "Default: a banned address reaches nothing on this server.",
            (true, false) => "Follows the global list. Every other port stays reachable from a banned address.",
            _ => "Every other port stays reachable from a banned address.",
        };
        Note = presets.FirstOrDefault(preset => !own.IsAll && PortSet.Parse(preset.Ports).Equals(own))?.Note ?? string.Empty;
    }

    partial void OnTextChanged(string value)
    {
        Error = SettingChecks.PortsError(value) ?? string.Empty;
        _changed();
    }

    private static string Shorten(PortSet ports) => ports.Tokens.Count <= 4
        ? string.Join(", ", ports.Tokens)
        : $"{string.Join(", ", ports.Tokens.Take(3))} and {ports.Tokens.Count - 3:N0} more";

    /// <summary>Stores a one-click list.</summary>
    [RelayCommand]
    private void ApplyPreset(PortChoice? choice)
    {
        if (choice is not null)
        {
            Text = string.Join(", ", choice.Ports);
        }
    }

    /// <summary>Clears the row, which gives it the default.</summary>
    [RelayCommand]
    private void UseDefault() => Text = string.Empty;
}

/// <summary>
/// One port list per engine and per custom source. The custom rows live on their sources, so a source
/// added or renamed in its own section shows up here by itself.
/// </summary>
public sealed class PortProfilesField : SettingField
{
    private readonly TextField _global;
    private readonly TextField _passiveRange;
    private readonly CustomSourcesField _custom;

    /// <summary>Creates the editor.</summary>
    /// <param name="global">The global list, which an empty row follows.</param>
    /// <param name="passiveRange">The FTP passive range, blocked along with an FTP list.</param>
    /// <param name="custom">The custom sources.</param>
    public PortProfilesField(TextField global, TextField passiveRange, CustomSourcesField custom)
        : base("Ports per engine", "Leave a row empty to follow the global list above. Blocking always covers TCP and UDP.")
    {
        _global = global;
        _passiveRange = passiveRange;
        _custom = custom;
        Rdp = new PortProfileRow(SourceLabels.Rdp, RaiseChanged);
        MsSql = new PortProfileRow(SourceLabels.MsSql, RaiseChanged);
        Ftp = new PortProfileRow(SourceLabels.Ftp, RaiseChanged);
        custom.Rows.CollectionChanged += (_, _) => Rebuild();
        Rebuild();
    }

    /// <summary>The RDP and logon engine.</summary>
    public PortProfileRow Rdp { get; }

    /// <summary>The MS SQL engine.</summary>
    public PortProfileRow MsSql { get; }

    /// <summary>The FTP engine.</summary>
    public PortProfileRow Ftp { get; }

    /// <summary>The rows, engines first.</summary>
    public ObservableCollection<PortProfileRow> Rows { get; } = [];

    /// <inheritdoc />
    public override bool HasError => Rows.Any(row => row.HasError);

    /// <inheritdoc />
    public override string Snapshot => string.Join('\n', Rows.Select(row => string.Join(',', row.Values)));

    /// <summary>Re-reads what every row blocks, after anything it depends on changed.</summary>
    public void Refresh()
    {
        var global = PortSet.Parse(SettingChecks.SplitPorts(_global.Text));
        var passive = _passiveRange.Value;

        // Asked only for what the FTP preset needs: the rest comes from this machine.
        var settings = new WinGuardSettings { Ftp = { PassivePortRange = passive } };
        var presets = PortPresets.All(settings)
            .Select(preset => new PortChoice($"{preset.Name} {string.Join(", ", preset.Ports)}", preset.Ports, preset.Note))
            .ToList();

        foreach (var row in Rows)
        {
            row.Refresh(global, presets, ReferenceEquals(row, Ftp) ? passive : null);
        }
    }

    private void Rebuild()
    {
        Rows.Clear();
        Rows.Add(Rdp);
        Rows.Add(MsSql);
        Rows.Add(Ftp);
        foreach (var source in _custom.Rows)
        {
            Rows.Add(source.Ports);
        }

        Refresh();
    }
}
