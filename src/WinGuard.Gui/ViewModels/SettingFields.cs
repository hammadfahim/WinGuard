using System.Collections.ObjectModel;
using System.Globalization;
using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using WinGuard.Core.Config;
using WinGuard.Core.Detection;
using WinGuard.Core.Model;
using WinGuard.Gui.Services;

namespace WinGuard.Gui.ViewModels;

/// <summary>
/// One row of the Settings page. Every field validates itself on each change, knows whether it differs
/// from what was loaded, and answers the search box, so the page is a list of fields rather than a
/// wall of bespoke XAML.
/// </summary>
public abstract partial class SettingField : ObservableObject
{
    private string _clean = string.Empty;

    /// <summary>Creates a field.</summary>
    protected SettingField(string label, string help)
    {
        Label = label;
        Help = help;
    }

    /// <summary>Raised on every edit.</summary>
    public event Action? Changed;

    /// <summary>The name of the setting.</summary>
    public string Label { get; }

    /// <summary>What it does.</summary>
    public string Help { get; }

    /// <summary>Whether the search box leaves this field visible.</summary>
    [ObservableProperty]
    private bool _isShown = true;

    /// <summary>The current validation message; empty when valid.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasError))]
    private string _error = string.Empty;

    /// <summary>Whether the field is invalid.</summary>
    public virtual bool HasError => Error.Length > 0;

    /// <summary>Everything the user can edit here, as one string, for change detection.</summary>
    public abstract string Snapshot { get; }

    /// <summary>Whether the value differs from what was loaded.</summary>
    public bool IsDirty => Snapshot != _clean;

    /// <summary>Records the current value as the loaded one.</summary>
    public void MarkClean() => _clean = Snapshot;

    /// <summary>Whether the search text matches.</summary>
    public virtual bool Matches(string query) =>
        Label.Contains(query, StringComparison.OrdinalIgnoreCase) || Help.Contains(query, StringComparison.OrdinalIgnoreCase);

    /// <summary>Tells the page something changed.</summary>
    protected void RaiseChanged() => Changed?.Invoke();
}

/// <summary>A switch.</summary>
public sealed partial class ToggleField : SettingField
{
    /// <summary>Creates a switch.</summary>
    public ToggleField(string label, string help, string warningWhenOn = "")
        : base(label, help)
    {
        WarningWhenOn = warningWhenOn;
    }

    /// <summary>The caution shown while the switch is on.</summary>
    public string WarningWhenOn { get; }

    /// <summary>The value.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowWarning))]
    private bool _isOn;

    /// <summary>Whether the caution shows.</summary>
    public bool ShowWarning => IsOn && WarningWhenOn.Length > 0;

    /// <inheritdoc />
    public override string Snapshot => IsOn ? "1" : "0";

    partial void OnIsOnChanged(bool value) => RaiseChanged();
}

/// <summary>Free text with an optional check.</summary>
public partial class TextField : SettingField
{
    private readonly Func<string, string?>? _validate;

    /// <summary>Creates a text field.</summary>
    public TextField(string label, string help, string placeholder = "", Func<string, string?>? validate = null)
        : base(label, help)
    {
        Placeholder = placeholder;
        _validate = validate;
    }

    /// <summary>Hint shown while empty.</summary>
    public string Placeholder { get; set; }

    /// <summary>The value.</summary>
    [ObservableProperty]
    private string _text = string.Empty;

    /// <inheritdoc />
    public override string Snapshot => Text;

    /// <summary>The trimmed value.</summary>
    public string Value => Text.Trim();

    /// <summary>Checks the value again, for a check that depends on another field.</summary>
    public void Revalidate() => Error = Validate(Text) ?? string.Empty;

    partial void OnTextChanged(string value)
    {
        Error = Validate(value) ?? string.Empty;
        OnTextEdited();
        RaiseChanged();
    }

    /// <summary>Checks a value; returns the message, or null when it is fine.</summary>
    protected virtual string? Validate(string value) => _validate?.Invoke(value.Trim());

    /// <summary>Lets a subclass refresh what it derives from the text.</summary>
    protected virtual void OnTextEdited()
    {
    }
}

/// <summary>A masked secret. Masked so an RDP recording or a shoulder does not capture it.</summary>
public sealed class SecretField : TextField
{
    /// <summary>Creates a secret field.</summary>
    public SecretField(string label, string help)
        : base(label, help)
    {
    }
}

/// <summary>A whole number within a range.</summary>
public sealed class NumberField : TextField
{
    private readonly int _min;
    private readonly int _max;
    private readonly bool _optional;
    private readonly Func<int, string?>? _check;

    /// <summary>Creates a number field.</summary>
    /// <param name="label">The name of the setting.</param>
    /// <param name="help">What it does.</param>
    /// <param name="min">Lowest accepted value.</param>
    /// <param name="max">Highest accepted value.</param>
    /// <param name="optional">Whether empty is allowed, meaning "use the global value".</param>
    /// <param name="placeholder">Hint shown while empty.</param>
    /// <param name="check">A further check on a number within the range.</param>
    public NumberField(string label, string help, int min, int max, bool optional = false, string placeholder = "", Func<int, string?>? check = null)
        : base(label, help, placeholder)
    {
        _min = min;
        _max = max;
        _optional = optional;
        _check = check;
    }

    /// <summary>The parsed value; null when empty or invalid.</summary>
    public int? Number => int.TryParse(Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) ? value : null;

    /// <summary>Sets the value from a number.</summary>
    public void Set(int? value) => Text = value?.ToString(CultureInfo.InvariantCulture) ?? string.Empty;

    /// <inheritdoc />
    protected override string? Validate(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return _optional ? null : "Required.";
        }

        return int.TryParse(value.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var number) && number >= _min && number <= _max
            ? _check?.Invoke(number)
            : $"Enter a whole number from {_min:N0} to {_max:N0}.";
    }
}

/// <summary>A duration typed in friendly form, echoed back in words.</summary>
public sealed partial class DurationField : TextField
{
    private readonly TimeSpan _minimum;
    private readonly TimeSpan? _maximum;
    private readonly bool _optional;

    // What was loaded: the friendly text drops fractions of a second, which must not change a value
    // nobody touched.
    private TimeSpan? _loaded;
    private string _loadedText = string.Empty;

    /// <summary>Creates a duration field.</summary>
    /// <param name="label">The name of the setting.</param>
    /// <param name="help">What it does.</param>
    /// <param name="minimum">Shortest accepted value.</param>
    /// <param name="optional">Whether empty is allowed, meaning "use the global value".</param>
    /// <param name="placeholder">Hint shown while empty.</param>
    /// <param name="maximum">Longest accepted value; the service would cut anything longer.</param>
    public DurationField(string label, string help, TimeSpan minimum, bool optional = false, string placeholder = "e.g. 10m, 1h 30m, 7d", TimeSpan? maximum = null)
        : base(label, help, placeholder)
    {
        _minimum = minimum;
        _maximum = maximum;
        _optional = optional;
    }

    /// <summary>The reading of the value in words.</summary>
    [ObservableProperty]
    private string _echo = string.Empty;

    /// <summary>The parsed value; null when empty or invalid.</summary>
    public TimeSpan? Duration => _loaded is not null && Text == _loadedText
        ? _loaded
        : DurationText.TryParse(Value, out var value) ? value : null;

    /// <summary>Sets the value from a duration.</summary>
    public void Set(TimeSpan? value)
    {
        Text = value is { } duration ? DurationText.Format(duration) : string.Empty;
        _loaded = value;
        _loadedText = Text;
    }

    /// <inheritdoc />
    protected override string? Validate(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return _optional ? null : "Required.";
        }

        if (!DurationText.TryParse(value, out var duration))
        {
            return "Try 10m, 1h 30m, 2 days or 00:10:00.";
        }

        if (duration < _minimum)
        {
            return $"Must be at least {DurationText.Describe(_minimum)}.";
        }

        return duration > _maximum ? $"Must be at most {DurationText.Describe(_maximum.Value)}." : null;
    }

    /// <inheritdoc />
    protected override void OnTextEdited() =>
        Echo = Error.Length == 0 && Duration is { } value ? DurationText.Describe(value) : string.Empty;
}

/// <summary>One step of the ban-tier ladder.</summary>
public sealed partial class TierRow : ObservableObject
{
    private readonly Action _changed;

    /// <summary>Creates a row.</summary>
    public TierRow(TimeSpan value, Action changed)
    {
        _changed = changed;
        _text = DurationText.Format(value);
        _echo = DurationText.Describe(value);
    }

    /// <summary>"1st offense".</summary>
    [ObservableProperty]
    private string _label = string.Empty;

    /// <summary>The duration as typed.</summary>
    [ObservableProperty]
    private string _text;

    /// <summary>The reading in words.</summary>
    [ObservableProperty]
    private string _echo;

    /// <summary>The validation message.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasError))]
    private string _error = string.Empty;

    /// <summary>Whether the row is invalid.</summary>
    public bool HasError => Error.Length > 0;

    /// <summary>The parsed value; null when invalid.</summary>
    public TimeSpan? Duration => DurationText.TryParse(Text, out var value) && value > TimeSpan.Zero ? value : null;

    partial void OnTextChanged(string value)
    {
        Error = Duration is null ? "Try 24h, 7d or 1d 12h." : string.Empty;
        Echo = Duration is { } duration ? DurationText.Describe(duration) : string.Empty;
        _changed();
    }
}

/// <summary>The escalation ladder: one duration per offense.</summary>
public sealed partial class BanTiersField : SettingField
{
    /// <summary>Creates the ladder.</summary>
    public BanTiersField()
        : base("Ban tiers", "How long each successive offense is blocked. The last tier repeats for every further offense.")
    {
    }

    /// <summary>The tiers, in order.</summary>
    public ObservableCollection<TierRow> Rows { get; } = [];

    /// <inheritdoc />
    public override bool HasError => Rows.Count == 0 || Rows.Any(row => row.HasError);

    /// <inheritdoc />
    public override string Snapshot => string.Join('|', Rows.Select(row => row.Text.Trim()));

    /// <summary>The parsed tiers.</summary>
    public TimeSpan[] Values => Rows.Where(row => row.Duration is not null).Select(row => row.Duration!.Value).ToArray();

    /// <summary>Replaces the ladder.</summary>
    public void Set(IEnumerable<TimeSpan> values)
    {
        Rows.Clear();
        foreach (var value in values)
        {
            Rows.Add(new TierRow(value, OnRowChanged));
        }

        Relabel();
    }

    [RelayCommand]
    private void AddTier()
    {
        Rows.Add(new TierRow(TimeSpan.FromDays(30), OnRowChanged));
        Relabel();
        RaiseChanged();
    }

    [RelayCommand]
    private void RemoveTier(TierRow? row)
    {
        if (row is not null && Rows.Count > 1)
        {
            Rows.Remove(row);
            Relabel();
            RaiseChanged();
        }
    }

    [RelayCommand]
    private void Preset(string? preset)
    {
        Set(preset switch
        {
            "24h" => [TimeSpan.FromHours(24)],
            "7d" => [TimeSpan.FromDays(7)],
            "30d" => [TimeSpan.FromDays(30)],
            _ => [TimeSpan.FromHours(24), TimeSpan.FromDays(7), TimeSpan.FromDays(30)],
        });
        RaiseChanged();
    }

    private void OnRowChanged()
    {
        OnPropertyChanged(nameof(HasError));
        RaiseChanged();
    }

    private void Relabel()
    {
        for (var i = 0; i < Rows.Count; i++)
        {
            var number = i + 1;
            var label = number switch
            {
                1 => "1st offense",
                2 => "2nd offense",
                3 => "3rd offense",
                _ => number + "th offense",
            };
            Rows[i].Label = i == Rows.Count - 1 && Rows.Count > 1 ? label + " onward" : label;
        }
    }
}

/// <summary>One editable line of a <see cref="StringListField"/>.</summary>
public sealed partial class TextRow : ObservableObject
{
    private readonly Action _changed;

    /// <summary>Creates a line.</summary>
    public TextRow(string value, Action changed)
    {
        _changed = changed;
        _value = value;
    }

    /// <summary>The text.</summary>
    [ObservableProperty]
    private string _value;

    partial void OnValueChanged(string value) => _changed();
}

/// <summary>An editable list of strings (exclusion rules, ignore patterns, honeypot names).</summary>
public sealed partial class StringListField : SettingField
{
    private readonly Func<string, string?>? _validate;

    /// <summary>Creates the list.</summary>
    /// <param name="label">The name of the setting.</param>
    /// <param name="help">What it does.</param>
    /// <param name="addLabel">Caption of the add button.</param>
    /// <param name="placeholder">Hint shown in an empty row.</param>
    /// <param name="validate">Checks one entry; returns the message, or null when it is fine.</param>
    public StringListField(string label, string help, string addLabel, string placeholder, Func<string, string?>? validate = null)
        : base(label, help)
    {
        AddLabel = addLabel;
        Placeholder = placeholder;
        _validate = validate;
    }

    /// <summary>Caption of the add button.</summary>
    public string AddLabel { get; }

    /// <summary>Hint shown in an empty row.</summary>
    public string Placeholder { get; }

    /// <summary>The rows.</summary>
    public ObservableCollection<TextRow> Rows { get; } = [];

    /// <inheritdoc />
    public override string Snapshot => string.Join('\n', Rows.Select(row => row.Value.Trim()).Where(value => value.Length > 0));

    /// <summary>The non-empty values.</summary>
    public string[] Values => Rows.Select(row => row.Value.Trim()).Where(value => value.Length > 0).ToArray();

    /// <summary>Replaces the rows.</summary>
    public void Set(IEnumerable<string> values)
    {
        Rows.Clear();
        foreach (var value in values)
        {
            Rows.Add(new TextRow(value, OnRowChanged));
        }

        Check();
    }

    [RelayCommand]
    private void AddRow()
    {
        Rows.Add(new TextRow(string.Empty, OnRowChanged));
        RaiseChanged();
    }

    [RelayCommand]
    private void RemoveRow(TextRow? row)
    {
        if (row is not null)
        {
            Rows.Remove(row);
            OnRowChanged();
        }
    }

    private void OnRowChanged()
    {
        Check();
        RaiseChanged();
    }

    private void Check() =>
        Error = _validate is null ? string.Empty : Values.Select(_validate).FirstOrDefault(problem => problem is not null) ?? string.Empty;
}

/// <summary>Something the reader needs to know at this point of a section. Nothing to edit, so it is never dirty.</summary>
public sealed partial class NoticeField : SettingField
{
    /// <summary>Creates a notice.</summary>
    /// <param name="tone">What it means.</param>
    /// <param name="title">Short headline.</param>
    /// <param name="message">What to know.</param>
    public NoticeField(Tone tone, string title, string message)
        : base(title, message)
    {
        _tone = tone;
        _message = message;
    }

    /// <summary>What it means. Changes when the service reports that the problem is real.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Glyph))]
    private Tone _tone;

    /// <summary>The text.</summary>
    [ObservableProperty]
    private string _message;

    /// <summary>Whether it applies right now.</summary>
    [ObservableProperty]
    private bool _isActive = true;

    /// <summary>Icon, so the meaning never rests on colour alone.</summary>
    public string Glyph => Tone is Tone.Warn or Tone.Attack ? "" : "";

    /// <inheritdoc />
    public override string Snapshot => string.Empty;
}

/// <summary>A heading that splits a long section into groups.</summary>
public sealed class GroupField : SettingField
{
    /// <summary>Creates a heading.</summary>
    public GroupField(string title, string help = "")
        : base(title, help)
    {
    }

    /// <inheritdoc />
    public override string Snapshot => string.Empty;
}

/// <summary>One choice in a <see cref="ChoiceField"/>.</summary>
/// <param name="Value">The stored value.</param>
/// <param name="Label">The name shown.</param>
public sealed record ChoiceOption(object Value, string Label);

/// <summary>A dropdown over a fixed set of values.</summary>
public sealed partial class ChoiceField : SettingField
{
    /// <summary>Creates a dropdown.</summary>
    public ChoiceField(string label, string help, params ChoiceOption[] options)
        : base(label, help)
    {
        Options = options;
        _selected = options[0].Value;
    }

    /// <summary>The choices.</summary>
    public IReadOnlyList<ChoiceOption> Options { get; }

    /// <summary>The value.</summary>
    [ObservableProperty]
    private object _selected;

    /// <inheritdoc />
    public override string Snapshot => Selected.ToString() ?? string.Empty;

    partial void OnSelectedChanged(object value) => RaiseChanged();
}

/// <summary>One choice in the FTP server dropdown.</summary>
/// <param name="Kind">The stored value.</param>
/// <param name="Label">The name shown.</param>
public sealed record FtpKindOption(FtpServerKind Kind, string Label);

/// <summary>Editable FTP log sources.</summary>
public sealed partial class FtpSourcesField : SettingField
{
    private readonly ToastCenter _toasts;

    /// <summary>Creates the list.</summary>
    public FtpSourcesField(ToastCenter toasts)
        : base("Log sources", "IIS FTP log folders and FileZilla log files, on a local drive.")
    {
        _toasts = toasts;
    }

    /// <summary>Server kinds for the dropdown, named as people know them.</summary>
    public static IReadOnlyList<FtpKindOption> Kinds { get; } =
    [
        new(FtpServerKind.IisFtp, "IIS FTP"),
        new(FtpServerKind.FileZilla, "FileZilla"),
    ];

    /// <summary>The rows.</summary>
    public ObservableCollection<FtpSourceRow> Rows { get; } = [];

    /// <inheritdoc />
    public override bool HasError => Rows.Any(row => row.HasError);

    /// <inheritdoc />
    public override string Snapshot => string.Join('\n', Rows.Select(row => $"{row.Name}|{row.Kind}|{row.Path}"));

    /// <summary>Replaces the rows.</summary>
    public void Set(IEnumerable<FtpLogSource> sources)
    {
        Rows.Clear();
        foreach (var source in sources)
        {
            Rows.Add(new FtpSourceRow(OnRowChanged, source) { Name = source.Name, Kind = source.Kind, Path = source.Path });
        }
    }

    [RelayCommand]
    private void AddSource()
    {
        Rows.Add(new FtpSourceRow(OnRowChanged));
        RaiseChanged();
    }

    [RelayCommand]
    private void RemoveSource(FtpSourceRow? row)
    {
        if (row is not null)
        {
            Rows.Remove(row);
            OnRowChanged();
        }
    }

    /// <summary>Adds the IIS FTP log folders found on this machine that are not listed yet.</summary>
    [RelayCommand]
    private void DetectIis()
    {
        var added = 0;
        try
        {
            var root = Environment.ExpandEnvironmentVariables(@"%SystemDrive%\inetpub\logs\LogFiles");
            if (System.IO.Directory.Exists(root))
            {
                foreach (var folder in System.IO.Directory.EnumerateDirectories(root, "FTPSVC*"))
                {
                    if (Rows.Any(row => string.Equals(row.Path.Trim(), folder, StringComparison.OrdinalIgnoreCase)))
                    {
                        continue;
                    }

                    Rows.Add(new FtpSourceRow(OnRowChanged) { Name = "IIS " + System.IO.Path.GetFileName(folder), Kind = FtpServerKind.IisFtp, Path = folder });
                    added++;
                }
            }
        }
        catch (Exception ex)
        {
            _toasts.Error("Could not look for IIS FTP logs", ex.Message);
            return;
        }

        if (added > 0)
        {
            _toasts.Success($"Added {added} IIS FTP log folder{(added == 1 ? string.Empty : "s")}", "Save to apply.");
            RaiseChanged();
        }
        else
        {
            _toasts.Info("No new IIS FTP log folders", @"Looked under %SystemDrive%\inetpub\logs\LogFiles.");
        }
    }

    private void OnRowChanged()
    {
        OnPropertyChanged(nameof(HasError));
        RaiseChanged();
    }
}

/// <summary>Editable custom log sources, each with a regex tester.</summary>
public sealed partial class CustomSourcesField : SettingField
{
    /// <summary>Creates the list.</summary>
    public CustomSourcesField()
        : base("Custom log sources", "Any log file plus a regex with a named group (?<ipaddress>...) and optionally (?<username>...). Each match counts as one failed login.")
    {
    }

    /// <summary>Ready-made recipes.</summary>
    public static IReadOnlyList<CustomSourceRecipe> Recipes { get; } = CustomSourceRecipes.All;

    /// <summary>The rows.</summary>
    public ObservableCollection<CustomSourceRow> Rows { get; } = [];

    /// <summary>The recipe picked in the dropdown.</summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(AddFromRecipeCommand))]
    private CustomSourceRecipe? _selectedRecipe;

    /// <inheritdoc />
    public override bool HasError => Rows.Any(row => row.HasError);

    /// <inheritdoc />
    public override string Snapshot => string.Join('\n', Rows.Select(row => $"{row.Name}|{row.Enabled}|{row.PathGlob}|{row.Regex}"));

    /// <summary>Replaces the rows.</summary>
    public void Set(IEnumerable<CustomLogSource> sources)
    {
        Rows.Clear();
        foreach (var source in sources)
        {
            var row = new CustomSourceRow(OnRowChanged, source)
            {
                Name = source.Name,
                Enabled = source.Enabled,
                PathGlob = source.PathGlob,
                Regex = source.Regex,
            };
            row.Ports.Text = string.Join(", ", source.BlockedPorts);
            Rows.Add(row);
        }
    }

    private bool CanAddFromRecipe() => SelectedRecipe is not null;

    [RelayCommand]
    private void AddSource()
    {
        Rows.Add(new CustomSourceRow(OnRowChanged) { IsExpanded = true });
        RaiseChanged();
    }

    [RelayCommand(CanExecute = nameof(CanAddFromRecipe))]
    private void AddFromRecipe()
    {
        if (SelectedRecipe is not { } recipe)
        {
            return;
        }

        Rows.Add(new CustomSourceRow(OnRowChanged)
        {
            Name = recipe.Name,
            PathGlob = recipe.PathGlob,
            Regex = recipe.Regex,
            SampleLine = CustomSourceRow.SampleFor(recipe),
            IsExpanded = true,
        });
        SelectedRecipe = null;
        RaiseChanged();
    }

    [RelayCommand]
    private void RemoveSource(CustomSourceRow? row)
    {
        if (row is not null)
        {
            Rows.Remove(row);
            OnRowChanged();
        }
    }

    private void OnRowChanged()
    {
        OnPropertyChanged(nameof(HasError));
        RaiseChanged();
    }
}

/// <summary>Checks shared by several fields.</summary>
public static class SettingChecks
{
    /// <summary>Whether a path is one the service will accept.</summary>
    public static string PathError(string path) =>
        string.IsNullOrWhiteSpace(path) || LogFileTailer.IsLocalPath(path)
            ? string.Empty
            : "Network paths are refused: use a path on a local drive.";

    /// <summary>Validates a list of ports: single ports or start-end ranges, as the firewall takes them.</summary>
    public static string? PortsError(string text)
    {
        foreach (var part in SplitPorts(text))
        {
            var bounds = part.Split('-');
            if (bounds.Length > 2 || !bounds.All(IsPort)
                || (bounds.Length == 2 && int.Parse(bounds[0], CultureInfo.InvariantCulture) > int.Parse(bounds[1], CultureInfo.InvariantCulture)))
            {
                return $"'{part}' is not a port or a range such as 1000-2000.";
            }
        }

        return null;
    }

    /// <summary>Validates one port or range, which is all a passive port setting takes.</summary>
    public static string? RangeError(string text) =>
        text.Length == 0 || PortSet.TryParseRange(text, out _, out _)
            ? null
            : "Enter one port, or one range such as 50000-50100.";

    /// <summary>Splits a typed port list.</summary>
    public static string[] SplitPorts(string text) =>
        text.Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    /// <summary>Validates an optional absolute http(s) address.</summary>
    public static string? UrlError(string text) =>
        text.Length == 0
        || (Uri.TryCreate(text, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https")
            ? null
            : "Enter a full address starting with https://.";

    /// <summary>
    /// A deep copy of part of the settings. A row edits a few properties of the object it was loaded
    /// from and saves this copy with those few changed: rebuilding it would wipe the rest.
    /// </summary>
    public static T Copy<T>(T value) => JsonSerializer.Deserialize<T>(JsonSerializer.Serialize(value))!;

    /// <summary>A message from the service, started as a sentence for showing on its own.</summary>
    public static string? Sentence(string? text) =>
        string.IsNullOrEmpty(text) ? text : char.ToUpperInvariant(text[0]) + text[1..];

    private static bool IsPort(string text) =>
        int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var port) && port is >= 1 and <= 65535;
}
