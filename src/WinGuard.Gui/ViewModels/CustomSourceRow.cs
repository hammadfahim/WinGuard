using CommunityToolkit.Mvvm.ComponentModel;
using WinGuard.Core.Config;
using WinGuard.Gui.Services;

namespace WinGuard.Gui.ViewModels;

/// <summary>Editable row for one custom log source, with its regex tester.</summary>
public sealed partial class CustomSourceRow : ObservableObject
{
    // Waits for a pause in typing: the tester compiles the regex on every run.
    private const int TestDelayMilliseconds = 250;

    private readonly Action _changed;
    private readonly CustomLogSource? _origin;
    private int _testVersion;

    /// <summary>Creates a row.</summary>
    /// <param name="changed">Called on every edit.</param>
    /// <param name="origin">The source this row edits; null for a new one.</param>
    public CustomSourceRow(Action changed, CustomLogSource? origin = null)
    {
        _changed = changed;
        _origin = origin;
        Ports = new PortProfileRow(Title, changed);
    }

    /// <summary>The ports a ban from this source blocks, edited in the Blocking section.</summary>
    public PortProfileRow Ports { get; }

    /// <summary>Display name.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Title))]
    private string _name = string.Empty;

    /// <summary>Whether the source is active.</summary>
    [ObservableProperty]
    private bool _enabled = true;

    /// <summary>File path or folder+glob.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PathError))]
    [NotifyPropertyChangedFor(nameof(HasError))]
    private string _pathGlob = string.Empty;

    /// <summary>Regex with named groups <c>ipaddress</c> (required) and <c>username</c> (optional).</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(RegexError))]
    [NotifyPropertyChangedFor(nameof(HasError))]
    private string _regex = string.Empty;

    /// <summary>The line to test against.</summary>
    [ObservableProperty]
    private string _sampleLine = string.Empty;

    /// <summary>Whether the editor is open.</summary>
    [ObservableProperty]
    private bool _isExpanded;

    /// <summary>The tester's latest result.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ResultTone))]
    [NotifyPropertyChangedFor(nameof(HasCapture))]
    private ProbeResult _result = new(ProbeStatus.Idle, "Paste a sample log line to test this regex.");

    /// <summary>Heading of the row.</summary>
    public string Title => string.IsNullOrWhiteSpace(Name) ? "Unnamed source" : Name;

    /// <summary>Why the path is refused.</summary>
    public string PathError => SettingChecks.PathError(PathGlob);

    /// <summary>Why the regex is refused.</summary>
    public string RegexError
    {
        get
        {
            var check = RegexProbe.Check(Regex);
            return check.Status == ProbeStatus.Idle ? string.Empty : check.Summary;
        }
    }

    /// <summary>Whether the row is invalid.</summary>
    public bool HasError => PathError.Length > 0 || RegexError.Length > 0;

    /// <summary>What the tester's result means.</summary>
    public Tone ResultTone => Result.Status switch
    {
        ProbeStatus.Match => Tone.Protected,
        ProbeStatus.Idle => Tone.Neutral,
        ProbeStatus.NoMatch => Tone.Warn,
        _ => Tone.Attack,
    };

    /// <summary>Whether the tester captured anything to show.</summary>
    public bool HasCapture => Result.Status == ProbeStatus.Match;

    /// <summary>A representative line for a recipe, so its tester works from the first click.</summary>
    public static string SampleFor(CustomSourceRecipe recipe) => recipe.Name switch
    {
        _ when recipe == CustomSourceRecipes.WindowsOpenSsh =>
            "sshd: Failed password for invalid user admin from 203.0.113.7 port 52144 ssh2",
        _ when recipe == CustomSourceRecipes.HMailServer =>
            "2026-10-31 12:00:01\tFAILED\tadmin@example.com\t25\t203.0.113.7\t",
        _ when recipe == CustomSourceRecipes.IisHttpAuth =>
            "2026-10-31 12:00:01 203.0.113.7 - W3SVC1 WEB01 10.0.0.5 GET /admin - 401 0 0",
        _ when recipe == CustomSourceRecipes.Vnc =>
            "<Warn> Connections: blacklisted: 203.0.113.7",
        _ => string.Empty,
    };

    /// <summary>Runs the tester now.</summary>
    public void TestNow() => Result = RegexProbe.Run(Regex, SampleLine);

    /// <summary>The source to save: what was loaded, with this row's edits on top.</summary>
    public CustomLogSource ToSource()
    {
        var source = _origin is null ? new CustomLogSource() : SettingChecks.Copy(_origin);
        source.Name = Name.Trim();
        source.Enabled = Enabled;
        source.PathGlob = PathGlob.Trim();
        source.Regex = Regex.Trim();
        source.BlockedPorts = Ports.Values;
        return source;
    }

    partial void OnNameChanged(string value)
    {
        Ports.Title = Title;
        _changed();
    }

    partial void OnEnabledChanged(bool value) => _changed();

    partial void OnPathGlobChanged(string value) => _changed();

    partial void OnRegexChanged(string value)
    {
        _changed();
        ScheduleTest();
    }

    partial void OnSampleLineChanged(string value) => ScheduleTest();

    private async void ScheduleTest()
    {
        var version = ++_testVersion;
        await Task.Delay(TestDelayMilliseconds);
        if (version != _testVersion)
        {
            return;
        }

        // Off the UI thread: a slow pattern takes up to its timeout, and the console must not freeze.
        var pattern = Regex;
        var line = SampleLine;
        var result = await Task.Run(() => RegexProbe.Run(pattern, line));
        if (version == _testVersion)
        {
            Result = result;
        }
    }
}
