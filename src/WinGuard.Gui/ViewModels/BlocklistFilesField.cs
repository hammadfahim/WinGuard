using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using WinGuard.Core.Config;
using WinGuard.Core.Ipc;
using WinGuard.Gui.Services;

namespace WinGuard.Gui.ViewModels;

/// <summary>One blocklist file and how it is doing.</summary>
public sealed partial class BlocklistFileRow : ObservableObject
{
    private readonly Action _changed;

    /// <summary>Creates a row.</summary>
    /// <param name="path">The file.</param>
    /// <param name="changed">Called on every edit.</param>
    public BlocklistFileRow(string path, Action changed)
    {
        _path = path;
        _changed = changed;
    }

    /// <summary>The file.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PathError))]
    [NotifyPropertyChangedFor(nameof(HasError))]
    private string _path;

    /// <summary>What the service last reported about this file.</summary>
    [ObservableProperty]
    private string _statusText = string.Empty;

    /// <summary>What that status means.</summary>
    [ObservableProperty]
    private Tone _statusTone = Tone.Neutral;

    /// <summary>Why the path is refused.</summary>
    public string PathError => SettingChecks.PathError(Path);

    /// <summary>Whether the row is invalid.</summary>
    public bool HasError => PathError.Length > 0;

    /// <summary>Shows what the service reports.</summary>
    /// <param name="file">The file's status; null when the service does not know this path yet.</param>
    /// <param name="nowUtc">The time, for "4m ago".</param>
    public void ApplyStatus(BlocklistFileStatusDto? file, DateTime nowUtc)
    {
        if (file is null)
        {
            StatusTone = Tone.Neutral;
            StatusText = "Not read yet. The service reads it once the settings are saved.";
            return;
        }

        var counts = $"{file.Loaded:N0} entries, {file.Skipped:N0} lines skipped";
        var read = file.LastLoadedUtc is { } read1 ? $"last loaded {TimeText.Ago(read1, nowUtc)}" : "never loaded";
        if (string.IsNullOrEmpty(file.Problem))
        {
            StatusTone = Tone.Protected;
            StatusText = $"{counts}, {read}.";
        }
        else
        {
            StatusTone = Tone.Warn;
            StatusText = $"{SettingChecks.Sentence(file.Problem)}. Its last good entries stay in force: {counts}, {read}.";
        }
    }

    partial void OnPathChanged(string value) => _changed();
}

/// <summary>The local blocklist files, each with the status the service reports for it.</summary>
public sealed partial class BlocklistFilesField : SettingField
{
    private readonly ToastCenter _toasts;
    private BlocklistStatusDto? _status;

    /// <summary>Creates the list.</summary>
    public BlocklistFilesField(ToastCenter toasts)
        : base("Blocklist files", "Text files on a local drive, one IP or CIDR per line. Listed addresses are blocked on all ports without waiting for a failed login.")
    {
        _toasts = toasts;
    }

    /// <summary>The rows.</summary>
    public ObservableCollection<BlocklistFileRow> Rows { get; } = [];

    /// <summary>The files as a whole.</summary>
    [ObservableProperty]
    private string _summaryText = string.Empty;

    /// <summary>What the summary means.</summary>
    [ObservableProperty]
    private Tone _summaryTone = Tone.Neutral;

    /// <inheritdoc />
    public override bool HasError => Rows.Any(row => row.HasError);

    /// <inheritdoc />
    public override string Snapshot => string.Join('\n', Values);

    /// <summary>The non-empty paths.</summary>
    public string[] Values => Rows.Select(row => row.Path.Trim()).Where(path => path.Length > 0).ToArray();

    /// <summary>Replaces the rows.</summary>
    public void Set(IEnumerable<string> paths)
    {
        Rows.Clear();
        foreach (var path in paths)
        {
            Rows.Add(new BlocklistFileRow(path, OnRowChanged));
        }

        Refresh();
    }

    /// <summary>Shows a fresh status from the service.</summary>
    public void ApplyStatus(BlocklistStatusDto status)
    {
        _status = status;
        Refresh();
    }

    private void Refresh()
    {
        var now = DateTime.UtcNow;
        foreach (var row in Rows)
        {
            row.ApplyStatus(_status?.Files.FirstOrDefault(file => string.Equals(file.Path, row.Path.Trim(), StringComparison.OrdinalIgnoreCase)), now);
        }

        if (_status is not { } status || Rows.Count == 0)
        {
            SummaryText = string.Empty;
            return;
        }

        var parts = new List<string> { $"{status.Loaded:N0} firewall entries in force", $"{status.Skipped:N0} lines skipped" };
        if (status.Capped > 0)
        {
            parts.Add($"{status.Capped:N0} left out: at most {Defaults.MaxBlocklistEntries:N0} are blocked");
        }

        SummaryTone = status.Capped > 0 ? Tone.Warn : Tone.Neutral;
        SummaryText = string.Join(", ", parts) + ".";
    }

    private void OnRowChanged()
    {
        OnPropertyChanged(nameof(HasError));
        Refresh();
        RaiseChanged();
    }

    [RelayCommand]
    private void AddFile()
    {
        Rows.Add(new BlocklistFileRow(string.Empty, OnRowChanged));
        OnRowChanged();
    }

    [RelayCommand]
    private void RemoveFile(BlocklistFileRow? row)
    {
        if (row is not null)
        {
            Rows.Remove(row);
            OnRowChanged();
        }
    }

    /// <summary>Picks the file for a row, or for a new one.</summary>
    [RelayCommand]
    private void Browse(BlocklistFileRow? row)
    {
        var dialog = new OpenFileDialog
        {
            Filter = "Lists (*.txt;*.lst;*.netset;*.csv)|*.txt;*.lst;*.netset;*.csv|All files (*.*)|*.*",
            Title = "Choose a blocklist file",
            CheckFileExists = true,
        };

        try
        {
            if (dialog.ShowDialog() != true)
            {
                return;
            }
        }
        catch (Exception ex)
        {
            _toasts.Error("Could not open the file dialog", ex.Message);
            return;
        }

        if (row is null)
        {
            Rows.Add(new BlocklistFileRow(dialog.FileName, OnRowChanged));
            OnRowChanged();
        }
        else
        {
            row.Path = dialog.FileName;
        }
    }
}
