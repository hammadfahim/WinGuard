using System.Globalization;
using System.Text;
using Microsoft.Extensions.Logging;
using WinGuard.Core.Detection;

namespace WinGuard.Core.Monitoring;

/// <summary>One engine's numbers.</summary>
/// <param name="Label">Value of the <c>engine</c> label.</param>
/// <param name="Enabled">Enabled in the settings; null for a source that has no switch.</param>
/// <param name="DetectionsToday">Failed logins seen today.</param>
/// <param name="ActiveBans">Bans in force that came from this source.</param>
public sealed record EngineMetrics(string Label, bool? Enabled, int DetectionsToday, int ActiveBans);

/// <summary>What housekeeping knows at the end of a pass.</summary>
/// <param name="HousekeepingUtc">When the pass ran.</param>
/// <param name="ActiveBans">Bans in force.</param>
/// <param name="Engines">Per-source numbers.</param>
/// <param name="FirewallRules">WinGuard rules in the firewall; null when not known at no cost.</param>
/// <param name="ReportOnly">Report-only mode is on.</param>
/// <param name="Disarmed">A break-glass window is open.</param>
/// <param name="NotificationsEnabled">The notification master switch is on.</param>
/// <param name="SyslogEnabled">Syslog output is on.</param>
public sealed record MetricsSnapshot(
    DateTime HousekeepingUtc,
    int ActiveBans,
    IReadOnlyList<EngineMetrics> Engines,
    int? FirewallRules,
    bool ReportOnly,
    bool Disarmed,
    bool NotificationsEnabled,
    bool SyslogEnabled);

/// <summary>Takes the metrics of a housekeeping pass. Called under the engine's lock, so it must not block or throw.</summary>
public interface IMetricsPublisher
{
    /// <summary>Hands over a snapshot for the given path.</summary>
    void Publish(MetricsSnapshot snapshot, string path);
}

/// <summary>
/// Writes metrics for the textfile collector of windows_exporter. A pull model on purpose: WinGuard
/// opens no listener, and the file is written by housekeeping only if a path is configured.
/// <para>
/// The file goes out atomically (written next to the target, then renamed), so the collector never
/// reads half of it, and it is written on a background task, so a stuck disk cannot hold the
/// engine's lock. One write runs at a time and only the newest snapshot waits behind it. A failed
/// write is logged and costs nothing else; the file then ages, and the housekeeping timestamp in it
/// is what an alert should watch.
/// </para>
/// </summary>
public sealed class PrometheusTextfileWriter : IMetricsPublisher
{
    private const string Extension = ".prom";

    // No BOM, and "\n" line ends on Windows too: this is what the collector's parser accepts.
    private static readonly UTF8Encoding Utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);

    private readonly ILogger _logger;
    private readonly object _lock = new();

    // Guarded by _lock.
    private (MetricsSnapshot Snapshot, string Path)? _pending;
    private Task? _writer;

    // Only the writer task uses this: a path that stays broken is reported once, not every pass.
    private string? _lastProblem;

    /// <summary>Creates the writer.</summary>
    /// <param name="logger">Diagnostic logger.</param>
    public PrometheusTextfileWriter(ILogger logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public void Publish(MetricsSnapshot snapshot, string path)
    {
        lock (_lock)
        {
            _pending = (snapshot, path);
            _writer ??= Task.Run(DrainAsync);
        }
    }

    /// <summary>Waits until everything published so far is on disk.</summary>
    internal Task FlushAsync()
    {
        lock (_lock)
        {
            return _writer ?? Task.CompletedTask;
        }
    }

    /// <summary>
    /// Why a path cannot be used, or null. Only a full local path will do: the service runs as
    /// SYSTEM, and a network path would authenticate the machine to whatever host it names.
    /// </summary>
    public static string? PathProblem(string? path)
    {
        if (!LogFileTailer.IsLocalPath(path))
        {
            return "network (UNC) and device paths are not allowed; use a path on a local drive.";
        }

        var expanded = Expand(path!);
        if (!Path.IsPathFullyQualified(expanded))
        {
            return "use a full path, such as C:\\Program Files\\windows_exporter\\textfile_inputs\\winguard.prom.";
        }

        if (!string.Equals(Path.GetExtension(expanded), Extension, StringComparison.OrdinalIgnoreCase))
        {
            return $"the file name must end in {Extension}: windows_exporter reads no other files.";
        }

        return null;
    }

    /// <summary>The file content in the Prometheus text format, one family after the other.</summary>
    public static string Format(MetricsSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        var text = new StringBuilder();
        Gauge(text, "winguard_active_bans", "Bans currently in force.", snapshot.ActiveBans);
        Family(text, "winguard_engine_active_bans", "Bans currently in force, by the engine that caused them.", snapshot.Engines, engine => engine.ActiveBans);
        Family(text, "winguard_engine_detections_today", "Failed logins seen today, by engine; starts again at midnight.", snapshot.Engines, engine => engine.DetectionsToday);
        Family(text, "winguard_engine_enabled", "1 when the engine is enabled.", snapshot.Engines.Where(engine => engine.Enabled is not null), engine => Flag(engine.Enabled == true));

        if (snapshot.FirewallRules is { } rules)
        {
            Gauge(text, "winguard_firewall_rules", "WinGuard rules in the Windows firewall.", rules);
        }

        var timestamp = new DateTimeOffset(DateTime.SpecifyKind(snapshot.HousekeepingUtc, DateTimeKind.Utc)).ToUnixTimeSeconds();
        Gauge(text, "winguard_last_housekeeping_timestamp_seconds", "Unix time of the last housekeeping pass.", timestamp);
        Gauge(text, "winguard_report_only", "1 in report-only mode: bans are recorded, not enforced.", Flag(snapshot.ReportOnly));
        Gauge(text, "winguard_disarmed", "1 during a break-glass window: nothing is enforced.", Flag(snapshot.Disarmed));
        Gauge(text, "winguard_notifications_enabled", "1 when notifications are enabled.", Flag(snapshot.NotificationsEnabled));
        Gauge(text, "winguard_syslog_enabled", "1 when syslog output is enabled.", Flag(snapshot.SyslogEnabled));
        return text.ToString();
    }

    private static int Flag(bool value) => value ? 1 : 0;

    private static void Gauge(StringBuilder text, string name, string help, long value)
    {
        Header(text, name, help);
        text.Append(name).Append(' ').Append(value.ToString(CultureInfo.InvariantCulture)).Append('\n');
    }

    private static void Family(StringBuilder text, string name, string help, IEnumerable<EngineMetrics> engines, Func<EngineMetrics, int> value)
    {
        Header(text, name, help);
        foreach (var engine in engines)
        {
            text.Append(name).Append("{engine=\"").Append(engine.Label).Append("\"} ")
                .Append(value(engine).ToString(CultureInfo.InvariantCulture)).Append('\n');
        }
    }

    private static void Header(StringBuilder text, string name, string help) =>
        text.Append("# HELP ").Append(name).Append(' ').Append(help).Append('\n')
            .Append("# TYPE ").Append(name).Append(" gauge\n");

    private static string Expand(string path) =>
        Environment.ExpandEnvironmentVariables(path.Trim().Trim('"'));

    private async Task DrainAsync()
    {
        while (true)
        {
            (MetricsSnapshot Snapshot, string Path) next;
            lock (_lock)
            {
                if (_pending is not { } pending)
                {
                    _writer = null;
                    return;
                }

                next = pending;
                _pending = null;
            }

            WriteOnce(next.Snapshot, next.Path);
            await Task.Yield();
        }
    }

    private void WriteOnce(MetricsSnapshot snapshot, string path)
    {
        try
        {
            if (PathProblem(path) is { } problem)
            {
                Report(problem, problem);
                return;
            }

            WriteAtomically(Path.GetFullPath(Expand(path)), Format(snapshot));
            _lastProblem = null;
        }
        catch (Exception ex)
        {
            // The message quotes the random temporary name, so it cannot tell two failures apart.
            Report($"{ex.GetType().Name} {path}", ex.Message);
        }
    }

    private void Report(string key, string problem)
    {
        if (!string.Equals(_lastProblem, key, StringComparison.Ordinal))
        {
            _lastProblem = key;
            _logger.LogWarning("Could not write the Prometheus textfile: {Problem}", problem);
        }
    }

    /// <summary>
    /// The temporary name is random and must not exist yet: the folder may be writable by others,
    /// and a file planted under a predictable name would have SYSTEM write through it. It does not
    /// end in <c>.prom</c>, so the collector skips it. The rename replaces a link at the target
    /// rather than following it.
    /// </summary>
    private static void WriteAtomically(string path, string content)
    {
        var temporary = $"{path}.{Guid.NewGuid():N}.tmp";
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                stream.Write(Utf8NoBom.GetBytes(content));
            }

            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }
}
