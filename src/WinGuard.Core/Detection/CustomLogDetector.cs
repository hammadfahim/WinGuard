using System.Text.RegularExpressions;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using WinGuard.Core.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Engine;
using WinGuard.Core.Model;

namespace WinGuard.Core.Detection;

/// <summary>
/// Generic log detector (PLAN.md §4.5): tails each configured <see cref="CustomLogSource"/> file
/// (or folder + glob) and applies the source's regex. A regex match yields one
/// <see cref="FailedLogin"/>; the regex must capture a named group <c>ipaddress</c> and may capture
/// an optional named group <c>username</c>. Tailing uses the shared <see cref="LogFileTailer"/> so
/// only appended lines are evaluated. The failure timestamp is the poller's current UTC time.
/// </summary>
public sealed class CustomLogDetector : IDetector
{
    private readonly Func<WinGuardSettings> _settingsAccessor;
    private readonly ILogger<CustomLogDetector> _logger;
    private readonly TimeProvider _timeProvider;
    private readonly LogFileTailer _tailer = new();

    /// <summary>Creates the detector.</summary>
    /// <param name="settingsAccessor">Returns the current live settings.</param>
    /// <param name="logger">Logger for polling diagnostics.</param>
    /// <param name="timeProvider">Clock abstraction; defaults to <see cref="TimeProvider.System"/>.</param>
    public CustomLogDetector(
        Func<WinGuardSettings> settingsAccessor,
        ILogger<CustomLogDetector> logger,
        TimeProvider? timeProvider = null)
    {
        _settingsAccessor = settingsAccessor;
        _logger = logger;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public ProtocolSource Source => ProtocolSource.Custom;

    /// <inheritdoc />
    public string Name => "Custom log sources";

    /// <inheritdoc />
    public Task StartAsync(Channel<FailedLogin> sink, CancellationToken ct)
    {
        // The loop always runs so hot-added/edited custom sources take effect without a restart;
        // each source's own Enabled flag is re-checked every cycle.
        _ = Task.Run(() => PollLoopAsync(sink, ct), CancellationToken.None);
        var enabled = (_settingsAccessor().CustomSources ?? []).Count(source => source is { Enabled: true });
        _logger.LogInformation("Custom log detector started with {Count} enabled source(s).", enabled);
        return Task.CompletedTask;
    }

    /// <summary>
    /// Applies <paramref name="regexPattern"/> to one log line. The named group <c>ipaddress</c> is
    /// required and must normalize to a valid IP; the optional named group <c>username</c> becomes
    /// the user. At most one failure is produced per line.
    /// </summary>
    /// <param name="line">A single log line.</param>
    /// <param name="regexPattern">Regex with named groups <c>ipaddress</c> and optional <c>username</c>.</param>
    /// <param name="failed">The parsed failure when the method returns <see langword="true"/>.</param>
    public static bool TryParseLine(string line, string regexPattern, out FailedLogin? failed)
    {
        failed = null;
        if (string.IsNullOrEmpty(line) || string.IsNullOrWhiteSpace(regexPattern))
        {
            return false;
        }

        Match match;
        try
        {
            match = Regex.Match(line, regexPattern);
        }
        catch (ArgumentException)
        {
            return false;
        }

        if (!match.Success)
        {
            return false;
        }

        var ipGroup = match.Groups["ipaddress"];
        if (!ipGroup.Success || !IpMatcher.TryNormalize(ipGroup.Value, out var ip))
        {
            return false;
        }

        var userGroup = match.Groups["username"];
        var user = userGroup.Success ? NormalizeOptional(userGroup.Value) : null;

        failed = new FailedLogin
        {
            IpAddress = ip,
            UserName = user,
            Source = ProtocolSource.Custom,
            TimestampUtc = DateTime.UtcNow,
            RawLog = line.Trim(),
        };
        return true;
    }

    private async Task PollLoopAsync(Channel<FailedLogin> sink, CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var settings = _settingsAccessor();
                try
                {
                    PollOnce(settings, sink);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Custom log detector poll cycle failed.");
                }

                try
                {
                    await Task.Delay(Defaults.FtpPollInterval, _timeProvider, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Custom log detector poll loop terminated unexpectedly.");
        }
    }

    private void PollOnce(WinGuardSettings settings, Channel<FailedLogin> sink)
    {
        var activeFiles = new List<string>();
        foreach (var source in settings.CustomSources ?? [])
        {
            if (source is null || !source.Enabled
                || string.IsNullOrWhiteSpace(source.PathGlob)
                || string.IsNullOrWhiteSpace(source.Regex))
            {
                continue;
            }

            foreach (var file in LogFileTailer.ResolveFiles(source.PathGlob, "*"))
            {
                activeFiles.Add(file);
                foreach (var line in _tailer.ReadNewLines(file))
                {
                    if (TryParseLine(line, source.Regex, out var failure) && failure is not null)
                    {
                        failure.TimestampUtc = _timeProvider.GetUtcNow().UtcDateTime;
                        if (!sink.Writer.TryWrite(failure))
                        {
                            _logger.LogWarning("Custom log detector could not write to the sink channel (closed).");
                        }
                    }
                }
            }
        }

        _tailer.Prune(activeFiles);
    }

    private static string? NormalizeOptional(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var trimmed = value.Trim();
        return trimmed == "-" ? null : trimmed;
    }
}