using Microsoft.Extensions.Logging;
using WinGuard.Core.Model;
using WinGuard.Core.Notifications;

namespace WinGuard.Core.Engine;

/// <summary>
/// Break-glass: while a valid <see cref="DisarmFile"/> says so, the engine keeps counting and
/// recording but holds no firewall rules at all. The file is the only source of truth: this class
/// follows it, and when it is gone, run out or no longer valid, the normal reconcile restores
/// enforcement.
/// </summary>
public sealed partial class BanEngine
{
    // Appended to what is reported about a ban, like ReportOnlyNote.
    private const string DisarmedNote = " (disarmed: firewall unchanged)";

    /// <summary>A disarm is noticed, and ends, this promptly however long the housekeeping interval is.</summary>
    internal static readonly TimeSpan BreakGlassPollInterval = TimeSpan.FromSeconds(15);

    // End of the window in UTC ticks, 0 when armed. A plain long: status requests read it off the gate.
    private long _disarmedUntilTicks;

    // The last refusal reported, so a bad file is reported once and not on every pass (under _gate).
    private string? _disarmProblem;

    /// <summary>The break-glass file to follow; null leaves the feature out.</summary>
    public DisarmFile? BreakGlass { get; init; }

    /// <summary>
    /// When the open disarm window ends, or null while enforcing. The window ends on time even if
    /// housekeeping is held up, so nothing here can outlast it.
    /// </summary>
    public DateTime? DisarmedUntilUtc
    {
        get
        {
            var ticks = Volatile.Read(ref _disarmedUntilTicks);
            return ticks > NowUtc().Ticks ? new DateTime(ticks, DateTimeKind.Utc) : null;
        }
    }

    /// <summary>True while a disarm window is open.</summary>
    public bool IsDisarmed => DisarmedUntilUtc is not null;

    /// <summary>Whether firewall writes are off, for a disarm or for report-only mode.</summary>
    private bool FirewallFrozen => IsDisarmed || _settingsAccessor().ReportOnly;

    /// <summary>
    /// Brings the engine in line with the break-glass file. Call under the gate. The firewall work
    /// it does is logged rather than thrown, so a failure leaves housekeeping running.
    /// </summary>
    private async Task CheckDisarmCoreAsync(CancellationToken ct)
    {
        if (BreakGlass is not { } file)
        {
            return;
        }

        var state = file.Read(NowUtc());
        switch (state.Status)
        {
            case DisarmStatus.Active:
                _disarmProblem = null;
                await ApplyDisarmAsync(state, ct).ConfigureAwait(false);
                break;

            case DisarmStatus.Expired:
                // A window that ended while the engine followed it is a normal rearm. One that
                // ended while the service was stopped has no such event, so it gets its own.
                if (Volatile.Read(ref _disarmedUntilTicks) == 0)
                {
                    await ReportDisarmProblemAsync($"its window ended at {state.UntilUtc:u}", ct).ConfigureAwait(false);
                }

                await RearmAsync("the break-glass window ended", ct).ConfigureAwait(false);
                RetireExpiredFile(file);
                break;

            case DisarmStatus.None:
                _disarmProblem = null;
                await RearmAsync("the break-glass file was removed", ct).ConfigureAwait(false);
                break;

            default:
                // Refused files stay where they are, for the administrator to look at.
                await ReportDisarmProblemAsync(state.Problem ?? "it is not valid", ct).ConfigureAwait(false);
                await RearmAsync("the break-glass file is no longer valid", ct).ConfigureAwait(false);
                break;
        }
    }

    private async Task ApplyDisarmAsync(DisarmState state, CancellationToken ct)
    {
        var until = state.UntilUtc!.Value;
        var previous = Interlocked.Exchange(ref _disarmedUntilTicks, until.Ticks);
        if (previous == until.Ticks)
        {
            return;
        }

        var by = state.By is null ? string.Empty : $" by {state.By}";
        if (previous != 0)
        {
            await AddBreakGlassEventAsync($"{WinGuardEventIds.DisarmedPrefix}window changed to end at {until:u}{by}.", ct).ConfigureAwait(false);
            return;
        }

        // Also after a restart: rules may have come back through anything but this engine. A clear
        // that fails here is tried again by the reconcile pass.
        TryFirewall(_firewall.ClearAll, "clear", "all rules");
        _logger.LogWarning("Break-glass: disarmed until {Until:u}{By}. No firewall rules are held until then.", until, by);
        await AddBreakGlassEventAsync($"{WinGuardEventIds.DisarmedPrefix}until {until:u}{by}: all WinGuard firewall rules removed, bans are recorded but NOT enforced.", ct).ConfigureAwait(false);
    }

    /// <summary>Removes a file whose window is over; one that stays would come back to life if the clock were set back.</summary>
    private void RetireExpiredFile(DisarmFile file)
    {
        try
        {
            file.Delete();
        }
        catch (Exception ex)
        {
            // It disarms nothing where it is, and this runs on every pass until it goes.
            _logger.LogDebug(ex, "Could not remove the expired break-glass file.");
        }
    }

    private async Task ReportDisarmProblemAsync(string problem, CancellationToken ct)
    {
        if (string.Equals(_disarmProblem, problem, StringComparison.Ordinal))
        {
            return;
        }

        _disarmProblem = problem;
        _logger.LogWarning("Ignoring the break-glass file: {Problem}.", problem);
        await AddBreakGlassEventAsync($"{WinGuardEventIds.DisarmRefusedPrefix}the break-glass file was ignored: {problem}.", ct).ConfigureAwait(false);
    }

    /// <summary>Ends a disarm: the reconcile puts back every active ban, as after a report-only run.</summary>
    private async Task RearmAsync(string reason, CancellationToken ct)
    {
        if (Interlocked.Exchange(ref _disarmedUntilTicks, 0) == 0)
        {
            return;
        }

        _logger.LogWarning("Break-glass: {Reason}; enforcement resumes.", reason);
        await AddBreakGlassEventAsync($"{WinGuardEventIds.RearmedPrefix}{reason}: enforcement resumes.{ReportSuffix()}", ct).ConfigureAwait(false);
        await ReconcileFirewallCoreAsync(ct).ConfigureAwait(false);
    }

    private Task AddBreakGlassEventAsync(string message, CancellationToken ct) => TryAddEventAsync(
        new LogEvent
        {
            TimestampUtc = NowUtc(),
            Level = LogEventLevel.Warning,
            Message = message,
        },
        ct);

    /// <summary>While disarmed the only firewall work is keeping it empty: a clear that failed, or rules added from outside.</summary>
    private void KeepFirewallClear()
    {
        if (_firewall.ListBlocked() is { Count: > 0 } left)
        {
            _logger.LogWarning("Break-glass: {Count} firewall target(s) are present while disarmed; removing them.", left.Count);
            TryFirewall(_firewall.ClearAll, "clear", "all rules");
        }
    }

    /// <summary>
    /// Waits out a housekeeping interval, looking at the break-glass file on the way when the
    /// interval is long: the settings allow a whole day, and neither the start of a window nor
    /// its end can wait that long.
    /// </summary>
    private async Task WaitForNextPassAsync(TimeSpan interval, CancellationToken ct)
    {
        while (BreakGlass is not null && interval > BreakGlassPollInterval)
        {
            await Task.Delay(BreakGlassPollInterval, _timeProvider, ct).ConfigureAwait(false);
            interval -= BreakGlassPollInterval;

            await _gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                await CheckDisarmCoreAsync(ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                _logger.LogError(ex, "BanEngine could not check the break-glass file.");
            }
            finally
            {
                _gate.Release();
            }
        }

        await Task.Delay(interval, _timeProvider, ct).ConfigureAwait(false);
    }
}
