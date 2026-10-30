using System.Threading.Channels;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WinGuard.Core.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Detection;
using WinGuard.Core.Engine;
using WinGuard.Core.Model;

namespace WinGuard.Service;

/// <summary>
/// Wires the detection engines to the ban engine (PLAN.md §4/§5). Creates the bounded
/// <see cref="FailedLogin"/> channel, starts every enabled detector (a detector that fails to
/// subscribe must not take the service down), then pumps the channel through
/// <see cref="BanEngine.RunAsync"/> until shutdown.
/// </summary>
public sealed class GuardWorker : BackgroundService
{
    private const int ChannelCapacity = 20_000;

    private readonly IEnumerable<IDetector> _detectors;
    private readonly BanEngine _engine;
    private readonly DetectorRuntimeState _state;
    private readonly ILogger<GuardWorker> _logger;

    /// <summary>Creates the worker.</summary>
    /// <param name="detectors">All registered detectors.</param>
    /// <param name="engine">The ban engine consuming the shared channel.</param>
    /// <param name="settings">Settings holder providing the live accessor.</param>
    /// <param name="state">Shared per-protocol running flags for the dashboard.</param>
    /// <param name="logger">Diagnostic logger.</param>
    public GuardWorker(
        IEnumerable<IDetector> detectors,
        BanEngine engine,
        SettingsHolder settings,
        DetectorRuntimeState state,
        ILogger<GuardWorker> logger)
    {
        _detectors = detectors ?? throw new ArgumentNullException(nameof(detectors));
        _engine = engine ?? throw new ArgumentNullException(nameof(engine));
        ArgumentNullException.ThrowIfNull(settings);
        _state = state ?? throw new ArgumentNullException(nameof(state));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("GuardWorker starting.");
        // Bounded: under a flood faster than the store and firewall can absorb, the oldest pending
        // failures are dropped instead of growing memory without limit.
        var channel = Channel.CreateBounded<FailedLogin>(new BoundedChannelOptions(ChannelCapacity)
        {
            SingleReader = true,
            FullMode = BoundedChannelFullMode.DropOldest,
        });

        try
        {
            await _engine.StartAsync(stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            return;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "BanEngine failed to start; detection will continue but bans may not be enforced.");
        }

        // Every detector is started regardless of its enabled setting: each one checks the live
        // setting itself, so enabling an engine in the GUI needs no service restart.
        foreach (var detector in _detectors)
        {
            if (stoppingToken.IsCancellationRequested)
            {
                break;
            }

            try
            {
                await detector.StartAsync(channel, stoppingToken).ConfigureAwait(false);
                _state.Register(detector);
                _logger.LogInformation("Detector {Detector} ({Source}) started.", detector.Name, detector.Source);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Detector {Detector} failed to start; continuing without it.", detector.Name);
            }
        }

        try
        {
            await _engine.RunAsync(channel.Reader, stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Normal shutdown.
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "BanEngine loop stopped unexpectedly.");
        }

        channel.Writer.TryComplete();
        try
        {
            await _engine.StopAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "BanEngine stop reported an error.");
        }

        _logger.LogInformation("GuardWorker stopped.");
    }
}
