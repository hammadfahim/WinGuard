using System.Collections.Concurrent;
using WinGuard.Core.Abstractions;
using WinGuard.Core.Model;

namespace WinGuard.Service;

/// <summary>
/// Shared runtime state published by <see cref="GuardWorker"/> and consumed by
/// <see cref="Ipc.PipeServer"/> for the per-engine <c>Running</c> flag. The flag is read live from
/// the detectors, so a subscription that failed or died shows as not running on the dashboard.
/// </summary>
public sealed class DetectorRuntimeState
{
    private readonly ConcurrentBag<IDetector> _detectors = [];

    /// <summary>Registers a started detector.</summary>
    public void Register(IDetector detector) => _detectors.Add(detector ?? throw new ArgumentNullException(nameof(detector)));

    /// <summary>True when at least one detector for the protocol is really watching its source.</summary>
    /// <param name="source">Protocol source.</param>
    public bool IsRunning(ProtocolSource source) => _detectors.Any(d => d.Source == source && d.IsRunning);
}
