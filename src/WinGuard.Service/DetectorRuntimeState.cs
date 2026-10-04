using System.Collections.Concurrent;
using WinGuard.Core.Model;

namespace WinGuard.Service;

/// <summary>
/// Small shared runtime state published by <see cref="GuardWorker"/> and consumed by
/// <see cref="Ipc.PipeServer"/> for the per-engine <c>Running</c> flag. A detector is marked
/// running once its <c>StartAsync</c> completed without throwing (a dead/absent channel leaves it
/// not-running, which the dashboard surfaces as a warning).
/// </summary>
public sealed class DetectorRuntimeState
{
    private readonly ConcurrentDictionary<ProtocolSource, bool> _running = new();

    /// <summary>Marks whether the detector(s) for a protocol started successfully.</summary>
    /// <param name="source">Protocol source.</param>
    /// <param name="running">True when at least one detector for the source subscribed successfully.</param>
    public void SetRunning(ProtocolSource source, bool running) => _running[source] = running;

    /// <summary>True when at least one detector for the protocol started successfully.</summary>
    /// <param name="source">Protocol source.</param>
    public bool IsRunning(ProtocolSource source) => _running.TryGetValue(source, out var running) && running;
}