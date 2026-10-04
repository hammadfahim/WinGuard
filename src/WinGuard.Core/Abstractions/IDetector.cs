using System.Threading.Channels;
using WinGuard.Core.Model;

namespace WinGuard.Core.Abstractions;

/// <summary>
/// A detection engine (RDP 4625, RdpCoreTS 140, MSSQL 18456, FTP tailer, custom log).
/// Detectors push observed failures into the shared sink channel; the BanEngine consumes it.
/// StartAsync must return promptly (background subscription/loop) and stop on cancellation.
/// </summary>
public interface IDetector
{
    ProtocolSource Source { get; }

    /// <summary>Human-readable name for status/logs (e.g. "RDP (Security 4625)").</summary>
    string Name { get; }

    Task StartAsync(Channel<FailedLogin> sink, CancellationToken ct);
}
