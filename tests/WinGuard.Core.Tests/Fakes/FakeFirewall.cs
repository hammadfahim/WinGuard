using WinGuard.Core.Abstractions;

namespace WinGuard.Core.Tests.Fakes;

/// <summary>
/// In-memory <see cref="IFirewall"/> used by the engine tests. Records every call and
/// keeps the current blocked set so assertions can observe both the calls and the state.
/// </summary>
public sealed class FakeFirewall : IFirewall
{
    private readonly object _gate = new();
    private readonly List<string> _blocked = new();

    /// <summary>Every IP passed to <see cref="Block"/>, in call order (duplicates included).</summary>
    public List<string> BlockCalls { get; } = new();

    /// <summary>Every IP passed to <see cref="Unblock"/>, in call order.</summary>
    public List<string> UnblockCalls { get; } = new();

    /// <summary>Snapshot of the target list given to each <see cref="SyncRules"/> call.</summary>
    public List<IReadOnlyList<string>> SyncRulesCalls { get; } = new();

    /// <summary>When true, <see cref="ListBlocked"/> fails the way an unreachable firewall does.</summary>
    public bool FailListBlocked { get; set; }

    /// <summary>Number of times <see cref="ClearAll"/> was invoked.</summary>
    public int ClearAllCallCount { get; private set; }

    /// <summary>Value returned by <see cref="IsServiceRunning"/>; defaults to true.</summary>
    public bool ServiceRunning { get; set; } = true;

    /// <summary>Current blocked set.</summary>
    public IReadOnlyList<string> Blocked
    {
        get { lock (_gate) { return _blocked.ToList(); } }
    }

    public void Block(string ip)
    {
        lock (_gate)
        {
            BlockCalls.Add(ip);
            if (!_blocked.Contains(ip))
            {
                _blocked.Add(ip);
            }
        }
    }

    public void Unblock(string ip)
    {
        lock (_gate)
        {
            UnblockCalls.Add(ip);
            _blocked.Remove(ip);
        }
    }

    public void SyncRules(IEnumerable<string> targets)
    {
        lock (_gate)
        {
            var ips = targets.ToList();
            SyncRulesCalls.Add(ips);
            _blocked.Clear();
            foreach (var ip in ips)
            {
                if (!_blocked.Contains(ip))
                {
                    _blocked.Add(ip);
                }
            }
        }
    }

    public IReadOnlyList<string>? ListBlocked()
    {
        lock (_gate)
        {
            return FailListBlocked ? null : _blocked.ToList();
        }
    }

    public void ClearAll()
    {
        lock (_gate)
        {
            ClearAllCallCount++;
            _blocked.Clear();
        }
    }

    public bool IsServiceRunning() => ServiceRunning;
}