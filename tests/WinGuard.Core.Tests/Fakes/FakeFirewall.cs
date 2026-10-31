using WinGuard.Core.Abstractions;
using WinGuard.Core.Model;

namespace WinGuard.Core.Tests.Fakes;

/// <summary>
/// In-memory <see cref="IFirewall"/> used by the engine tests. Records every call and
/// keeps the current blocked set so assertions can observe both the calls and the state.
/// </summary>
public sealed class FakeFirewall : IFirewall
{
    private readonly object _gate = new();
    private readonly List<string> _blocked = new();
    private readonly Dictionary<string, PortSet> _ports = new(StringComparer.Ordinal);

    /// <summary>Every IP passed to <see cref="Block(string, PortSet)"/>, in call order (duplicates included).</summary>
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

    /// <summary>The ports a target is blocked on now, or null when it is not blocked.</summary>
    public PortSet? PortsOf(string ip)
    {
        lock (_gate)
        {
            return _ports.GetValueOrDefault(ip);
        }
    }

    public void Block(string ip) => Block(ip, PortSet.All);

    public void Block(string ip, PortSet ports)
    {
        lock (_gate)
        {
            BlockCalls.Add(ip);
            if (!_blocked.Contains(ip))
            {
                _blocked.Add(ip);
            }

            _ports[ip] = ports;
        }
    }

    public void Unblock(string ip)
    {
        lock (_gate)
        {
            UnblockCalls.Add(ip);
            _blocked.Remove(ip);
            _ports.Remove(ip);
        }
    }

    public void SyncRules(IEnumerable<string> targets) =>
        SyncRules(targets.Select(target => new FirewallTarget(target, PortSet.All)));

    public void SyncRules(IEnumerable<FirewallTarget> targets)
    {
        lock (_gate)
        {
            var wanted = targets.ToList();
            SyncRulesCalls.Add(wanted.Select(target => target.Address).ToList());
            _blocked.Clear();
            _ports.Clear();
            foreach (var target in wanted)
            {
                if (!_blocked.Contains(target.Address))
                {
                    _blocked.Add(target.Address);
                }

                _ports[target.Address] = target.Ports;
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

    public IReadOnlyList<BlockedTarget>? ListBlockedTargets()
    {
        lock (_gate)
        {
            return FailListBlocked ? null : _blocked.Select(ip => new BlockedTarget(ip, _ports[ip].RuleFamily)).ToList();
        }
    }

    public void ClearAll()
    {
        lock (_gate)
        {
            ClearAllCallCount++;
            _blocked.Clear();
            _ports.Clear();
        }
    }

    public bool IsServiceRunning() => ServiceRunning;
}