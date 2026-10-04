using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using WinGuard.Core.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Engine;
using WinGuard.Core.Model;

namespace WinGuard.Core.Firewall;

/// <summary>
/// Windows Defender Firewall implementation of <see cref="IFirewall"/> (PLAN.md §7) using the
/// COM automation API <c>HNetCfg.FwPolicy2</c> / <c>HNetCfg.FWRule</c> through <c>dynamic</c>.
/// No interop assembly, no <c>netsh</c>, no extra NuGet package.
/// <para>
/// Bans are stored in batched block rules named <c>WinGuard_Block_0001</c>, <c>WinGuard_Block_0002</c>,
/// … Each rule holds up to <c>maxAddressesPerRule</c> comma-separated remote addresses (the Windows
/// firewall practical limit is ~1000 per rule). Every operation is idempotent and never throws out
/// of the <see cref="IFirewall"/> surface — failures are logged instead.
/// </para>
/// <para>
/// When <see cref="WinGuardSettings.BlockedPorts"/> is empty (the default) a single rule with
/// <c>Protocol = Any</c> is used per batch (cheapest: one condition per IP). When it is non-empty a
/// TCP and a UDP rule pair is maintained per batch with <c>LocalPorts</c> set, because a single rule
/// cannot mix the TCP and UDP protocols. The pair shares the same remote-address batch and is named
/// with a <c>_TCP</c>/<c>_UDP</c> suffix; both still start with <see cref="Defaults.RuleNamePrefix"/>
/// so <see cref="ClearAll"/> and <see cref="ListBlocked"/> see them.
/// </para>
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsFirewall : IFirewall
{
    private const string PolicyProgId = "HNetCfg.FwPolicy2";
    private const string RuleProgId = "HNetCfg.FWRule";

    private const int RuleDirectionIn = 1;      // NET_FW_RULE_DIR_IN
    private const int RuleActionBlock = 2;      // NET_FW_ACTION_BLOCK
    private const int ProfileAll = 0x7FFFFFFF;  // NET_FW_PROFILE2_ALL
    private const int ProtocolAny = 256;        // NET_FW_IP_PROTOCOL_ANY
    private const int ProtocolTcp = 6;          // NET_FW_IP_PROTOCOL_TCP
    private const int ProtocolUdp = 17;         // NET_FW_IP_PROTOCOL_UDP

    private const string RuleDescription = "WinGuard managed block rule (auto-generated - do not edit).";

    private readonly ILogger<WindowsFirewall> _logger;
    private readonly int _maxAddressesPerRule;
    private readonly Func<WinGuardSettings>? _settingsAccessor;
    private readonly object _gate = new();

    /// <summary>
    /// Creates the firewall wrapper.
    /// </summary>
    /// <param name="logger">Diagnostic logger.</param>
    /// <param name="maxAddressesPerRule">Maximum number of remote addresses stored per batch rule.</param>
    /// <param name="settingsAccessor">
    /// Optional live-settings accessor used to read <see cref="WinGuardSettings.BlockedPorts"/>.
    /// When null/omitted the firewall blocks all ports (single <c>Protocol = Any</c> rule per batch).
    /// The parameter is optional so existing call sites using the two-argument contract still compile.
    /// </param>
    public WindowsFirewall(
        ILogger<WindowsFirewall> logger,
        int maxAddressesPerRule = Defaults.MaxAddressesPerRule,
        Func<WinGuardSettings>? settingsAccessor = null)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _maxAddressesPerRule = Math.Max(1, maxAddressesPerRule);
        _settingsAccessor = settingsAccessor;
    }

    /// <inheritdoc />
    public void Block(string ip)
    {
        if (!IpMatcher.TryNormalize(ip, out var normalized) || !IpMatcher.IsValid(normalized))
        {
            _logger.LogWarning("Refusing to block invalid IP value {Ip}; it was not added to any firewall rule.", ip);
            return;
        }

        lock (_gate)
        {
            try
            {
                dynamic policy = CreatePolicy();
                List<RuleBatch> batches = LoadBatches(policy);

                foreach (var batch in batches)
                {
                    if (batch.Addresses.Contains(normalized, StringComparer.OrdinalIgnoreCase))
                    {
                        _logger.LogDebug("IP {Ip} is already present in firewall rule {Rule}; nothing to do.", normalized, RuleName(batch.Index));
                        return;
                    }
                }

                var target = batches.FirstOrDefault(b => b.Addresses.Count < _maxAddressesPerRule);
                if (target is null)
                {
                    target = new RuleBatch { Index = batches.Count == 0 ? 1 : batches.Max(b => b.Index) + 1 };
                    batches.Add(target);
                }

                target.Addresses.Add(normalized);
                WriteBatch(policy, target, CurrentPorts());
                _logger.LogInformation("Blocked {Ip} in firewall rule {Rule} ({Count} addresses).", normalized, RuleName(target.Index), target.Addresses.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to block {Ip} in the Windows firewall.", ip);
            }
        }
    }

    /// <inheritdoc />
    public void Unblock(string ip)
    {
        if (!IpMatcher.TryNormalize(ip, out var normalized))
        {
            _logger.LogWarning("Refusing to unblock invalid IP value {Ip}.", ip);
            return;
        }

        lock (_gate)
        {
            try
            {
                dynamic policy = CreatePolicy();
                List<RuleBatch> batches = LoadBatches(policy);

                RuleBatch? target = null;
                foreach (var batch in batches)
                {
                    if (batch.Addresses.RemoveAll(a => string.Equals(a, normalized, StringComparison.OrdinalIgnoreCase)) > 0)
                    {
                        target = batch;
                        break;
                    }
                }

                if (target is null)
                {
                    _logger.LogDebug("IP {Ip} was not present in any WinGuard firewall rule; nothing to do.", normalized);
                    return;
                }

                if (target.Addresses.Count == 0)
                {
                    DeleteRule(policy, RuleName(target.Index));
                    DeleteRule(policy, RuleName(target.Index, "TCP"));
                    DeleteRule(policy, RuleName(target.Index, "UDP"));
                    _logger.LogInformation("Unblocked {Ip}; firewall rule {Rule} is now empty and was removed.", normalized, RuleName(target.Index));
                }
                else
                {
                    WriteBatch(policy, target, CurrentPorts());
                    _logger.LogInformation("Unblocked {Ip} from firewall rule {Rule} ({Count} addresses remain).", normalized, RuleName(target.Index), target.Addresses.Count);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to unblock {Ip} in the Windows firewall.", ip);
            }
        }
    }

    /// <inheritdoc />
    public void SyncRules(IEnumerable<BanEntry> activeBans)
    {
        if (activeBans is null)
        {
            return;
        }

        lock (_gate)
        {
            try
            {
                dynamic policy = CreatePolicy();
                ClearAllLocked(policy);

                var ports = CurrentPorts();
                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var batches = new List<RuleBatch>();
                RuleBatch? current = null;

                foreach (var ban in activeBans)
                {
                    if (ban is null || !IpMatcher.TryNormalize(ban.IpAddress, out var normalized) || !seen.Add(normalized))
                    {
                        continue;
                    }

                    if (current is null || current.Addresses.Count >= _maxAddressesPerRule)
                    {
                        current = new RuleBatch { Index = batches.Count + 1 };
                        batches.Add(current);
                    }

                    current.Addresses.Add(normalized);
                }

                foreach (var batch in batches)
                {
                    WriteBatch(policy, batch, ports);
                }

                _logger.LogInformation("Reconciled firewall rules: {Rules} rule(s) for {Addresses} active ban(s).", batches.Count, seen.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to synchronize WinGuard firewall rules.");
            }
        }
    }

    /// <inheritdoc />
    public IReadOnlyList<string> ListBlocked()
    {
        lock (_gate)
        {
            var results = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                dynamic policy = CreatePolicy();
                foreach (dynamic rule in policy.Rules)
                {
                    string? name = SafeGet(() => (string?)rule.Name);
                    if (!TryParseRuleName(name, out _, out _))
                    {
                        continue;
                    }

                    string? remote = SafeGet(() => (string?)rule.RemoteAddresses);
                    foreach (var candidate in SplitAddresses(remote))
                    {
                        if (IpMatcher.TryNormalize(candidate, out var normalized) && seen.Add(normalized))
                        {
                            results.Add(normalized);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to enumerate WinGuard firewall rules.");
            }

            return results;
        }
    }

    /// <inheritdoc />
    public void ClearAll()
    {
        lock (_gate)
        {
            try
            {
                dynamic policy = CreatePolicy();
                ClearAllLocked(policy);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to clear WinGuard firewall rules.");
            }
        }
    }

    /// <inheritdoc />
    public bool IsServiceRunning()
    {
        IntPtr scm = IntPtr.Zero;
        IntPtr service = IntPtr.Zero;
        try
        {
            scm = ServiceControl.OpenSCManager(null, null, ServiceControl.ScManagerConnect);
            if (scm == IntPtr.Zero)
            {
                _logger.LogWarning("Could not open the service control manager to query MpsSvc (Win32 error {Error}).", Marshal.GetLastWin32Error());
                return false;
            }

            service = ServiceControl.OpenService(scm, "MpsSvc", ServiceControl.ServiceQueryStatus);
            if (service == IntPtr.Zero)
            {
                _logger.LogWarning("Could not open the MpsSvc service (Win32 error {Error}); the firewall may not be installed.", Marshal.GetLastWin32Error());
                return false;
            }

            if (!ServiceControl.QueryServiceStatus(service, out var status))
            {
                _logger.LogWarning("Could not query the MpsSvc service status (Win32 error {Error}).", Marshal.GetLastWin32Error());
                return false;
            }

            return (status.dwCurrentState & ServiceControl.ServiceRunning) != 0;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to query the Windows Defender Firewall service (MpsSvc).");
            return false;
        }
        finally
        {
            if (service != IntPtr.Zero)
            {
                ServiceControl.CloseServiceHandle(service);
            }

            if (scm != IntPtr.Zero)
            {
                ServiceControl.CloseServiceHandle(scm);
            }
        }
    }

    // ---- rule plumbing ----

    private static dynamic CreatePolicy()
    {
        var type = Type.GetTypeFromProgID(PolicyProgId, throwOnError: false)
            ?? throw new PlatformNotSupportedException(
                "The Windows Firewall COM API (HNetCfg.FwPolicy2) is unavailable. This operation requires Windows.");
        return Activator.CreateInstance(type)!;
    }

    private static dynamic BuildRule(string name, int protocol, string? localPorts, string remoteAddresses)
    {
        var type = Type.GetTypeFromProgID(RuleProgId, throwOnError: false)
            ?? throw new PlatformNotSupportedException(
                "The Windows Firewall COM API (HNetCfg.FWRule) is unavailable. This operation requires Windows.");

        dynamic rule = Activator.CreateInstance(type)!;
        rule.Name = name;
        rule.Description = RuleDescription;
        rule.Direction = RuleDirectionIn;
        rule.Action = RuleActionBlock;
        rule.Enabled = true;
        rule.Profiles = ProfileAll;
        rule.Protocol = protocol;
        if (localPorts is not null)
        {
            rule.LocalPorts = localPorts;
        }

        rule.RemoteAddresses = remoteAddresses;
        return rule;
    }

    /// <summary>Loads every <c>WinGuard_Block_*</c> rule into logical batches keyed by their index.</summary>
    private List<RuleBatch> LoadBatches(dynamic policy)
    {
        var map = new Dictionary<int, RuleBatch>();
        foreach (dynamic rule in policy.Rules)
        {
            try
            {
                string? name = (string?)rule.Name;
                if (!TryParseRuleName(name, out var index, out var kind))
                {
                    continue;
                }

                if (!map.TryGetValue(index, out var batch))
                {
                    batch = new RuleBatch { Index = index };
                    map[index] = batch;
                }

                foreach (var candidate in SplitAddresses((string?)rule.RemoteAddresses))
                {
                    if (IpMatcher.TryNormalize(candidate, out var normalized)
                        && !batch.Addresses.Contains(normalized, StringComparer.OrdinalIgnoreCase))
                    {
                        batch.Addresses.Add(normalized);
                    }
                }

                switch (kind)
                {
                    case RuleKind.Any:
                        batch.AnyRule = (object)rule;
                        break;
                    case RuleKind.Tcp:
                        batch.TcpRule = (object)rule;
                        break;
                    case RuleKind.Udp:
                        batch.UdpRule = (object)rule;
                        break;
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Skipped an unreadable firewall rule while enumerating WinGuard rules.");
            }
        }

        return map.Values.OrderBy(b => b.Index).ToList();
    }

    /// <summary>
    /// Writes the batch's address list into the correct rule shape for the current port mode,
    /// creating rules when needed, updating existing ones and removing stale variants.
    /// </summary>
    private void WriteBatch(dynamic policy, RuleBatch batch, string[] ports)
    {
        var csv = string.Join(",", batch.Addresses);
        if (ports.Length == 0)
        {
            // All-ports mode: one Protocol=Any rule per batch.
            EnsureRule(policy, ref batch.AnyRule, RuleName(batch.Index), ProtocolAny, csv, null);
            DeleteRule(policy, RuleName(batch.Index, "TCP"));
            DeleteRule(policy, RuleName(batch.Index, "UDP"));
            batch.TcpRule = null;
            batch.UdpRule = null;
        }
        else
        {
            // Port mode: a TCP and a UDP rule sharing the same address batch (a single rule
            // cannot carry both protocols), both restricted to the configured LocalPorts.
            var portList = string.Join(",", ports);
            EnsureRule(policy, ref batch.TcpRule, RuleName(batch.Index, "TCP"), ProtocolTcp, csv, portList);
            EnsureRule(policy, ref batch.UdpRule, RuleName(batch.Index, "UDP"), ProtocolUdp, csv, portList);
            DeleteRule(policy, RuleName(batch.Index));
            batch.AnyRule = null;
        }
    }

    private void EnsureRule(dynamic policy, ref object? handle, string name, int protocol, string csv, string? localPorts)
    {
        if (handle is null)
        {
            var rule = BuildRule(name, protocol, localPorts, csv);
            policy.Rules.Add(rule);
            handle = (object)rule;
            _logger.LogInformation("Created firewall rule {Rule} ({Protocol}).", name, protocol == ProtocolAny ? "any" : protocol == ProtocolTcp ? "TCP" : "UDP");
        }
        else
        {
            ((dynamic)handle).RemoteAddresses = csv;
        }
    }

    private void DeleteRule(dynamic policy, string name)
    {
        try
        {
            policy.Rules.Remove(name);
            _logger.LogInformation("Removed firewall rule {Rule}.", name);
        }
        catch (Exception ex)
        {
            // Remove throws when the named rule does not exist; treat as a no-op for idempotency.
            _logger.LogDebug(ex, "Firewall rule {Rule} was not present or could not be removed.", name);
        }
    }

    private void ClearAllLocked(dynamic policy)
    {
        var names = new List<string>();
        foreach (dynamic rule in policy.Rules)
        {
            string? name = SafeGet(() => (string?)rule.Name);
            if (name is not null && name.StartsWith(Defaults.RuleNamePrefix, StringComparison.OrdinalIgnoreCase))
            {
                names.Add(name);
            }
        }

        foreach (var name in names)
        {
            DeleteRule(policy, name);
        }

        _logger.LogInformation("Cleared {Count} WinGuard firewall rule(s).", names.Count);
    }

    private string[] CurrentPorts()
    {
        try
        {
            var settings = _settingsAccessor?.Invoke();
            if (settings?.BlockedPorts is { Length: > 0 } ports)
            {
                return ports
                    .Where(p => !string.IsNullOrWhiteSpace(p))
                    .Select(p => p.Trim())
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray();
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not read BlockedPorts from settings; defaulting to block-all-ports.");
        }

        return [];
    }

    private string RuleName(int index) => $"{Defaults.RuleNamePrefix}{index:D4}";

    private string RuleName(int index, string suffix) => $"{Defaults.RuleNamePrefix}{index:D4}_{suffix}";

    private static bool TryParseRuleName(string? name, out int index, out RuleKind kind)
    {
        index = 0;
        kind = RuleKind.Any;
        if (name is null || !name.StartsWith(Defaults.RuleNamePrefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var remainder = name[Defaults.RuleNamePrefix.Length..];
        if (remainder.EndsWith("_TCP", StringComparison.OrdinalIgnoreCase))
        {
            kind = RuleKind.Tcp;
            remainder = remainder[..^4];
        }
        else if (remainder.EndsWith("_UDP", StringComparison.OrdinalIgnoreCase))
        {
            kind = RuleKind.Udp;
            remainder = remainder[..^4];
        }

        return int.TryParse(remainder, out index) && index > 0;
    }

    private static IEnumerable<string> SplitAddresses(string? remoteAddresses)
    {
        if (string.IsNullOrWhiteSpace(remoteAddresses))
        {
            yield break;
        }

        foreach (var part in remoteAddresses.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            yield return part;
        }
    }

    private static T? SafeGet<T>(Func<T> getter)
    {
        try
        {
            return getter();
        }
        catch (Exception)
        {
            return default;
        }
    }

    private enum RuleKind
    {
        Any,
        Tcp,
        Udp,
    }

    private sealed class RuleBatch
    {
        public int Index { get; init; }

        public List<string> Addresses { get; } = [];

        public object? AnyRule;

        public object? TcpRule;

        public object? UdpRule;
    }

    /// <summary>
    /// Minimal P/Invoke surface over <c>advapi32.dll</c> to query the MpsSvc service state without
    /// referencing <c>System.ServiceProcess.ServiceController</c> (not available without a package).
    /// </summary>
    private static class ServiceControl
    {
        internal const uint ScManagerConnect = 0x0001;
        internal const uint ServiceQueryStatus = 0x0004;
        internal const uint ServiceRunning = 0x00000004;

        [StructLayout(LayoutKind.Sequential)]
        internal struct ServiceStatus
        {
            public uint dwServiceType;
            public uint dwCurrentState;
            public uint dwControlsAccepted;
            public uint dwWin32ExitCode;
            public uint dwServiceSpecificExitCode;
            public uint dwCheckPoint;
            public uint dwWaitHint;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr OpenSCManager(string? machineName, string? databaseName, uint desiredAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr OpenService(IntPtr scManager, string serviceName, uint desiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool QueryServiceStatus(IntPtr service, out ServiceStatus serviceStatus);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseServiceHandle(IntPtr handle);
    }
}