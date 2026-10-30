using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using WinGuard.Core.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Engine;

namespace WinGuard.Core.Firewall;

/// <summary>
/// Windows Defender Firewall implementation of <see cref="IFirewall"/> (PLAN.md §7). Rule storage
/// goes through <see cref="IFirewallRuleStore"/> (COM in production, an in-memory fake in tests);
/// this class owns the batching.
/// <para>
/// Bans are stored in batched block rules named <c>WinGuard_Block_0001</c>, <c>WinGuard_Block_0002</c>,
/// … Each rule holds up to <c>MaxAddressesPerRule</c> comma-separated remote addresses (the Windows
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
/// <para>
/// The batches are cached in memory (guarded by one lock) so a block or unblock is a single rule
/// write instead of an enumeration of every firewall rule. <see cref="ListBlocked"/> (called by the
/// engine's reconcile pass) re-reads the live firewall and refreshes the cache; any failure drops
/// the cache so the next call reloads it.
/// </para>
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsFirewall : IFirewall
{
    internal const int ProtocolAny = 256;        // NET_FW_IP_PROTOCOL_ANY
    internal const int ProtocolTcp = 6;          // NET_FW_IP_PROTOCOL_TCP
    internal const int ProtocolUdp = 17;         // NET_FW_IP_PROTOCOL_UDP

    private readonly ILogger<WindowsFirewall> _logger;
    private readonly IFirewallRuleStore _store;
    private readonly int _maxAddressesPerRule;
    private readonly Func<WinGuardSettings>? _settingsAccessor;
    private readonly object _gate = new();

    private List<RuleBatch>? _batchCache;

    // The port list the rules were last written with; a change rewrites every batch.
    private string? _appliedPortsKey;

    /// <summary>
    /// Creates the firewall wrapper over the Windows Firewall COM API.
    /// </summary>
    /// <param name="logger">Diagnostic logger.</param>
    /// <param name="maxAddressesPerRule">
    /// Fallback maximum number of remote addresses per batch rule, used when no settings accessor is
    /// supplied; otherwise <see cref="WinGuardSettings.MaxAddressesPerRule"/> is read live.
    /// </param>
    /// <param name="settingsAccessor">
    /// Optional live-settings accessor used to read <see cref="WinGuardSettings.BlockedPorts"/> and
    /// <see cref="WinGuardSettings.MaxAddressesPerRule"/>. When null the firewall blocks all ports.
    /// </param>
    public WindowsFirewall(
        ILogger<WindowsFirewall> logger,
        int maxAddressesPerRule = Defaults.MaxAddressesPerRule,
        Func<WinGuardSettings>? settingsAccessor = null)
        : this(logger, new ComFirewallRuleStore(), maxAddressesPerRule, settingsAccessor)
    {
    }

    internal WindowsFirewall(
        ILogger<WindowsFirewall> logger,
        IFirewallRuleStore store,
        int maxAddressesPerRule = Defaults.MaxAddressesPerRule,
        Func<WinGuardSettings>? settingsAccessor = null)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _maxAddressesPerRule = Math.Max(1, maxAddressesPerRule);
        _settingsAccessor = settingsAccessor;
    }

    /// <inheritdoc />
    public void Block(string ipOrRange)
    {
        if (!TryNormalizeTarget(ipOrRange, out var normalized))
        {
            _logger.LogWarning("Refusing to block invalid address value {Ip}; it was not added to any firewall rule.", ipOrRange);
            return;
        }

        lock (_gate)
        {
            try
            {
                var batches = GetBatches();
                var ports = CurrentPorts();
                EnsurePortsApplied(batches, ports);

                foreach (var batch in batches)
                {
                    if (batch.Addresses.Contains(normalized))
                    {
                        _logger.LogDebug("Address {Ip} is already present in firewall rule {Rule}; nothing to do.", normalized, RuleName(batch.Index));
                        return;
                    }
                }

                var max = MaxAddressesPerRule();
                var target = batches.FirstOrDefault(b => b.Addresses.Count < max);
                if (target is null)
                {
                    target = new RuleBatch { Index = NextFreeIndex(batches) };
                    batches.Add(target);
                    batches.Sort((a, b) => a.Index.CompareTo(b.Index));
                }

                target.Addresses.Add(normalized);
                WriteBatch(target, ports);
                _logger.LogInformation("Blocked {Ip} in firewall rule {Rule} ({Count} addresses).", normalized, RuleName(target.Index), target.Addresses.Count);
            }
            catch (Exception ex)
            {
                _batchCache = null;
                _logger.LogError(ex, "Failed to block {Ip} in the Windows firewall.", ipOrRange);
            }
        }
    }

    /// <inheritdoc />
    public void Unblock(string ipOrRange)
    {
        if (!TryNormalizeTarget(ipOrRange, out var normalized))
        {
            _logger.LogWarning("Refusing to unblock invalid address value {Ip}.", ipOrRange);
            return;
        }

        lock (_gate)
        {
            try
            {
                var batches = GetBatches();
                var ports = CurrentPorts();
                EnsurePortsApplied(batches, ports);

                var target = batches.FirstOrDefault(b => b.Addresses.Contains(normalized));
                if (target is null)
                {
                    _logger.LogDebug("IP {Ip} was not present in any WinGuard firewall rule; nothing to do.", normalized);
                    return;
                }

                target.Addresses.Remove(normalized);
                if (target.Addresses.Count == 0)
                {
                    DeleteBatchRules(target);
                    batches.Remove(target);
                    _logger.LogInformation("Unblocked {Ip}; firewall rule {Rule} is now empty and was removed.", normalized, RuleName(target.Index));
                }
                else
                {
                    WriteBatch(target, ports);
                    _logger.LogInformation("Unblocked {Ip} from firewall rule {Rule} ({Count} addresses remain).", normalized, RuleName(target.Index), target.Addresses.Count);
                }
            }
            catch (Exception ex)
            {
                _batchCache = null;
                _logger.LogError(ex, "Failed to unblock {Ip} in the Windows firewall.", ipOrRange);
            }
        }
    }

    /// <inheritdoc />
    public void SyncRules(IEnumerable<string> targets)
    {
        if (targets is null)
        {
            return;
        }

        lock (_gate)
        {
            try
            {
                var ports = CurrentPorts();
                var max = MaxAddressesPerRule();
                var wanted = new List<string>();
                var unplaced = new HashSet<string>(StringComparer.Ordinal);
                foreach (var target in targets)
                {
                    if (TryNormalizeTarget(target, out var normalized) && unplaced.Add(normalized))
                    {
                        wanted.Add(normalized);
                    }
                }

                // Every address stays in the rule that already holds it: moving one between rules
                // would leave it unenforced from the first rule's write until the second's. The only
                // exception is a lowered MaxAddressesPerRule, which the write order below covers.
                var batches = LoadBatches();
                foreach (var batch in batches)
                {
                    var kept = batch.Addresses.Where(unplaced.Contains).Take(max).ToList();
                    unplaced.ExceptWith(kept);
                    batch.Addresses.Clear();
                    batch.Addresses.AddRange(kept);
                }

                var grown = new HashSet<RuleBatch>();
                foreach (var address in wanted.Where(unplaced.Contains))
                {
                    var batch = batches.FirstOrDefault(b => b.Addresses.Count < max);
                    if (batch is null)
                    {
                        batch = new RuleBatch { Index = NextFreeIndex(batches) };
                        batches.Add(batch);
                    }

                    batch.Addresses.Add(address);
                    grown.Add(batch);
                }

                // Write the rules that gain addresses first and delete what is left over last, so
                // there is no moment at start-up where existing bans are unenforced.
                foreach (var batch in batches.Where(b => b.Addresses.Count > 0).OrderByDescending(grown.Contains))
                {
                    WriteBatch(batch, ports);
                }

                foreach (var stale in batches.Where(b => b.Addresses.Count == 0))
                {
                    DeleteBatchRules(stale);
                }

                batches.RemoveAll(b => b.Addresses.Count == 0);
                batches.Sort((a, b) => a.Index.CompareTo(b.Index));
                _batchCache = batches;
                _appliedPortsKey = PortsKey(ports);
                _logger.LogInformation("Reconciled firewall rules: {Rules} rule(s) for {Addresses} address(es).", batches.Count, wanted.Count);
            }
            catch (Exception ex)
            {
                _batchCache = null;
                _logger.LogError(ex, "Failed to synchronize WinGuard firewall rules.");
            }
        }
    }

    /// <inheritdoc />
    public IReadOnlyList<string>? ListBlocked()
    {
        lock (_gate)
        {
            var results = new List<string>();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            try
            {
                // Fresh read from the live firewall; also refreshes the cache (self-heals drift).
                var batches = LoadBatches();
                _batchCache = batches;
                EnsurePortsApplied(batches, CurrentPorts());

                foreach (var batch in batches)
                {
                    foreach (var address in batch.Addresses)
                    {
                        if (seen.Add(address))
                        {
                            results.Add(address);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _batchCache = null;
                _logger.LogError(ex, "Failed to enumerate WinGuard firewall rules.");
                return null;
            }

            return results;
        }
    }

    /// <inheritdoc />
    public void ClearAll()
    {
        if (!TryClearAll(out var error))
        {
            _logger.LogError("Failed to clear WinGuard firewall rules: {Error}", error);
        }
    }

    /// <summary>
    /// Like <see cref="ClearAll"/> but reports failure instead of swallowing it: returns
    /// <see langword="false"/> when the store call failed OR WinGuard_Block_* rules are still
    /// present afterwards. The <c>--clear-firewall</c> CLI uses this to exit non-zero so the
    /// uninstaller can warn instead of orphaning permanent blocks (review S-M4).
    /// </summary>
    public bool TryClearAll(out string? error)
    {
        error = null;
        lock (_gate)
        {
            try
            {
                var rules = _store.ReadRules();
                foreach (var rule in rules)
                {
                    TryRemove(rule.Name);
                }

                _logger.LogInformation("Cleared {Count} WinGuard firewall rule(s).", rules.Count);

                var remaining = _store.ReadRules();
                _batchCache = null;
                if (remaining.Count > 0)
                {
                    error = $"{remaining.Count} WinGuard_Block_* rule(s) are still present after the clear attempt.";
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                _batchCache = null;
                error = ex.Message;
                return false;
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

            // dwCurrentState is an enumeration, not a bit mask.
            return status.dwCurrentState == ServiceControl.ServiceRunning;
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

    /// <summary>
    /// Parses one entry of a rule's remote-address list as Windows reports it. Windows rewrites what
    /// was written: an IPv4 host comes back as <c>1.2.3.4/255.255.255.255</c> (or <c>/32</c>) and an
    /// IPv6 host as the single-address range <c>a::1-a::1</c> (or <c>/128</c>). Real subnets
    /// (WinGuard's IPv6 aggregate bans and blacklisted ranges) are canonicalized to
    /// <c>network/prefix</c>.
    /// </summary>
    internal static bool TryParseRuleAddress(string? token, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(token))
        {
            return false;
        }

        var text = token.Trim();

        var slash = text.IndexOf('/');
        if (slash > 0)
        {
            if (!IpMatcher.TryNormalize(text[..slash], out var host))
            {
                return false;
            }

            var suffix = text[(slash + 1)..];
            var isIPv4 = !host.Contains(':');
            var isHostMask = isIPv4
                ? suffix is "255.255.255.255" or "32"
                : suffix == "128";
            if (isHostMask)
            {
                normalized = host;
                return true;
            }

            // A real subnet: canonicalize to network/prefix. IPv4 may come back with a
            // dotted netmask ("255.255.255.0") instead of a prefix length.
            if (isIPv4 && TryNetmaskToPrefix(suffix, out var maskPrefix))
            {
                normalized = host + "/" + maskPrefix.ToString(System.Globalization.CultureInfo.InvariantCulture);
                return true;
            }

            if (int.TryParse(suffix, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var prefix)
                && prefix is >= 0 and <= 128)
            {
                normalized = host + "/" + prefix.ToString(System.Globalization.CultureInfo.InvariantCulture);
                return true;
            }

            return false;
        }

        var dash = text.IndexOf('-');
        if (dash > 0)
        {
            if (IpMatcher.TryNormalize(text[..dash], out var from)
                && IpMatcher.TryNormalize(text[(dash + 1)..], out var to)
                && string.Equals(from, to, StringComparison.Ordinal))
            {
                normalized = from;
                return true;
            }

            return false;
        }

        return IpMatcher.TryNormalize(text, out normalized);
    }

    /// <summary>Normalizes a block/unblock target; see <see cref="IpMatcher.TryNormalizeBanTarget"/>.</summary>
    private static bool TryNormalizeTarget(string? value, out string target) =>
        IpMatcher.TryNormalizeBanTarget(value, out target);

    /// <summary>Converts an IPv4 dotted netmask to its prefix length, e.g. 255.255.255.0 → 24.</summary>
    private static bool TryNetmaskToPrefix(string suffix, out int prefix)
    {
        prefix = 0;
        if (!System.Net.IPAddress.TryParse(suffix, out var mask)
            || mask.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return false;
        }

        var bits = mask.GetAddressBytes();
        var ones = 0;
        var seenZero = false;
        foreach (var b in bits)
        {
            for (var i = 7; i >= 0; i--)
            {
                var bit = (b >> i) & 1;
                if (bit == 1)
                {
                    if (seenZero)
                    {
                        return false; // 255.0.255.0 is not a valid netmask
                    }

                    ones++;
                }
                else
                {
                    seenZero = true;
                }
            }
        }

        prefix = ones;
        return true;
    }

    // ---- rule plumbing ----

    private List<RuleBatch> GetBatches() => _batchCache ??= LoadBatches();

    /// <summary>Reads every <c>WinGuard_Block_*</c> rule into logical batches keyed by their index.</summary>
    private List<RuleBatch> LoadBatches()
    {
        var map = new Dictionary<int, RuleBatch>();
        foreach (var rule in _store.ReadRules())
        {
            if (!TryParseRuleName(rule.Name, out var index, out var kind))
            {
                continue;
            }

            if (!map.TryGetValue(index, out var batch))
            {
                batch = new RuleBatch { Index = index };
                map[index] = batch;
            }

            batch.ExistingKinds.Add(kind);
            foreach (var part in rule.RemoteAddresses.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (TryParseRuleAddress(part, out var normalized) && !batch.Addresses.Contains(normalized))
                {
                    batch.Addresses.Add(normalized);
                }
            }
        }

        return map.Values.OrderBy(b => b.Index).ToList();
    }

    /// <summary>
    /// Writes the batch's address list in the rule shape for the given port mode and removes the
    /// rule variants of the other mode when they exist.
    /// </summary>
    private void WriteBatch(RuleBatch batch, string[] ports)
    {
        // A rule with no remote addresses applies to every address. A batch gets here empty when
        // none of its rule's addresses could be parsed; such a rule must not be rewritten as "all".
        if (batch.Addresses.Count == 0)
        {
            DeleteBatchRules(batch);
            return;
        }

        var csv = string.Join(",", batch.Addresses);
        if (ports.Length == 0)
        {
            // All-ports mode: one Protocol=Any rule per batch.
            Upsert(batch, RuleKind.Any, ProtocolAny, null, csv);
            RemoveIfPresent(batch, RuleKind.Tcp);
            RemoveIfPresent(batch, RuleKind.Udp);
        }
        else
        {
            // Port mode: a TCP and a UDP rule sharing the same address batch (a single rule
            // cannot carry both protocols), both restricted to the configured LocalPorts.
            var portList = string.Join(",", ports);
            Upsert(batch, RuleKind.Tcp, ProtocolTcp, portList, csv);
            Upsert(batch, RuleKind.Udp, ProtocolUdp, portList, csv);
            RemoveIfPresent(batch, RuleKind.Any);
        }
    }

    private void Upsert(RuleBatch batch, RuleKind kind, int protocol, string? localPorts, string csv)
    {
        var name = RuleName(batch.Index, kind);
        _store.Upsert(name, protocol, localPorts, csv);
        if (batch.ExistingKinds.Add(kind))
        {
            _logger.LogInformation("Created firewall rule {Rule}.", name);
        }
    }

    private void RemoveIfPresent(RuleBatch batch, RuleKind kind)
    {
        if (batch.ExistingKinds.Remove(kind))
        {
            TryRemove(RuleName(batch.Index, kind));
        }
    }

    private void DeleteBatchRules(RuleBatch batch)
    {
        foreach (var kind in batch.ExistingKinds.ToArray())
        {
            TryRemove(RuleName(batch.Index, kind));
        }

        batch.ExistingKinds.Clear();
    }

    private void TryRemove(string name)
    {
        try
        {
            _store.Remove(name);
            _logger.LogInformation("Removed firewall rule {Rule}.", name);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Firewall rule {Rule} was not present or could not be removed.", name);
        }
    }

    /// <summary>
    /// Rewrites every batch when <see cref="WinGuardSettings.BlockedPorts"/> changed since the rules
    /// were last written, so a settings change also applies to bans that already exist.
    /// </summary>
    private void EnsurePortsApplied(List<RuleBatch> batches, string[] ports)
    {
        var key = PortsKey(ports);
        if (_appliedPortsKey is null)
        {
            // First use in this process without a SyncRules: trust what is in the firewall.
            _appliedPortsKey = key;
            return;
        }

        if (string.Equals(_appliedPortsKey, key, StringComparison.Ordinal))
        {
            return;
        }

        foreach (var batch in batches)
        {
            WriteBatch(batch, ports);
        }

        _appliedPortsKey = key;
        _logger.LogInformation("Blocked-ports setting changed; rewrote {Count} firewall rule batch(es).", batches.Count);
    }

    private static string PortsKey(string[] ports) => string.Join(",", ports);

    private static int NextFreeIndex(List<RuleBatch> batches)
    {
        var used = batches.Select(b => b.Index).ToHashSet();
        var index = 1;
        while (used.Contains(index))
        {
            index++;
        }

        return index;
    }

    private int MaxAddressesPerRule()
    {
        try
        {
            var configured = _settingsAccessor?.Invoke()?.MaxAddressesPerRule;
            if (configured is > 0)
            {
                return Math.Min(configured.Value, Defaults.MaxAddressesPerRule);
            }
        }
        catch (Exception)
        {
            // Fall back to the constructor value.
        }

        return _maxAddressesPerRule;
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

    private static string RuleName(int index) => RuleName(index, RuleKind.Any);

    private static string RuleName(int index, RuleKind kind) => kind switch
    {
        RuleKind.Tcp => $"{Defaults.RuleNamePrefix}{index:D4}_TCP",
        RuleKind.Udp => $"{Defaults.RuleNamePrefix}{index:D4}_UDP",
        _ => $"{Defaults.RuleNamePrefix}{index:D4}",
    };

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

        /// <summary>Which rule variants of this batch currently exist in the firewall.</summary>
        public HashSet<RuleKind> ExistingKinds { get; } = [];
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
