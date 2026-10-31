using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using WinGuard.Core.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Engine;
using WinGuard.Core.Model;

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
/// Each distinct <see cref="PortSet"/> has its own family of batches, so the rule count follows the
/// sets in use, not the number of bans. All ports use a single rule with <c>Protocol = Any</c> per
/// batch (cheapest: one condition per IP) under the plain name above. Any other set keeps a TCP and
/// a UDP rule pair per batch with <c>LocalPorts</c> set, because a single rule cannot mix the two
/// protocols: <c>WinGuard_Block_P1A2B3C4D_0001_TCP</c> and <c>_UDP</c>, with the set's
/// <see cref="PortSet.RuleFamily"/> in the name so a fresh process can tell what a rule covers. All
/// of them start with <see cref="Defaults.RuleNamePrefix"/>, so <see cref="ClearAll"/> and
/// <see cref="ListBlocked"/> see them. Which ports a target gets is the engine's decision: a pair
/// named <c>WinGuard_Block_0001_TCP</c> comes from a version that decided it here, and
/// <see cref="SyncRules(IEnumerable{FirewallTarget})"/> moves its addresses into their family.
/// </para>
/// <para>
/// The batches are cached in memory (guarded by one lock) so a block or unblock is a single rule
/// write instead of an enumeration of every firewall rule. <see cref="ListBlocked"/> (called by the
/// engine's reconcile pass) re-reads the live firewall and refreshes the cache; any failure drops
/// the cache so the next call reloads it.
/// </para>
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsFirewall : IFirewall, IFirewallRuleCounter
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

    // The first sync of a process writes every rule, which also re-enables one an administrator
    // switched off. Later ones write what changed: a blocklist can span dozens of rules.
    private bool _allRulesWritten;

    /// <summary>
    /// Creates the firewall wrapper over the Windows Firewall COM API.
    /// </summary>
    /// <param name="logger">Diagnostic logger.</param>
    /// <param name="maxAddressesPerRule">
    /// Fallback maximum number of remote addresses per batch rule, used when no settings accessor is
    /// supplied; otherwise <see cref="WinGuardSettings.MaxAddressesPerRule"/> is read live.
    /// </param>
    /// <param name="settingsAccessor">
    /// Optional live-settings accessor used to read <see cref="WinGuardSettings.MaxAddressesPerRule"/>.
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
    public int? CachedRuleCount
    {
        get
        {
            lock (_gate)
            {
                return _batchCache?.Sum(batch => batch.ExistingKinds.Count);
            }
        }
    }

    /// <inheritdoc />
    public void Block(string ipOrRange) => Block(ipOrRange, PortSet.All);

    /// <inheritdoc />
    public void Block(string ipOrRange, PortSet ports)
    {
        ArgumentNullException.ThrowIfNull(ports);
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
                var holders = batches.Where(b => b.Addresses.Contains(normalized)).ToList();
                var settled = holders.Find(b => b.HoldsFamily(ports));
                if (settled is not null && holders.Count == 1)
                {
                    _logger.LogDebug("Address {Ip} is already present in firewall rule {Rule}; nothing to do.", normalized, RuleName(settled));
                    return;
                }

                // Into the new rule first: leaving the old one first would open a gap in the block.
                if (settled is null)
                {
                    var target = FindOrAddBatch(batches, ports.RuleFamily, MaxAddressesPerRule());
                    target.Addresses.Add(normalized);
                    WriteBatch(target, ports);
                    batches.Sort(CompareBatches);
                    _logger.LogInformation("Blocked {Ip} in firewall rule {Rule} ({Count} addresses).", normalized, RuleName(target), target.Addresses.Count);
                }

                foreach (var other in holders.Where(b => b != settled))
                {
                    RemoveAddress(batches, other, normalized);
                }
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

                // More than one holds it only if the process died in the middle of a move.
                var holders = batches.Where(b => b.Addresses.Contains(normalized)).ToList();
                if (holders.Count == 0)
                {
                    _logger.LogDebug("IP {Ip} was not present in any WinGuard firewall rule; nothing to do.", normalized);
                    return;
                }

                foreach (var holder in holders)
                {
                    RemoveAddress(batches, holder, normalized);
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
        if (targets is not null)
        {
            SyncRules(targets.Select(target => new FirewallTarget(target, PortSet.All)));
        }
    }

    /// <inheritdoc />
    public void SyncRules(IEnumerable<FirewallTarget> targets)
    {
        if (targets is null)
        {
            return;
        }

        lock (_gate)
        {
            try
            {
                var max = MaxAddressesPerRule();

                // One family per address. Named twice, the wider block wins.
                var wanted = new Dictionary<string, PortSet>(StringComparer.Ordinal);
                foreach (var target in targets)
                {
                    if (TryNormalizeTarget(target.Address, out var normalized))
                    {
                        wanted[normalized] = wanted.TryGetValue(normalized, out var known) ? known.Union(target.Ports) : target.Ports;
                    }
                }

                // Every address stays in the rule that already holds it: moving one between rules
                // would leave it unenforced from the first rule's write until the second's. It moves
                // only when its ports changed or MaxAddressesPerRule was lowered, and the write order
                // below covers both.
                var unplaced = new HashSet<string>(wanted.Keys, StringComparer.Ordinal);
                var batches = LoadBatches();
                var shrunk = new HashSet<RuleBatch>();
                foreach (var batch in batches)
                {
                    var kept = batch.Addresses
                        .Where(address => unplaced.Contains(address) && batch.HoldsFamily(wanted[address]))
                        .Take(max)
                        .ToList();
                    unplaced.ExceptWith(kept);
                    if (kept.Count != batch.Addresses.Count)
                    {
                        shrunk.Add(batch);
                    }

                    batch.Addresses.Clear();
                    batch.Addresses.AddRange(kept);
                }

                var grown = new HashSet<RuleBatch>();
                foreach (var (address, ports) in wanted.Where(pair => unplaced.Contains(pair.Key)))
                {
                    var batch = FindOrAddBatch(batches, ports.RuleFamily, max);
                    batch.Addresses.Add(address);
                    grown.Add(batch);
                }

                // Write the rules that gain addresses first and delete what is left over last, so
                // there is no moment at start-up where existing bans are unenforced. A rule that also
                // loses some waits for those that only gain, which is where the addresses went.
                var portsOfFamily = wanted.Values.DistinctBy(set => set.RuleFamily).ToDictionary(set => set.RuleFamily);
                var changed = batches
                    .Where(b => b.Addresses.Count > 0 && (!_allRulesWritten || grown.Contains(b) || shrunk.Contains(b)))
                    .OrderBy(b => (grown.Contains(b) ? 0 : 2) + (shrunk.Contains(b) ? 1 : 0))
                    .ToList();
                foreach (var batch in changed)
                {
                    WriteBatch(batch, portsOfFamily[batch.Family]);
                }

                foreach (var stale in batches.Where(b => b.Addresses.Count == 0))
                {
                    DeleteBatchRules(stale);
                }

                batches.RemoveAll(b => b.Addresses.Count == 0);
                batches.Sort(CompareBatches);
                _batchCache = batches;
                _allRulesWritten = true;
                _logger.LogInformation("Reconciled firewall rules: {Rules} batch(es) for {Addresses} address(es), {Written} written.", batches.Count, wanted.Count, changed.Count);
            }
            catch (Exception ex)
            {
                _batchCache = null;
                _logger.LogError(ex, "Failed to synchronize WinGuard firewall rules.");
            }
        }
    }

    /// <inheritdoc />
    public IReadOnlyList<string>? ListBlocked() =>
        ListBlockedTargets()?.Select(target => target.Address).Distinct(StringComparer.Ordinal).ToList();

    /// <inheritdoc />
    public IReadOnlyList<BlockedTarget>? ListBlockedTargets()
    {
        lock (_gate)
        {
            try
            {
                // Fresh read from the live firewall; also refreshes the cache (self-heals drift).
                var batches = LoadBatches();
                _batchCache = batches;
                return batches
                    .SelectMany(batch => batch.Addresses.Select(address => new BlockedTarget(address, batch.ReportedFamily)))
                    .Distinct()
                    .ToList();
            }
            catch (Exception ex)
            {
                _batchCache = null;
                _logger.LogError(ex, "Failed to enumerate WinGuard firewall rules.");
                return null;
            }
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

    /// <summary>Reads every <c>WinGuard_Block_*</c> rule into logical batches keyed by family and index.</summary>
    private List<RuleBatch> LoadBatches()
    {
        var map = new Dictionary<(string Family, int Index), RuleBatch>();
        var seen = new Dictionary<RuleBatch, HashSet<string>>();
        foreach (var rule in _store.ReadRules())
        {
            if (!TryParseRuleName(rule.Name, out var family, out var index, out var kind))
            {
                continue;
            }

            if (!map.TryGetValue((family, index), out var batch))
            {
                batch = new RuleBatch { Family = family, Index = index };
                map[(family, index)] = batch;
                seen[batch] = new HashSet<string>(StringComparer.Ordinal);
            }

            batch.ExistingKinds.Add(kind);
            foreach (var part in rule.RemoteAddresses.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (TryParseRuleAddress(part, out var normalized) && seen[batch].Add(normalized))
                {
                    batch.Addresses.Add(normalized);
                }
            }
        }

        var batches = map.Values.ToList();
        batches.Sort(CompareBatches);
        return batches;
    }

    /// <summary>
    /// Writes the batch's address list in the rule shape for the given ports and removes the rule
    /// variants of the other shape when they exist.
    /// </summary>
    private void WriteBatch(RuleBatch batch, PortSet ports)
    {
        // A rule with no remote addresses applies to every address. A batch gets here empty when
        // none of its rule's addresses could be parsed; such a rule must not be rewritten as "all".
        if (batch.Addresses.Count == 0)
        {
            DeleteBatchRules(batch);
            return;
        }

        var csv = string.Join(",", batch.Addresses);
        if (ports.IsAll)
        {
            // All ports: one Protocol=Any rule per batch.
            Upsert(batch, RuleKind.Any, null, csv);
            RemoveIfPresent(batch, RuleKind.Tcp);
            RemoveIfPresent(batch, RuleKind.Udp);
        }
        else
        {
            // Ports: a TCP and a UDP rule sharing the same address batch (a single rule cannot
            // carry both protocols), both restricted to the set's LocalPorts.
            Upsert(batch, RuleKind.Tcp, ports.Text, csv);
            Upsert(batch, RuleKind.Udp, ports.Text, csv);
            RemoveIfPresent(batch, RuleKind.Any);
        }
    }

    /// <summary>Takes one address out of a batch, leaving its rules' ports as they are.</summary>
    private void RemoveAddress(List<RuleBatch> batches, RuleBatch batch, string address)
    {
        batch.Addresses.Remove(address);
        if (batch.Addresses.Count == 0)
        {
            DeleteBatchRules(batch);
            batches.Remove(batch);
            _logger.LogInformation("Unblocked {Ip}; firewall rule {Rule} is now empty and was removed.", address, RuleName(batch));
            return;
        }

        var csv = string.Join(",", batch.Addresses);
        foreach (var kind in batch.ExistingKinds)
        {
            _store.Upsert(RuleName(batch, kind), ProtocolOf(kind), null, csv);
        }

        _logger.LogInformation("Unblocked {Ip} from firewall rule {Rule} ({Count} addresses remain).", address, RuleName(batch), batch.Addresses.Count);
    }

    private void Upsert(RuleBatch batch, RuleKind kind, string? localPorts, string csv)
    {
        var name = RuleName(batch, kind);
        _store.Upsert(name, ProtocolOf(kind), localPorts, csv);
        if (batch.ExistingKinds.Add(kind))
        {
            _logger.LogInformation("Created firewall rule {Rule}.", name);
        }
    }

    private void RemoveIfPresent(RuleBatch batch, RuleKind kind)
    {
        if (batch.ExistingKinds.Remove(kind))
        {
            TryRemove(RuleName(batch, kind));
        }
    }

    private void DeleteBatchRules(RuleBatch batch)
    {
        foreach (var kind in batch.ExistingKinds.ToArray())
        {
            TryRemove(RuleName(batch, kind));
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

    /// <summary>The first batch of the family with room (never an older pair), or a new one.</summary>
    private static RuleBatch FindOrAddBatch(List<RuleBatch> batches, string family, int max)
    {
        var batch = batches.Find(b => b.Family == family && !b.IsOlderPair && b.Addresses.Count < max);
        if (batch is null)
        {
            batch = new RuleBatch { Family = family, Index = NextFreeIndex(batches, family) };
            batches.Add(batch);
        }

        return batch;
    }

    private static int NextFreeIndex(List<RuleBatch> batches, string family)
    {
        var used = batches.Where(b => b.Family == family).Select(b => b.Index).ToHashSet();
        var index = 1;
        while (used.Contains(index))
        {
            index++;
        }

        return index;
    }

    private static int CompareBatches(RuleBatch a, RuleBatch b)
    {
        var family = string.CompareOrdinal(a.Family, b.Family);
        return family != 0 ? family : a.Index.CompareTo(b.Index);
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

    private static int ProtocolOf(RuleKind kind) => kind switch
    {
        RuleKind.Tcp => ProtocolTcp,
        RuleKind.Udp => ProtocolUdp,
        _ => ProtocolAny,
    };

    private static string RuleName(RuleBatch batch, RuleKind kind = RuleKind.Any)
    {
        var family = batch.Family.Length == 0 ? string.Empty : batch.Family + "_";
        var name = $"{Defaults.RuleNamePrefix}{family}{batch.Index:D4}";
        return kind switch
        {
            RuleKind.Tcp => name + "_TCP",
            RuleKind.Udp => name + "_UDP",
            _ => name,
        };
    }

    private static bool TryParseRuleName(string? name, out string family, out int index, out RuleKind kind)
    {
        family = string.Empty;
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

        var separator = remainder.IndexOf('_');
        if (separator >= 0)
        {
            family = remainder[..separator].ToUpperInvariant();
            remainder = remainder[(separator + 1)..];
            if (!PortSet.IsRuleFamily(family))
            {
                return false;
            }
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
        /// <summary>The <see cref="PortSet.RuleFamily"/> of the ports this batch's rules cover.</summary>
        public string Family { get; init; } = string.Empty;

        public int Index { get; init; }

        public List<string> Addresses { get; } = [];

        /// <summary>Which rule variants of this batch currently exist in the firewall.</summary>
        public HashSet<RuleKind> ExistingKinds { get; } = [];

        /// <summary>A rule pair from before families: its name does not say what it covers.</summary>
        public bool IsOlderPair => Family.Length == 0 && (ExistingKinds.Contains(RuleKind.Tcp) || ExistingKinds.Contains(RuleKind.Udp));

        public string ReportedFamily => IsOlderPair ? BlockedTarget.OlderRuleFamily : Family;

        public bool HoldsFamily(PortSet ports) => Family == ports.RuleFamily && !IsOlderPair;
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
