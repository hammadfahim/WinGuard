using System.Net;
using Microsoft.Extensions.Logging;
using WinGuard.Core.Config;
using WinGuard.Core.Model;
using WinGuard.Core.Notifications;

namespace WinGuard.Core.Engine;

/// <summary>
/// Successful logons (Security 4624): an alert when an IP with failures or an active ban gets in,
/// and the optional short-lived trust of an administrator's IP. A success never counts as a failure
/// and never clears one, or an attacker could reset their own counters.
/// </summary>
public sealed partial class BanEngine
{
    private const int RdpLogonType = 10;

    // Longest user name shown in an event; a name comes from a log, so it is cut and cleaned first.
    private const int MaxDisplayedUserLength = 64;

    private const int MaxTrackedLogonIps = 50_000;
    private const int MaxReplayedSuccesses = 10_000;

    // An RDP logon logs a network and an RDP success, and a failed-then-working client keeps logging
    // on: one alert per IP this often is enough to look.
    private static readonly TimeSpan CompromiseAlertInterval = TimeSpan.FromHours(1);

    // How long an IP with no failures and no ban skips the store. A failure or manual ban ends it early.
    private static readonly TimeSpan CleanLogonLifetime = TimeSpan.FromMinutes(5);

    // The replays of the logon and failure channels run side by side, newest first, so a replayed
    // logon can arrive before the failures that led to it. It waits this long for them.
    private static readonly TimeSpan ReplaySettleDelay = TimeSpan.FromMinutes(1);

    // All of the below are accessed under _gate. Values are "until when".
    private readonly Dictionary<string, DateTime> _cleanLogons = new(StringComparer.Ordinal);
    private readonly Dictionary<string, DateTime> _compromiseAlertedUntil = new(StringComparer.Ordinal);

    // Deliberately memory only: this trust must end with the service.
    private readonly Dictionary<string, DateTime> _temporaryTrust = new(StringComparer.Ordinal);

    // A ban clears the IP's failed_logins rows, which would leave an alert with nothing to report.
    private readonly Dictionary<string, (int Failures, DateTime ExpiresUtc)> _failuresAtBan = new(StringComparer.Ordinal);

    private readonly List<ReplayedSuccess> _replayedSuccesses = [];

    private sealed record ReplayedSuccess(FailedLogin Logon, string Ip, string Identity, DateTime ReceivedUtc);

    /// <summary>
    /// The identity failures of this address are counted and banned under: the IPv6 prefix when
    /// aggregation applies, as worked out in <see cref="ProcessCoreAsync"/>.
    /// </summary>
    private string CountingIdentity(string ip, WinGuardSettings settings) =>
        !_matcher.IsBlacklisted(ip)
        && settings.Ipv6AggregatePrefixLength > 0
        && ip.Contains(':')
        && IpMatcher.TryAggregateIpv6(ip, settings.Ipv6AggregatePrefixLength, out var prefix)
        && !_matcher.OverlapsWhitelist(prefix)
        && !OverlapsTemporaryTrust(prefix)
            ? prefix
            : ip;

    /// <summary>Handles one successful logon. Reads the store only for an IP not known to be clean.</summary>
    private async Task ProcessSuccessCoreAsync(FailedLogin logon, CancellationToken ct)
    {
        var settings = _settingsAccessor();
        var rules = settings.Rules;
        if (!rules.ObservesLogons() || !IpMatcher.TryNormalize(logon.IpAddress, out var ip) || !IpMatcher.IsBannable(ip))
        {
            return;
        }

        logon.TimestampUtc = NormalizeUtc(logon.TimestampUtc);
        if (logon.IsReplayed && logon.TimestampUtc <= _replayCutoffUtc)
        {
            return;
        }

        await EnsureListsLoadedCoreAsync(ct).ConfigureAwait(false);
        if ((!settings.ProcessInternalIPs && IpMatcher.IsInternal(ip))
            || _matcher.IsWhitelisted(ip)
            || IsTemporarilyTrusted(ip, settings))
        {
            return;
        }

        var identity = CountingIdentity(ip, settings);
        var now = NowUtc();

        // A replayed logon is old news: it may alert, but it must never grant trust, or a restart
        // would bring back what must end with the service. A live logon right after a restart waits
        // with it: "no failures" means nothing while those of the downtime are still on their way.
        if (logon.IsReplayed || ReplayMayBeRunning(now))
        {
            if (rules.CompromiseAlerts && _replayedSuccesses.Count < MaxReplayedSuccesses)
            {
                _replayedSuccesses.Add(new ReplayedSuccess(logon, ip, identity, now));
            }

            return;
        }

        var mayTrust = MayTrust(logon, ip, rules);
        if (!mayTrust
            && (!rules.CompromiseAlerts || IsStill(_cleanLogons, identity, now) || IsStill(_compromiseAlertedUntil, identity, now)))
        {
            return;
        }

        var (failures, complete) = await CountAllFailuresAsync(identity, now - rules.CompromiseWindow, ct).ConfigureAwait(false);
        var (ban, banKnown) = await GetActiveBanAsync(identity, now, ct).ConfigureAwait(false);
        complete &= banKnown;
        var suspicious = ban is not null || failures >= rules.CompromiseMinFailures;
        if (rules.CompromiseAlerts && suspicious)
        {
            await AlertCompromiseAsync(logon, ip, identity, failures, ban, now, ct).ConfigureAwait(false);
            return;
        }

        if (mayTrust && ban is null && failures == 0 && complete)
        {
            await TryTrustAsync(logon, ip, identity, settings, now, ct).ConfigureAwait(false);
        }

        if (ban is null && failures == 0 && complete)
        {
            if (_cleanLogons.Count >= MaxTrackedLogonIps)
            {
                _cleanLogons.Clear();
            }

            _cleanLogons[identity] = now + CleanLogonLifetime;
        }
    }

    private static bool IsStill(Dictionary<string, DateTime> untilByIp, string ip, DateTime now) =>
        untilByIp.TryGetValue(ip, out var until) && until > now;

    /// <summary>Whether the start-up replay can still be delivering: a first start has nothing to replay.</summary>
    private bool ReplayMayBeRunning(DateTime now) =>
        _replayCutoffUtc < _startedUtc && now - _startedUtc < ReplaySettleDelay;

    /// <summary>The ban in force for this identity. <c>Known</c> is false when the store could not say.</summary>
    private async Task<(BanEntry? Ban, bool Known)> GetActiveBanAsync(string identity, DateTime now, CancellationToken ct)
    {
        var (ban, known) = await FindBanAsync(identity, ct).ConfigureAwait(false);
        return (ban is not null && (ban.IsPermanent || ban.ExpiresUtc > now) ? ban : null, known);
    }

    /// <summary>Remembers how many failures led to a ban: the ban deletes the rows that say so.</summary>
    private void RememberFailuresAtBan(string ip, int failures, DateTime expiresUtc, DetectionRuleSettings rules)
    {
        if (rules.CompromiseAlerts)
        {
            _failuresAtBan[ip] = (Math.Max(1, failures), expiresUtc);
        }
    }

    private async Task AlertCompromiseAsync(FailedLogin logon, string ip, string identity, int failures, BanEntry? ban, DateTime now, CancellationToken ct)
    {
        if (_compromiseAlertedUntil.Count >= MaxTrackedLogonIps)
        {
            _compromiseAlertedUntil.Clear();
        }

        _compromiseAlertedUntil[identity] = now + CompromiseAlertInterval;

        var attempts = failures + (ban is not null && _failuresAtBan.TryGetValue(identity, out var atBan) ? atBan.Failures : 0);
        var user = DisplayUser(logon.UserName);
        var message = $"{WinGuardEventIds.CompromisePrefix}{user} logged on from {ip} after {attempts} failed attempt(s)";
        _logger.LogWarning("{Message}", message);

        await AddBanHistoryCoreAsync(new BanHistoryEntry
        {
            TimestampUtc = now,
            Action = BanHistoryAction.SuspiciousLogon,
            IpAddress = identity,
            Source = ban?.Source ?? logon.Source,
            OffenseCount = ban?.OffenseCount ?? _offenses.GetCount(identity),
            IsPermanent = ban?.IsPermanent ?? false,
            Note = $"{user} logged on from {ip} after {attempts} failed attempt(s)",
        }, ct).ConfigureAwait(false);

        await TryAddEventAsync(new LogEvent
        {
            TimestampUtc = now,
            Level = LogEventLevel.Warning,
            Source = logon.Source,
            IpAddress = identity,
            Message = message,
        }, ct).ConfigureAwait(false);
    }

    private bool MayTrust(FailedLogin logon, string ip, DetectionRuleSettings rules) =>
        rules.TrustAdminIpHours > 0
        && logon.LogonType == RdpLogonType
        && rules.MatchHoneypot(logon.UserName) is null
        && !_matcher.IsBlacklisted(ip);

    /// <summary>
    /// Trusts an IP after the checks that need the store. Failures count back as far as they are
    /// kept, and past offenses count too: a ban deleted the rows of the failures that led to it.
    /// </summary>
    private async Task TryTrustAsync(FailedLogin logon, string ip, string identity, WinGuardSettings settings, DateTime now, CancellationToken ct)
    {
        var (failures, complete) = await CountAllFailuresAsync(identity, now - settings.ExpireTime, ct).ConfigureAwait(false);
        if (failures > 0 || !complete || _offenses.GetCount(identity) > 0)
        {
            return;
        }

        if (_temporaryTrust.Count >= MaxTrackedLogonIps)
        {
            _temporaryTrust.Clear();
        }

        var duration = TimeSpan.FromHours(settings.Rules.TrustAdminIpHours);
        _temporaryTrust[ip] = now + duration;

        var message = $"TEMPORARILY TRUSTED {ip} for {FormatDuration(duration)} after RDP logon by {DisplayUser(logon.UserName)}";
        _logger.LogWarning("{Message}", message);
        await TryAddEventAsync(new LogEvent
        {
            TimestampUtc = now,
            Level = LogEventLevel.Warning,
            Source = logon.Source,
            IpAddress = ip,
            Message = message,
        }, ct).ConfigureAwait(false);
    }

    /// <summary>True for an IP trusted right now. The live setting and the blacklist can end it early.</summary>
    private bool IsTemporarilyTrusted(string ip, WinGuardSettings settings)
    {
        if (_temporaryTrust.Count == 0)
        {
            return false;
        }

        if (settings.Rules.TrustAdminIpHours <= 0)
        {
            _temporaryTrust.Clear();
            return false;
        }

        return IsStill(_temporaryTrust, ip, NowUtc()) && !_matcher.IsBlacklisted(ip);
    }

    /// <summary>
    /// True when a range holds a trusted address. Such a prefix stays on per-address bans: a block
    /// rule for it would lock out the administrator the trust is for.
    /// </summary>
    private bool OverlapsTemporaryTrust(string range) =>
        _temporaryTrust.Count != 0
        && IpMatcher.TryParseCidr(range, out var network)
        && _temporaryTrust.Keys.Any(ip => IPAddress.TryParse(ip, out var address) && network.Contains(address));

    /// <summary>An administrator's block outranks the trust, and the IP is no longer known to be clean.</summary>
    private void ForgetLogonState(string ip)
    {
        _temporaryTrust.Remove(ip);
        _cleanLogons.Remove(ip);
    }

    /// <summary>Evaluates replayed logons whose failures have had time to arrive, or all of them on stop.</summary>
    private async Task EvaluateReplayedSuccessesAsync(DateTime now, bool all, CancellationToken ct)
    {
        if (_replayedSuccesses.Count == 0)
        {
            return;
        }

        var rules = _settingsAccessor().Rules;
        var due = _replayedSuccesses.Where(replayed => all || now - replayed.ReceivedUtc >= ReplaySettleDelay).ToList();
        _replayedSuccesses.RemoveRange(0, due.Count);
        foreach (var replayed in due)
        {
            if (rules.CompromiseAlerts && !IsStill(_compromiseAlertedUntil, replayed.Identity, now))
            {
                await EvaluateReplayedSuccessAsync(replayed, rules, now, ct).ConfigureAwait(false);
            }
        }
    }

    private async Task EvaluateReplayedSuccessAsync(ReplayedSuccess replayed, DetectionRuleSettings rules, DateTime now, CancellationToken ct)
    {
        // Only what came before the logon led to it.
        var loggedOn = replayed.Logon.TimestampUtc;
        var (upToNow, _) = await CountAllFailuresAsync(replayed.Identity, loggedOn - rules.CompromiseWindow, ct).ConfigureAwait(false);
        var (afterLogon, _) = await CountAllFailuresAsync(replayed.Identity, loggedOn.AddTicks(1), ct).ConfigureAwait(false);
        var failures = upToNow - afterLogon;

        var (ban, _) = await GetActiveBanAsync(replayed.Identity, now, ct).ConfigureAwait(false);
        if (ban is not null || failures >= rules.CompromiseMinFailures)
        {
            await AlertCompromiseAsync(replayed.Logon, replayed.Ip, replayed.Identity, failures, ban, now, ct).ConfigureAwait(false);
        }
    }

    private async Task HousekeepLogonsAsync(DateTime now, CancellationToken ct)
    {
        RemoveExpired(_cleanLogons, now);
        RemoveExpired(_compromiseAlertedUntil, now);
        RemoveExpired(_temporaryTrust, now);
        foreach (var ip in _failuresAtBan.Where(pair => pair.Value.ExpiresUtc <= now).Select(pair => pair.Key).ToList())
        {
            _failuresAtBan.Remove(ip);
        }

        await EvaluateReplayedSuccessesAsync(now, all: false, ct).ConfigureAwait(false);
    }

    private static void RemoveExpired(Dictionary<string, DateTime> untilByIp, DateTime now)
    {
        foreach (var ip in untilByIp.Where(pair => pair.Value <= now).Select(pair => pair.Key).ToList())
        {
            untilByIp.Remove(ip);
        }
    }

    /// <summary>A user name from a log, safe to put in an event: one line, bounded.</summary>
    private static string DisplayUser(string? userName)
    {
        if (string.IsNullOrWhiteSpace(userName))
        {
            return "(unknown)";
        }

        var clean = new string(userName.Trim().Select(c => char.IsControl(c) ? '?' : c).ToArray());
        return clean.Length > MaxDisplayedUserLength ? clean[..MaxDisplayedUserLength] : clean;
    }
}
