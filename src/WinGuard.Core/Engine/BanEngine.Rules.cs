using Microsoft.Extensions.Logging;
using WinGuard.Core.Config;
using WinGuard.Core.Model;

namespace WinGuard.Core.Engine;

/// <summary>
/// Detection rules beyond the per-protocol threshold: honeypot user names, password spraying and
/// slow brute force. A rule only says that an already recorded failure should ban; the ban itself
/// takes the normal path, so whitelist, exclusions, report-only and the tiers apply unchanged.
/// </summary>
public sealed partial class BanEngine
{
    /// <summary>
    /// Whether this duplicate carries a user name the rules can use. When the 140 half of an attempt
    /// arrives first it is counted without a name, and the name only comes with the 4625 dropped here.
    /// </summary>
    private static bool NamesCountedAttempt(FailedLogin failed, DetectionRuleSettings rules) =>
        failed.UserName is not null && (rules.HoneypotUsernames.Length > 0 || rules.SprayMaxUsernames > 0);

    /// <summary>Adds the user name to the row already counted for this attempt. Adds no count, so returns 0.</summary>
    private async Task<int> NameCountedAttemptAsync(FailedLogin failed, CancellationToken ct)
    {
        try
        {
            await _store.SetFailedLoginUserAsync(
                failed.IpAddress,
                failed.Source,
                failed.UserName!,
                failed.TimestampUtc - RdpDeduplicator.Window,
                ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _logger.LogWarning(ex, "Could not add the user name to the counted failure of {Ip}.", failed.IpAddress);
        }

        return 0;
    }

    /// <summary>
    /// Text naming the rule that bans this failure, null when none does. With every rule off this
    /// costs no query; each enabled rule adds one indexed read per failure.
    /// </summary>
    private async ValueTask<string?> EvaluateRulesAsync(
        FailedLogin failed,
        int count,
        int threshold,
        DetectionRuleSettings rules,
        DateTime now,
        CancellationToken ct)
    {
        var ip = failed.IpAddress;
        _cleanLogons.Remove(ip);

        if (rules.MatchHoneypot(failed.UserName) is { } honeypot)
        {
            return $"honeypot user '{honeypot}'";
        }

        // The normal threshold bans anyway, so the reads below would only change the wording.
        if (count >= threshold)
        {
            return null;
        }

        // A failure without a user name cannot add a distinct one.
        if (rules.SprayMaxUsernames > 0 && failed.UserName is not null)
        {
            var users = await CountDistinctUsersAsync(ip, now - rules.SprayWindow, ct).ConfigureAwait(false);
            if (users >= rules.SprayMaxUsernames)
            {
                return $"password spraying: {users} usernames in {FormatDuration(rules.SprayWindow)}";
            }
        }

        if (rules.SlowBruteForceThreshold > 0)
        {
            var (failures, _) = await CountAllFailuresAsync(ip, now - rules.SlowBruteForceWindow, ct).ConfigureAwait(false);
            if (failures >= rules.SlowBruteForceThreshold)
            {
                return $"slow brute force: {failures} failures in {FormatDuration(rules.SlowBruteForceWindow)}";
            }
        }

        return null;
    }

    /// <summary>User names this IP tried since then; <c>DOMAIN\bob</c>, <c>BOB</c> and <c>bob@example.com</c> are one user.</summary>
    private async Task<int> CountDistinctUsersAsync(string ip, DateTime since, CancellationToken ct)
    {
        try
        {
            var users = await _store.GetFailedLoginUsersAsync(ip, since, ct).ConfigureAwait(false);
            return users
                .Select(DetectionRuleSettings.CanonicalUserName)
                .OfType<string>()
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count();
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _logger.LogWarning(ex, "Could not read the user names tried from {Ip}.", ip);
            return 0;
        }
    }

    /// <summary>
    /// Failures of this IP across all engines since then, stored or held in memory during a store
    /// outage. <c>Complete</c> is false when the store could not be read, so the count is a lower bound.
    /// </summary>
    private async Task<(int Count, bool Complete)> CountAllFailuresAsync(string ip, DateTime since, CancellationToken ct)
    {
        var inMemory = _fallbackCounts.Count(ip, since);
        try
        {
            return (inMemory + await _store.CountFailedLoginsAsync(ip, since, null, ct).ConfigureAwait(false), true);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _logger.LogWarning(ex, "Could not read the stored failures of {Ip}.", ip);
            return (inMemory, false);
        }
    }
}
