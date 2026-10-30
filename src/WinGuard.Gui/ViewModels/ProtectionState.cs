namespace WinGuard.Gui.ViewModels;

/// <summary>The one overall state the console reports, in the banner and the dashboard hero.</summary>
public enum ProtectionKind
{
    /// <summary>The first connection attempt has not finished.</summary>
    Connecting,

    /// <summary>Connected, enforcing, every enabled engine running.</summary>
    Protected,

    /// <summary>Connected and enforcing, but an enabled engine has stopped.</summary>
    Degraded,

    /// <summary>Monitoring only: bans are recorded, not enforced.</summary>
    ReportOnly,

    /// <summary>The Windows Firewall service is stopped, so bans have no effect.</summary>
    FirewallOff,

    /// <summary>The service is up, but no engine is watching anything.</summary>
    NotWatching,

    /// <summary>The service is not running.</summary>
    ServiceDown,

    /// <summary>The service is there but cannot be used by this console.</summary>
    Refused,
}

/// <summary>Everything the overall state is derived from.</summary>
/// <param name="Connected">The service answered on the current connection.</param>
/// <param name="ConnectionSettled">The first connection attempt has finished, so "not connected" is an answer.</param>
/// <param name="Problem">Why the service cannot be used, when it is there.</param>
/// <param name="ReportOnly">The service runs in monitoring mode.</param>
/// <param name="FirewallRunning">Windows Firewall state; null until first checked.</param>
/// <param name="EnginesEnabled">Enabled engines.</param>
/// <param name="EnginesRunning">Enabled engines that are running.</param>
/// <param name="ActiveBans">Current ban count.</param>
public sealed record ProtectionInputs(
    bool Connected,
    bool ConnectionSettled,
    string? Problem,
    bool ReportOnly,
    bool? FirewallRunning,
    int EnginesEnabled,
    int EnginesRunning,
    int ActiveBans);

/// <summary>The overall state, worded for people.</summary>
/// <param name="Kind">Which state this is.</param>
/// <param name="Tone">What it means.</param>
/// <param name="Glyph">Icon, so the state never rests on colour alone.</param>
/// <param name="Title">Short headline.</param>
/// <param name="Detail">One sentence of consequence.</param>
/// <param name="CanRetry">Offers Retry.</param>
/// <param name="CanStartService">Offers Start service.</param>
/// <param name="CanReview">Offers a link to the setting behind this state.</param>
public sealed record ProtectionSummary(
    ProtectionKind Kind,
    Tone Tone,
    string Glyph,
    string Title,
    string Detail,
    bool CanRetry = false,
    bool CanStartService = false,
    bool CanReview = false);

/// <summary>
/// Pure decision of the overall state. When several things are wrong at once the one with the worst
/// consequence wins, and the rest is mentioned in the detail where it still matters.
/// </summary>
public static class ProtectionEvaluator
{
    private const string GlyphCheck = "";
    private const string GlyphWarning = "";
    private const string GlyphError = "";
    private const string GlyphEye = "";
    private const string GlyphPlug = "";
    private const string GlyphSync = "";

    /// <summary>Decides the state.</summary>
    public static ProtectionSummary Evaluate(ProtectionInputs input)
    {
        if (!input.Connected)
        {
            if (!string.IsNullOrEmpty(input.Problem))
            {
                return new ProtectionSummary(
                    ProtectionKind.Refused, Tone.Attack, GlyphError, "Cannot reach the service", input.Problem, CanRetry: true);
            }

            return input.ConnectionSettled
                ? new ProtectionSummary(
                    ProtectionKind.ServiceDown,
                    Tone.Attack,
                    GlyphPlug,
                    "Service down",
                    "The WinGuard service is not running. Nothing is being detected or blocked.",
                    CanRetry: true,
                    CanStartService: true)
                : new ProtectionSummary(ProtectionKind.Connecting, Tone.Neutral, GlyphSync, "Connecting", "Looking for the WinGuard service.");
        }

        var firewallOff = input.FirewallRunning == false;
        if (firewallOff && !input.ReportOnly)
        {
            return new ProtectionSummary(
                ProtectionKind.FirewallOff,
                Tone.Attack,
                GlyphError,
                "Firewall off",
                $"The Windows Firewall service (MpsSvc) is stopped, so {Bans(input.ActiveBans)} no effect.",
                CanRetry: true);
        }

        if (input.EnginesRunning == 0)
        {
            return new ProtectionSummary(
                ProtectionKind.NotWatching,
                Tone.Warn,
                GlyphWarning,
                input.EnginesEnabled == 0 ? "No engines enabled" : "No engines running",
                input.EnginesEnabled == 0
                    ? "Every detection engine is switched off, so no new attacks are noticed."
                    : "Enabled engines have stopped, so no new attacks are noticed. Check the service log.",
                CanReview: true);
        }

        if (input.ReportOnly)
        {
            return new ProtectionSummary(
                ProtectionKind.ReportOnly,
                Tone.Warn,
                GlyphEye,
                "Report-only",
                firewallOff
                    ? "Monitoring without blocking. The Windows Firewall service is also stopped: start it before you switch to enforcing."
                    : "Monitoring without blocking: would-be bans are recorded, and enforced the moment this is switched off.",
                CanReview: true);
        }

        if (input.EnginesRunning < input.EnginesEnabled)
        {
            var stopped = input.EnginesEnabled - input.EnginesRunning;
            return new ProtectionSummary(
                ProtectionKind.Degraded,
                Tone.Warn,
                GlyphWarning,
                "Partly protected",
                stopped == 1
                    ? "One enabled engine has stopped. The others are still watching and blocking."
                    : $"{stopped} enabled engines have stopped. The others are still watching and blocking.");
        }

        return new ProtectionSummary(
            ProtectionKind.Protected,
            Tone.Protected,
            GlyphCheck,
            "Protected",
            input.EnginesRunning == 1
                ? "1 engine is watching and the firewall is enforcing bans."
                : $"{input.EnginesRunning} engines are watching and the firewall is enforcing bans.");
    }

    private static string Bans(int count) => count switch
    {
        0 => "new bans would have",
        1 => "the 1 active ban has",
        _ => $"the {count:N0} active bans have",
    };
}
