using System.Globalization;
using WinGuard.Gui.Services;

namespace WinGuard.Gui.ViewModels;

/// <summary>The one overall state the console reports, in the banner and the dashboard hero.</summary>
public enum ProtectionKind
{
    /// <summary>Break-glass is on: WinGuard holds no firewall rules. Outranks everything else.</summary>
    Disarmed,

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

    /// <summary>The firewall runs, but its policy keeps WinGuard's rules from doing anything.</summary>
    RulesIneffective,

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
/// <param name="Disarmed">The last status said a break-glass window is open.</param>
/// <param name="DisarmedUntilUtc">When that window ends by itself.</param>
/// <param name="RulesIneffective">The firewall policy keeps WinGuard's rules from taking effect.</param>
/// <param name="NowUtc">The time, for the countdown.</param>
public sealed record ProtectionInputs(
    bool Connected,
    bool ConnectionSettled,
    string? Problem,
    bool ReportOnly,
    bool? FirewallRunning,
    int EnginesEnabled,
    int EnginesRunning,
    int ActiveBans,
    bool Disarmed = false,
    DateTime? DisarmedUntilUtc = null,
    bool RulesIneffective = false,
    DateTime NowUtc = default);

/// <summary>The overall state, worded for people.</summary>
/// <param name="Kind">Which state this is.</param>
/// <param name="Tone">What it means.</param>
/// <param name="Glyph">Icon, so the state never rests on colour alone.</param>
/// <param name="Title">Short headline.</param>
/// <param name="Detail">One sentence of consequence.</param>
/// <param name="CanRetry">Offers Retry.</param>
/// <param name="CanStartService">Offers Start service.</param>
/// <param name="CanReview">Offers a link to the setting behind this state.</param>
/// <param name="Countdown">What is left of a limited state, as a live count; empty otherwise.</param>
/// <param name="Tray">The tray's words, when the title alone would say too little; empty otherwise.</param>
public sealed record ProtectionSummary(
    ProtectionKind Kind,
    Tone Tone,
    string Glyph,
    string Title,
    string Detail,
    bool CanRetry = false,
    bool CanStartService = false,
    bool CanReview = false,
    string Countdown = "",
    string Tray = "")
{
    /// <summary>What the tray icon says. Windows cuts it off, so it stays short, and it must not tick.</summary>
    public string TrayText => Tray.Length > 0 ? Tray : Title;
}

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
        // First, ahead of the connection: nothing is enforced whatever else is true, and a service
        // that stops answering during a window does not end the window. Its end is known, so a
        // stale answer cannot outlast it.
        if (input.Disarmed && (input.DisarmedUntilUtc is not { } until || until > input.NowUtc))
        {
            return Disarmed(input);
        }

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

        if (input.RulesIneffective && !input.ReportOnly)
        {
            return new ProtectionSummary(
                ProtectionKind.RulesIneffective,
                Tone.Attack,
                GlyphError,
                "Rules have no effect",
                $"The firewall policy keeps WinGuard's rules from working, so {Bans(input.ActiveBans)} no effect. The dashboard says why.",
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

    private static ProtectionSummary Disarmed(ProtectionInputs input)
    {
        var until = input.DisarmedUntilUtc;
        var clock = until is { } end ? TimeText.ToLocal(end).ToString("t", CultureInfo.CurrentCulture) : string.Empty;
        var countdown = until is { } left ? TimeText.Countdown(left - input.NowUtc) : string.Empty;

        var resumes = until is null
            ? "Enforcement resumes by itself when the window ends."
            : $"Enforcement resumes by itself at {clock}.";
        var stale = input.Connected ? string.Empty : " The service is not answering, so this is the last it reported.";

        return new ProtectionSummary(
            ProtectionKind.Disarmed,
            Tone.Attack,
            GlyphError,
            "Disarmed",
            $"Break-glass is on: WinGuard holds no firewall rules, so nothing is enforced and attackers are not blocked. {resumes} To end it early, run winguard-svc --rearm from an elevated prompt.{stale}",
            CanRetry: !input.Connected,
            Countdown: countdown,
            Tray: until is null ? "Disarmed, nothing is enforced" : $"Disarmed until {clock}, nothing is enforced");
    }

    private static string Bans(int count) => count switch
    {
        0 => "new bans would have",
        1 => "the 1 active ban has",
        _ => $"the {count:N0} active bans have",
    };
}
