using System.Runtime.Versioning;
using WinGuard.Core.Ipc;

namespace WinGuard.Core.Firewall;

/// <summary>One firewall profile as Windows reports it.</summary>
/// <param name="ProfileType">The <c>NET_FW_PROFILE2_*</c> bit of the profile.</param>
/// <param name="Enabled"><c>INetFwPolicy2.FirewallEnabled</c> for the profile.</param>
/// <param name="BlockAllInbound"><c>INetFwPolicy2.BlockAllInboundTraffic</c> for the profile.</param>
public sealed record FirewallProfileState(int ProfileType, bool Enabled, bool BlockAllInbound);

/// <summary>The raw policy values, before any interpretation.</summary>
/// <param name="CurrentProfileTypes">Bit mask of the active profiles: <c>INetFwPolicy2.CurrentProfileTypes</c>.</param>
/// <param name="LocalPolicyModifyState">The <c>NET_FW_MODIFY_STATE</c> from <c>INetFwPolicy2.LocalPolicyModifyState</c>.</param>
/// <param name="Profiles">The active profiles.</param>
public sealed record FirewallPolicyState(int CurrentProfileTypes, int LocalPolicyModifyState, IReadOnlyList<FirewallProfileState> Profiles);

/// <summary>Reads the firewall policy. Read-only by contract: nothing behind this may change policy.</summary>
public interface IFirewallPolicyReader
{
    /// <summary>Reads the current policy; throws when it cannot.</summary>
    FirewallPolicyState Read();
}

/// <summary>
/// Turns the raw policy into what an administrator needs to know: whether WinGuard's rules can do
/// anything at all. A rule written to a firewall that is switched off, or that Group Policy tells
/// to ignore local rules, is accepted without complaint and blocks nothing, so this is the only
/// place such a server gets found out. Pure, so it can be tested without COM.
/// </summary>
public static class FirewallPolicyEvaluator
{
    // NET_FW_PROFILE_TYPE2 (icftypes.h). The contract tests check these against FirewallAPI.dll.
    internal const int ProfileDomain = 0x1;
    internal const int ProfilePrivate = 0x2;
    internal const int ProfilePublic = 0x4;

    // NET_FW_MODIFY_STATE (icftypes.h). The value says whether a rule added to the current profile
    // takes effect: it does, it does not because Group Policy controls the profile, or it does not
    // because unsolicited inbound traffic is not allowed in the first place.
    internal const int ModifyStateOk = 0;
    internal const int ModifyStateGroupPolicyOverride = 1;
    internal const int ModifyStateInboundBlocked = 2;

    internal static readonly int[] KnownProfiles = [ProfileDomain, ProfilePrivate, ProfilePublic];

    /// <summary>Evaluates a policy read from Windows.</summary>
    public static FirewallPolicyDto Evaluate(FirewallPolicyState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        var modifyState = state.LocalPolicyModifyState;
        var profiles = state.Profiles
            .Select(profile => new FirewallProfileDto
            {
                Name = ProfileName(profile.ProfileType),
                Enabled = profile.Enabled,
                BlockAllInbound = profile.BlockAllInbound,
            })
            .ToList();

        var dto = new FirewallPolicyDto
        {
            Known = true,
            ActiveProfiles = profiles,
            LocalPolicyModifyState = modifyState,
            LocalPolicyHonoured = modifyState is ModifyStateOk or ModifyStateInboundBlocked,
            InboundBlocked = modifyState == ModifyStateInboundBlocked || profiles.Any(profile => profile.BlockAllInbound),
        };

        if (profiles.Count == 0)
        {
            dto.Warnings.Add("Windows reports no active firewall profile, so it cannot be said whether WinGuard's block rules take effect.");
        }

        foreach (var profile in profiles.Where(profile => !profile.Enabled))
        {
            dto.Warnings.Add($"Windows Firewall is turned off for the active {profile.Name} profile: WinGuard's block rules do nothing for traffic on that network. Turn the firewall on for this profile.");
        }

        if (modifyState == ModifyStateGroupPolicyOverride)
        {
            dto.Warnings.Add("Group Policy controls the firewall on the active profile and local rules do not take effect (\"Apply local firewall rules: No\"): WinGuard's block rules are written, but Windows ignores them and attackers stay unblocked. Change the policy to apply local firewall rules.");
        }
        else if (dto.InboundBlocked)
        {
            dto.Warnings.Add("Windows Firewall blocks all incoming connections on the active profile: nothing unsolicited gets in, including what is allowed by a rule, so WinGuard's block rules add nothing while this is on.");
        }
        else if (!dto.LocalPolicyHonoured)
        {
            dto.Warnings.Add($"Windows reported an unknown firewall policy state ({modifyState}), so it cannot be said whether WinGuard's block rules take effect.");
        }

        dto.RulesTakeEffect = profiles.Count > 0
            && profiles.All(profile => profile.Enabled)
            && modifyState == ModifyStateOk
            && !dto.InboundBlocked;

        return dto;
    }

    /// <summary>What to report when the policy could not be read at all.</summary>
    public static FirewallPolicyDto Unknown(string reason) => new()
    {
        Warnings = [$"The firewall policy could not be read, so it cannot be said whether WinGuard's block rules take effect: {reason}"],
    };

    /// <summary>Reads and evaluates the policy. Never throws.</summary>
    public static FirewallPolicyDto ReadSafely(IFirewallPolicyReader reader)
    {
        try
        {
            return Evaluate(reader.Read());
        }
        catch (Exception ex)
        {
            return Unknown(ex.GetBaseException().Message);
        }
    }

    private static string ProfileName(int profileType) => profileType switch
    {
        ProfileDomain => "Domain",
        ProfilePrivate => "Private",
        ProfilePublic => "Public",
        _ => $"unknown ({profileType})",
    };
}

/// <summary>
/// <see cref="IFirewallPolicyReader"/> over <c>HNetCfg.FwPolicy2</c>, through <c>dynamic</c> like
/// <see cref="ComFirewallRuleStore"/>. Reads properties only, which works without elevation.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ComFirewallPolicyReader : IFirewallPolicyReader
{
    private const string PolicyProgId = "HNetCfg.FwPolicy2";

    /// <inheritdoc />
    public FirewallPolicyState Read()
    {
        var type = Type.GetTypeFromProgID(PolicyProgId, throwOnError: false)
            ?? throw new PlatformNotSupportedException(
                "The Windows Firewall COM API (HNetCfg.FwPolicy2) is unavailable. This operation requires Windows.");

        dynamic policy = Activator.CreateInstance(type)!;
        int current = policy.CurrentProfileTypes;
        int modifyState = policy.LocalPolicyModifyState;

        var profiles = new List<FirewallProfileState>();
        foreach (var profile in FirewallPolicyEvaluator.KnownProfiles.Where(profile => (current & profile) != 0))
        {
            bool enabled = policy.FirewallEnabled[profile];
            bool blockAll = policy.BlockAllInboundTraffic[profile];
            profiles.Add(new FirewallProfileState(profile, enabled, blockAll));
        }

        return new FirewallPolicyState(current, modifyState, profiles);
    }
}
