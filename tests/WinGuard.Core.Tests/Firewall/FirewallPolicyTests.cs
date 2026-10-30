using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Engine;
using WinGuard.Core.Firewall;
using WinGuard.Core.Ipc;
using WinGuard.Core.Tests.Fakes;
using WinGuard.Service;
using WinGuard.Service.Ipc;
using Xunit;
using TypeLib = System.Runtime.InteropServices.ComTypes;

namespace WinGuard.Core.Tests;

/// <summary>What the firewall policy means for WinGuard's rules, from raw values, without COM.</summary>
public sealed class FirewallPolicyTests
{
    private const int Domain = 1;
    private const int Private = 2;
    private const int Public = 4;

    private const int Ok = 0;
    private const int GroupPolicyOverride = 1;
    private const int InboundBlocked = 2;

    private static FirewallPolicyState Policy(int modifyState, params FirewallProfileState[] profiles) =>
        new(profiles.Aggregate(0, (mask, profile) => mask | profile.ProfileType), modifyState, profiles);

    private static FirewallProfileState On(int profile) => new(profile, Enabled: true, BlockAllInbound: false);

    private static FirewallProfileState Off(int profile) => new(profile, Enabled: false, BlockAllInbound: false);

    [Fact]
    public void A_firewall_that_is_on_and_honours_local_rules_gives_no_warning()
    {
        var dto = FirewallPolicyEvaluator.Evaluate(Policy(Ok, On(Public)));

        Assert.True(dto.Known);
        Assert.True(dto.RulesTakeEffect);
        Assert.True(dto.LocalPolicyHonoured);
        Assert.False(dto.InboundBlocked);
        Assert.Equal(Ok, dto.LocalPolicyModifyState);
        Assert.Empty(dto.Warnings);
        var profile = Assert.Single(dto.ActiveProfiles);
        Assert.Equal("Public", profile.Name);
        Assert.True(profile.Enabled);
    }

    [Fact]
    public void Group_policy_that_ignores_local_rules_is_said_in_plain_language()
    {
        var dto = FirewallPolicyEvaluator.Evaluate(Policy(GroupPolicyOverride, On(Domain)));

        Assert.False(dto.RulesTakeEffect);
        Assert.False(dto.LocalPolicyHonoured);
        var warning = Assert.Single(dto.Warnings);
        Assert.Contains("Group Policy", warning);
        Assert.Contains("Apply local firewall rules", warning);
        Assert.Contains("ignores them", warning);
    }

    [Fact]
    public void A_firewall_turned_off_on_an_active_profile_makes_the_rules_useless()
    {
        var dto = FirewallPolicyEvaluator.Evaluate(Policy(Ok, Off(Public)));

        Assert.False(dto.RulesTakeEffect);
        Assert.True(dto.LocalPolicyHonoured);
        Assert.Contains("turned off for the active Public profile", Assert.Single(dto.Warnings));
    }

    [Fact]
    public void Every_active_profile_counts_when_several_are_in_use()
    {
        var dto = FirewallPolicyEvaluator.Evaluate(Policy(Ok, On(Domain), Off(Private), Off(Public)));

        Assert.False(dto.RulesTakeEffect);
        Assert.Equal(["Domain", "Private", "Public"], dto.ActiveProfiles.Select(profile => profile.Name));
        Assert.Equal(2, dto.Warnings.Count);
        Assert.Contains(dto.Warnings, warning => warning.Contains("Private"));
        Assert.Contains(dto.Warnings, warning => warning.Contains("Public"));
    }

    [Fact]
    public void Both_problems_are_reported_when_both_apply()
    {
        var dto = FirewallPolicyEvaluator.Evaluate(Policy(GroupPolicyOverride, Off(Domain)));

        Assert.Equal(2, dto.Warnings.Count);
    }

    [Fact]
    public void Inbound_blocked_is_a_warning_that_says_the_rules_add_nothing()
    {
        var dto = FirewallPolicyEvaluator.Evaluate(Policy(InboundBlocked, new FirewallProfileState(Public, Enabled: true, BlockAllInbound: true)));

        Assert.True(dto.InboundBlocked);
        Assert.True(dto.LocalPolicyHonoured);
        Assert.False(dto.RulesTakeEffect);
        Assert.Contains("blocks all incoming connections", Assert.Single(dto.Warnings));
    }

    [Fact]
    public void Block_all_on_one_profile_is_noticed_even_when_the_state_says_ok()
    {
        var dto = FirewallPolicyEvaluator.Evaluate(Policy(Ok, On(Domain), new FirewallProfileState(Public, Enabled: true, BlockAllInbound: true)));

        Assert.True(dto.InboundBlocked);
        Assert.Single(dto.Warnings);
    }

    [Fact]
    public void An_unknown_state_is_not_taken_for_ok()
    {
        var dto = FirewallPolicyEvaluator.Evaluate(Policy(7, On(Public)));

        Assert.False(dto.RulesTakeEffect);
        Assert.False(dto.LocalPolicyHonoured);
        Assert.Contains("unknown firewall policy state (7)", Assert.Single(dto.Warnings));
    }

    [Fact]
    public void No_active_profile_is_not_taken_for_ok()
    {
        var dto = FirewallPolicyEvaluator.Evaluate(new FirewallPolicyState(0, Ok, []));

        Assert.False(dto.RulesTakeEffect);
        Assert.Contains("no active firewall profile", Assert.Single(dto.Warnings));
    }

    [Fact]
    public void A_reader_that_fails_gives_a_warning_not_an_exception()
    {
        var dto = FirewallPolicyEvaluator.ReadSafely(new FakeFirewallPolicyReader { Failure = new COMException("MpsSvc is stopped") });

        Assert.False(dto.Known);
        Assert.False(dto.RulesTakeEffect);
        Assert.Contains("MpsSvc is stopped", Assert.Single(dto.Warnings));
    }

    [Fact]
    public void The_doctor_fails_on_rules_that_do_nothing()
    {
        var checks = CliCommands.DescribeFirewallPolicy(FirewallPolicyEvaluator.Evaluate(Policy(GroupPolicyOverride, Off(Public))));

        Assert.Contains(checks, check => check is { Label: "Firewall profile Public", Ok: false, WarnOnly: false });
        Assert.Contains(checks, check => check is { Label: "Local firewall rules honoured", Ok: false, WarnOnly: false });
    }

    [Fact]
    public void The_doctor_passes_a_healthy_policy()
    {
        var checks = CliCommands.DescribeFirewallPolicy(FirewallPolicyEvaluator.Evaluate(Policy(Ok, On(Domain), On(Public))));

        Assert.Equal(3, checks.Count);
        Assert.All(checks, check => Assert.True(check.Ok));
    }

    [Fact]
    public void The_doctor_only_warns_about_inbound_blocked_or_an_unreadable_policy()
    {
        var blocked = CliCommands.DescribeFirewallPolicy(FirewallPolicyEvaluator.Evaluate(Policy(InboundBlocked, On(Public))));
        Assert.Contains(blocked, check => check is { Label: "Inbound traffic", Ok: false, WarnOnly: true });
        Assert.DoesNotContain(blocked, check => check is { Ok: false, WarnOnly: false });

        var unreadable = Assert.Single(CliCommands.DescribeFirewallPolicy(FirewallPolicyEvaluator.Unknown("no COM")));
        Assert.True(unreadable.WarnOnly);
    }

    [Fact]
    public async Task The_prerequisites_carry_the_policy_and_its_warnings()
    {
        var reader = new FakeFirewallPolicyReader { State = Policy(GroupPolicyOverride, On(Domain)) };
        var dto = await CheckPrereqsAsync(reader);

        Assert.NotNull(dto.FirewallPolicy);
        Assert.False(dto.FirewallPolicy.RulesTakeEffect);
        Assert.Equal("Domain", Assert.Single(dto.FirewallPolicy.ActiveProfiles).Name);
        Assert.Contains(dto.Warnings, warning => warning.Contains("Group Policy"));
    }

    [Fact]
    public async Task A_failing_policy_read_does_not_fail_the_prerequisites()
    {
        var dto = await CheckPrereqsAsync(new FakeFirewallPolicyReader { Failure = new COMException("no") });

        Assert.False(dto.FirewallPolicy!.Known);
        Assert.Contains(dto.Warnings, warning => warning.Contains("could not be read"));
    }

    private static async Task<PrereqsDto> CheckPrereqsAsync(IFirewallPolicyReader reader)
    {
        var store = new FakeStore();
        var firewall = new FakeFirewall();
        var settings = new WinGuardSettings { HousekeepingInterval = TimeSpan.FromHours(6) };
        var holder = new SettingsHolder(store, NullLogger<SettingsHolder>.Instance);
        await holder.LoadAsync();
        var engine = new BanEngine(store, firewall, () => settings, NullLogger<BanEngine>.Instance);
        var handler = new IpcRequestHandler(
            store,
            engine,
            holder,
            firewall,
            new DetectorRuntimeState(),
            TimeProvider.System,
            NullLogger<IpcRequestHandler>.Instance,
            reader);

        var request = System.Text.Json.JsonSerializer.Serialize(new IpcRequest { Id = 1, Method = IpcMethods.CheckPrereqs }, IpcJson.Options);
        var line = await handler.HandleLineAsync(request, CancellationToken.None);
        var response = System.Text.Json.JsonSerializer.Deserialize<IpcResponse>(line!, IpcJson.Options)!;
        Assert.True(response.Ok, response.Error);
        return System.Text.Json.JsonSerializer.Deserialize<PrereqsDto>(response.Result!.Value, IpcJson.Options)!;
    }

    private sealed class FakeFirewallPolicyReader : IFirewallPolicyReader
    {
        public FirewallPolicyState? State { get; init; }

        public Exception? Failure { get; init; }

        public FirewallPolicyState Read() => Failure is null ? State! : throw Failure;
    }
}

/// <summary>
/// The policy reader and the enum values against the REAL Windows Firewall API. Reading the policy
/// and the type library needs no administrator rights, so these run wherever Windows does.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class FirewallPolicyComContractTests
{
    private const int RegKindNone = 2;

    [DllImport("oleaut32.dll", CharSet = CharSet.Unicode, PreserveSig = false)]
    private static extern void LoadTypeLibEx(string file, int regKind, out TypeLib.ITypeLib library);

    /// <summary>The constants of an enum in the type library inside FirewallAPI.dll, the library netfw.h describes.</summary>
    private static Dictionary<string, int> EnumFromFirewallApi(string enumName)
    {
        LoadTypeLibEx(Path.Combine(Environment.SystemDirectory, "FirewallAPI.dll"), RegKindNone, out var library);
        for (var index = 0; index < library.GetTypeInfoCount(); index++)
        {
            library.GetDocumentation(index, out var name, out _, out _, out _);
            if (name != enumName)
            {
                continue;
            }

            library.GetTypeInfo(index, out var info);
            info.GetTypeAttr(out var attributesPointer);
            var attributes = Marshal.PtrToStructure<TypeLib.TYPEATTR>(attributesPointer);
            var constants = new Dictionary<string, int>();
            for (var variable = 0; variable < attributes.cVars; variable++)
            {
                info.GetVarDesc(variable, out var descriptionPointer);
                var description = Marshal.PtrToStructure<TypeLib.VARDESC>(descriptionPointer);
                info.GetDocumentation(description.memid, out var constant, out _, out _, out _);
                constants[constant] = Convert.ToInt32(Marshal.GetObjectForNativeVariant(description.desc.lpvarValue));
                info.ReleaseVarDesc(descriptionPointer);
            }

            info.ReleaseTypeAttr(attributesPointer);
            return constants;
        }

        throw new InvalidOperationException($"{enumName} is not in FirewallAPI.dll.");
    }

    [Fact]
    public void The_modify_state_values_are_the_ones_windows_defines()
    {
        var constants = EnumFromFirewallApi("NET_FW_MODIFY_STATE_");

        Assert.Equal(FirewallPolicyEvaluator.ModifyStateOk, constants["NET_FW_MODIFY_STATE_OK"]);
        Assert.Equal(FirewallPolicyEvaluator.ModifyStateGroupPolicyOverride, constants["NET_FW_MODIFY_STATE_GP_OVERRIDE"]);
        Assert.Equal(FirewallPolicyEvaluator.ModifyStateInboundBlocked, constants["NET_FW_MODIFY_STATE_INBOUND_BLOCKED"]);
        Assert.Equal(3, constants.Count);
    }

    [Fact]
    public void The_profile_bits_are_the_ones_windows_defines()
    {
        var constants = EnumFromFirewallApi("NET_FW_PROFILE_TYPE2_");

        Assert.Equal(FirewallPolicyEvaluator.ProfileDomain, constants["NET_FW_PROFILE2_DOMAIN"]);
        Assert.Equal(FirewallPolicyEvaluator.ProfilePrivate, constants["NET_FW_PROFILE2_PRIVATE"]);
        Assert.Equal(FirewallPolicyEvaluator.ProfilePublic, constants["NET_FW_PROFILE2_PUBLIC"]);
    }

    [Fact]
    public void The_real_policy_can_be_read_without_elevation()
    {
        var state = new ComFirewallPolicyReader().Read();

        Assert.NotEqual(0, state.CurrentProfileTypes);
        Assert.NotEmpty(state.Profiles);
        Assert.All(state.Profiles, profile => Assert.Contains(profile.ProfileType, FirewallPolicyEvaluator.KnownProfiles));
        Assert.InRange(state.LocalPolicyModifyState, 0, 2);
    }

    [Fact]
    public void The_real_policy_evaluates_without_an_unknown_state()
    {
        var dto = FirewallPolicyEvaluator.ReadSafely(new ComFirewallPolicyReader());

        Assert.True(dto.Known, string.Join(" ", dto.Warnings));
        Assert.DoesNotContain(dto.Warnings, warning => warning.Contains("unknown"));
    }
}
