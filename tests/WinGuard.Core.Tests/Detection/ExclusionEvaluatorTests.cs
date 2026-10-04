using WinGuard.Core.Detection;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>Tests for RDP 4625 exclusion rules (PLAN.md §6).</summary>
public sealed class ExclusionEvaluatorTests
{
    [Fact]
    public void And_within_a_rule_requires_all_conditions()
    {
        var data = new Dictionary<string, string>
        {
            ["LogonType"] = "2",
            ["IpAddress"] = "127.0.0.1",
        };

        Assert.True(ExclusionEvaluator.IsExcluded(data, ["LogonType=2, IpAddress=127.0.0.1"]));
        Assert.False(ExclusionEvaluator.IsExcluded(data, ["LogonType=3, IpAddress=127.0.0.1"]));
        Assert.False(ExclusionEvaluator.IsExcluded(data, ["LogonType=2, IpAddress=10.0.0.1"]));
    }

    [Fact]
    public void Or_across_rules_requires_only_one()
    {
        var data = new Dictionary<string, string> { ["TargetUserName"] = "administrator" };

        Assert.True(ExclusionEvaluator.IsExcluded(data, ["LogonType=3", "TargetUserName=administrator"]));
        Assert.False(ExclusionEvaluator.IsExcluded(data, ["LogonType=3", "TargetUserName=bob"]));
    }

    [Fact]
    public void Not_equal_negation()
    {
        var admin = new Dictionary<string, string> { ["TargetUserName"] = "admin" };
        var administrator = new Dictionary<string, string> { ["TargetUserName"] = "administrator" };

        Assert.True(ExclusionEvaluator.IsExcluded(admin, ["TargetUserName!=administrator"]));
        Assert.False(ExclusionEvaluator.IsExcluded(administrator, ["TargetUserName!=administrator"]));
    }

    [Fact]
    public void Wildcard_matches_any_run()
    {
        var data = new Dictionary<string, string> { ["TargetUserName"] = "administrator" };

        Assert.True(ExclusionEvaluator.IsExcluded(data, ["TargetUserName=admin*"]));
        Assert.True(ExclusionEvaluator.IsExcluded(data, ["TargetUserName=*rator"]));
        Assert.False(ExclusionEvaluator.IsExcluded(data, ["TargetUserName=bob*"]));
    }

    [Fact]
    public void Field_lookup_is_case_insensitive()
    {
        // Default dictionary comparer is case-sensitive, so only an evaluator that looks
        // fields up case-insensitively can match this rule.
        var data = new Dictionary<string, string> { ["ipaddress"] = "203.0.113.45" };

        Assert.True(ExclusionEvaluator.IsExcluded(data, ["IpAddress=203.0.113.45"]));
    }

    [Fact]
    public void Unknown_field_does_not_match()
    {
        var data = new Dictionary<string, string> { ["IpAddress"] = "203.0.113.45" };

        Assert.False(ExclusionEvaluator.IsExcluded(data, ["NoSuchField=anything"]));
    }

    [Fact]
    public void Empty_rules_never_exclude()
    {
        var data = new Dictionary<string, string> { ["LogonType"] = "10" };

        Assert.False(ExclusionEvaluator.IsExcluded(data, []));
    }

    [Theory]
    [InlineData("administrator", "admin*", true)]
    [InlineData("administrator", "*ator", true)]
    [InlineData("administrator", "a*a", false)]
    [InlineData("banana", "b*a", true)]
    [InlineData("administrator", "*", true)]
    [InlineData("administrator", "admin", false)]
    public void MatchesWildcard_cases(string input, string pattern, bool expected)
    {
        Assert.Equal(expected, ExclusionEvaluator.MatchesWildcard(input, pattern));
    }
}