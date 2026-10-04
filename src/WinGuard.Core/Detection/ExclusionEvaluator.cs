namespace WinGuard.Core.Detection;

/// <summary>
/// Evaluates the RDP 4625 exclusion rules described in PLAN.md §6 and CONTRACTS.md.
/// <para>
/// Semantics: separate entries in <c>rules</c> are OR-ed together; the comma-separated
/// conditions inside a single entry are AND-ed together. Every condition is either
/// <c>Field=value</c> or <c>Field!=value</c>. A value may contain <c>'*'</c>, which
/// matches any run of characters (including empty). Field-name lookup over the
/// EventData <c>Name</c> → value map is case-insensitive, and value comparison is also
/// case-insensitive to match Windows account-name semantics.
/// </para>
/// </summary>
public static class ExclusionEvaluator
{
    /// <summary>
    /// Returns <see langword="true"/> when any rule entry matches the supplied EventData.
    /// An empty/invalid rule set or empty dictionary never excludes.
    /// </summary>
    /// <param name="eventData">4625 EventData <c>Name</c> → value pairs.</param>
    /// <param name="rules">Rule entries (OR-ed); each entry is conditions joined by ',' (AND-ed).</param>
    public static bool IsExcluded(IReadOnlyDictionary<string, string> eventData, IEnumerable<string> rules)
    {
        if (eventData is null || rules is null)
        {
            return false;
        }

        foreach (var rule in rules)
        {
            if (string.IsNullOrWhiteSpace(rule))
            {
                continue;
            }

            if (RuleMatches(eventData, rule))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Wildcard match where <c>'*'</c> matches any run of characters (including none).
    /// The comparison is case-insensitive; all other characters match literally.
    /// </summary>
    /// <param name="input">The value to test (null is treated as empty).</param>
    /// <param name="pattern">The pattern; only <c>'*'</c> is special.</param>
    public static bool MatchesWildcard(string? input, string? pattern)
    {
        input ??= string.Empty;
        pattern ??= string.Empty;

        var inputIndex = 0;
        var patternIndex = 0;
        var starIndex = -1;
        var matchIndex = 0;

        while (inputIndex < input.Length)
        {
            if (patternIndex < pattern.Length
                && char.ToUpperInvariant(pattern[patternIndex]) == char.ToUpperInvariant(input[inputIndex]))
            {
                inputIndex++;
                patternIndex++;
            }
            else if (patternIndex < pattern.Length && pattern[patternIndex] == '*')
            {
                starIndex = patternIndex;
                matchIndex = inputIndex;
                patternIndex++;
            }
            else if (starIndex != -1)
            {
                patternIndex = starIndex + 1;
                matchIndex++;
                inputIndex = matchIndex;
            }
            else
            {
                return false;
            }
        }

        while (patternIndex < pattern.Length && pattern[patternIndex] == '*')
        {
            patternIndex++;
        }

        return patternIndex == pattern.Length;
    }

    private static bool RuleMatches(IReadOnlyDictionary<string, string> eventData, string rule)
    {
        var conditions = rule.Split(',');
        foreach (var rawCondition in conditions)
        {
            var condition = rawCondition.Trim();
            if (condition.Length == 0)
            {
                // A trailing/embedded empty condition makes the whole rule malformed.
                return false;
            }

            if (!ConditionMatches(eventData, condition))
            {
                return false;
            }
        }

        return true;
    }

    private static bool ConditionMatches(IReadOnlyDictionary<string, string> eventData, string condition)
    {
        var equals = condition.IndexOf('=');
        if (equals <= 0)
        {
            // No operator, or an empty field name: not a valid condition.
            return false;
        }

        var isNegated = condition[equals - 1] == '!';
        var field = condition[..(isNegated ? equals - 1 : equals)].Trim();
        var pattern = condition[(equals + 1)..].Trim();
        if (field.Length == 0)
        {
            return false;
        }

        var matched = ValueMatches(Lookup(eventData, field), pattern);
        return isNegated ? !matched : matched;
    }

    private static string Lookup(IReadOnlyDictionary<string, string> eventData, string field)
    {
        if (eventData.TryGetValue(field, out var value))
        {
            return value ?? string.Empty;
        }

        foreach (var pair in eventData)
        {
            if (string.Equals(pair.Key, field, StringComparison.OrdinalIgnoreCase))
            {
                return pair.Value ?? string.Empty;
            }
        }

        return string.Empty;
    }

    private static bool ValueMatches(string? value, string pattern)
    {
        value ??= string.Empty;
        return pattern.IndexOf('*') >= 0
            ? MatchesWildcard(value, pattern)
            : string.Equals(value, pattern, StringComparison.OrdinalIgnoreCase);
    }
}