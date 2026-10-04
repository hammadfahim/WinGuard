namespace WinGuard.Gui.Services;

/// <summary>CSV cell escaping shared by the export commands.</summary>
public static class CsvText
{
    /// <summary>
    /// Quotes a value when needed. A value starting with <c>= + - @</c> gets a leading apostrophe so
    /// a spreadsheet opens it as text instead of evaluating it as a formula.
    /// </summary>
    public static string Escape(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        if (value[0] is '=' or '+' or '-' or '@')
        {
            value = "'" + value;
        }

        if (value.Contains(',') || value.Contains('"') || value.Contains('\n') || value.Contains('\r'))
        {
            return "\"" + value.Replace("\"", "\"\"") + "\"";
        }

        return value;
    }
}
