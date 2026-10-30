namespace WinGuard.Core.Config;

/// <summary>
/// One ready-made <see cref="CustomLogSource"/> template for a common Windows server product.
/// Recipes are starting points: the path almost always needs adjusting to the machine, and the
/// regex has been written for the product's default log layout. They exist so administrators do
/// not have to invent a regex to cover, say, Windows OpenSSH or hMailServer.
/// </summary>
public sealed class CustomSourceRecipe
{
    public string Name { get; init; } = string.Empty;

    /// <summary>Where the product writes its log by default (shown as the editable suggestion).</summary>
    public string PathGlob { get; init; } = string.Empty;

    /// <summary>Regex with the required <c>ipaddress</c> named group.</summary>
    public string Regex { get; init; } = string.Empty;

    /// <summary>One-line hint shown in the GUI ("what this detects").</summary>
    public string Description { get; init; } = string.Empty;
}

/// <summary>
/// Built-in custom-source recipes. All of them use the generic regex engine, so adding one to the
/// settings needs no code change. Adjust <c>%ProgramData%</c>-style paths to the real installation.
/// </summary>
public static class CustomSourceRecipes
{
    /// <summary>Windows OpenSSH server: failed publickey/password logins in the sshd log.</summary>
    public static readonly CustomSourceRecipe WindowsOpenSsh = new()
    {
        Name = "Windows OpenSSH (sshd)",
        PathGlob = @"C:\ProgramData\ssh\logs\sshd.log",
        // sshd logs the user name verbatim and a client can put spaces in it, so a name like
        // "x from 198.51.100.9 port 1" fakes the address part. Only the end of the line is
        // written by sshd alone, so the address is taken from there.
        Regex = @"Failed password for (invalid user )?(?<username>.*) from (?<ipaddress>[0-9a-fA-F:.]+) port \d+(?: ssh2)?\s*$",
        Description = "Failed password logins to the built-in Windows OpenSSH server (sshd).",
    };

    // The OpenSSH recipe before it was anchored; settings saved from it hold a copy of this text.
    private const string UnanchoredOpenSshRegex =
        @"Failed password for (invalid user )?(?<username>\S+) from (?<ipaddress>[0-9a-fA-F:.]+) port \d+";

    /// <summary>hMailServer: SMTP/IMAP/POP failed authentication.</summary>
    public static readonly CustomSourceRecipe HMailServer = new()
    {
        Name = "hMailServer",
        PathGlob = @"C:\Program Files (x86)\hMailServer\Logs\hmailserver_awstats.log",
        Regex = @"\tFAILED\t(?<username>\S+)\t\d+\t(?<ipaddress>[0-9a-fA-F:.]+)\t",
        Description = "hMailServer failed SMTP/IMAP/POP3 authentications (awstats log).",
    };

    /// <summary>IIS HTTP basic authentication failures (401.1/401.2 on any site).</summary>
    public static readonly CustomSourceRecipe IisHttpAuth = new()
    {
        Name = "IIS HTTP auth (401)",
        PathGlob = @"C:\inetpub\logs\LogFiles\W3SVC1\*.log",
        Regex = @"^(?!#).*\s(?<ipaddress>\S+)\s+\S+\s+\S+\s+\S+\s+\S+\s+(GET|POST)\s+\S+\s+\S+\s+401(?:\.\d+)?\s",
        Description = "IIS requests rejected with 401 (failed basic/digest authentication). Adjust the W3SVC folder per site.",
    };

    /// <summary>RealVNC-style connection refusal log.</summary>
    public static readonly CustomSourceRecipe Vnc = new()
    {
        Name = "VNC server",
        PathGlob = @"C:\Program Files\RealVNC\VNC Server\*.log",
        Regex = @"Connections: (?:closed|blacklisted): (?<ipaddress>[0-9a-fA-F:.]+)",
        Description = "VNC connections refused/blacklisted by the server. Layouts vary by product; adjust the regex.",
    };

    /// <summary>All built-in recipes in GUI order.</summary>
    public static IReadOnlyList<CustomSourceRecipe> All =>
    [
        WindowsOpenSsh,
        HMailServer,
        IisHttpAuth,
        Vnc,
    ];

    /// <summary>
    /// Replaces a regex copied from a recipe version with a known flaw by the current one. Recipes
    /// are copied into the settings, so fixing the recipe alone would not reach existing installs.
    /// </summary>
    public static string UpgradeRegex(string regex) =>
        regex == UnanchoredOpenSshRegex ? WindowsOpenSsh.Regex : regex;
}
