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

    /// <summary>
    /// The product ends every record with CRLF and logs client text verbatim, bare LFs included,
    /// so the log must be split at CRLF only. Without this a client can forge a whole line.
    /// </summary>
    public bool CrLfRecords { get; init; }
}

/// <summary>
/// Built-in custom-source recipes. All of them use the generic regex engine, so adding one to the
/// settings needs no code change. Adjust <c>%ProgramData%</c>-style paths to the real installation.
/// The regexes avoid lookaround and backreferences, so a line that times out can still be checked
/// on the linear-time regex engine.
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

    /// <summary>hMailServer: SMTP/IMAP/POP failed authentication in the daily TCP/IP session log.</summary>
    public static readonly CustomSourceRecipe HMailServer = new()
    {
        Name = "hMailServer",
        PathGlob = @"C:\Program Files (x86)\hMailServer\Logs\hmailserver_*.log",
        // "SMTPD|POP3D|IMAPD" <tab> thread <tab> session <tab> "time" <tab> "client ip" <tab> "text".
        // The address column comes before anything a client can influence, and only the server's
        // own SENT replies count: RECEIVED lines hold client text, and SMTPC/POP3C are hMailServer's
        // outgoing connections, where the peer is another server. An IMAP reply starts with the
        // client's tag, which hMailServer ends at the first space and nowhere else, so a tab or a
        // quote can be part of it. CrLfRecords keeps a bare LF in client text from forging a whole line.
        Regex = @"^""(?:SMTPD|POP3D|IMAPD)""\t\d+\t\d+\t""[^""]*""\t""(?<ipaddress>[0-9a-fA-F:.]+)""\t""SENT: (?:535 Authentication failed\.|-ERR Invalid user name or password\.|[^ ]+ NO Invalid user name(?: or password)?\.|\* Too many invalid logon attempts\.)[^""]*""\s*$",
        Description = "hMailServer failed SMTP/IMAP/POP3 logins. Turn on SMTP, POP3 and IMAP logging under Settings > Logging; the awstats log has no logins.",
        CrLfRecords = true,
    };

    // The hMailServer recipe whose IMAP tag stopped at any white space; a tab in the tag went uncounted.
    private const string WhitespaceTagHMailServerRegex =
        @"^""(?:SMTPD|POP3D|IMAPD)""\t\d+\t\d+\t""[^""]*""\t""(?<ipaddress>[0-9a-fA-F:.]+)""\t""SENT: (?:535 Authentication failed\.|-ERR Invalid user name or password\.|\S+ NO Invalid user name(?: or password)?\.|\* Too many invalid logon attempts\.)[^""]*""\s*$";

    // The hMailServer recipe from before it had a sample log: the awstats log it read records
    // deliveries only, so it never matched, and hMailServer writes that file with other columns.
    private const string AwstatsHMailServerRegex =
        @"\tFAILED\t(?<username>\S+)\t\d+\t(?<ipaddress>[0-9a-fA-F:.]+)\t";

    /// <summary>IIS HTTP authentication failures (a rejected password, not the 401 challenge).</summary>
    public static readonly CustomSourceRecipe IisHttpAuth = new()
    {
        Name = "IIS HTTP auth (401.1)",
        PathGlob = @"C:\inetpub\logs\LogFiles\W3SVC1\*.log",
        // The default W3C columns, matched one by one from the start of the line to the end, so a
        // URL, query, user name or user agent (IIS writes their spaces as '+') cannot move the
        // c-ip column. Only 401.1 with a logon-failure Win32 status counts: 1326 wrong user or
        // password, 1327 account restriction, 1331 disabled, 1909 locked out, 2148074252
        // SEC_E_LOGON_DENIED. 401.2 is the anonymous challenge every browser triggers, and
        // 401.1 with 2148074254 (SEC_E_NO_CREDENTIALS) is a healthy NTLM handshake step. A column
        // ends at a space and nowhere else: \S would also stop at a no-break space, which IIS writes
        // as it is, so one of those in the URL would hide the failure.
        Regex = @"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [^ ]+ [^ ]+ [^ ]+ [^ ]+ \d+ (?<username>[^ ]+) (?<ipaddress>[0-9a-fA-F:.]+) [^ ]+ [^ ]+ 401 1 (?:1326|1327|1331|1909|2148074252) \d+\s*$",
        Description = "IIS logins rejected with 401.1, on the default W3C fields. Adjust the W3SVC folder per site.",
    };

    // The IIS recipe whose columns stopped at any white space, no-break spaces included.
    private const string WhitespaceColumnsIisHttpAuthRegex =
        @"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \S+ \S+ \S+ \S+ \d+ (?<username>\S+) (?<ipaddress>[0-9a-fA-F:.]+) \S+ \S+ 401 1 (?:1326|1327|1331|1909|2148074252) \d+\s*$";

    // The IIS recipe that assumed another column order; it never matched a default W3C line.
    private const string PositionalIisHttpAuthRegex =
        @"^(?!#).*\s(?<ipaddress>\S+)\s+\S+\s+\S+\s+\S+\s+\S+\s+(GET|POST)\s+\S+\s+\S+\s+401(?:\.\d+)?\s";

    /// <summary>RealVNC Server, plus the blacklisted line of TigerVNC-family servers.</summary>
    public static readonly CustomSourceRecipe Vnc = new()
    {
        Name = "RealVNC Server",
        PathGlob = @"C:\ProgramData\RealVNC-Service\vncserver.log",
        // Up to five tokens of syslog-style prefix, then RealVNC's disconnect line with the
        // [AuthFailure] reason; any other reason is an ordinary disconnect. Blacklisted means the
        // client already failed repeatedly. An "authenticated ..., as <user>" line is too long
        // for its user name to reach the "Connections:" this anchors on.
        Regex = @"^\s*(?:\S+\s+){0,5}?Connections: (?:disconnected: \[?(?<ipaddress>[0-9a-fA-F:.]+?)\]?::\d+(?: \(\w+\))? \(\[AuthFailure\]|[Bb]lacklisted: (?<ipaddress>[0-9a-fA-F:.]+)\s*$)",
        Description = "RealVNC logins refused with [AuthFailure]. It logs to the Windows Event Log by default: if this file has no \"Connections:\" lines, add a file target to its Log parameter.",
    };

    // The VNC recipe from before it had a sample log: "closed" is every disconnect, failed or not.
    private const string ClosedVncRegex =
        @"Connections: (?:closed|blacklisted): (?<ipaddress>[0-9a-fA-F:.]+)";

    // Where the replaced recipes pointed; sources saved from them hold a copy of this.
    private const string AwstatsFileName = "hmailserver_awstats.log";
    private const string OldVncPathGlob = @"C:\Program Files\RealVNC\VNC Server\*.log";

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
    public static string UpgradeRegex(string regex) => regex switch
    {
        UnanchoredOpenSshRegex => WindowsOpenSsh.Regex,
        AwstatsHMailServerRegex or WhitespaceTagHMailServerRegex => HMailServer.Regex,
        PositionalIisHttpAuthRegex or WhitespaceColumnsIisHttpAuthRegex => IisHttpAuth.Regex,
        ClosedVncRegex => Vnc.Regex,
        _ => regex,
    };

    /// <summary>
    /// Companion to <see cref="UpgradeRegex"/>: the same source's path, where an upgraded regex
    /// would otherwise keep reading a file that can never match it. Only a source already holding
    /// the current recipe regex is changed, so a custom regex on the same file is left alone.
    /// </summary>
    /// <param name="pathGlob">The source's configured path.</param>
    /// <param name="regex">The source's regex, after <see cref="UpgradeRegex"/>.</param>
    public static string UpgradePathGlob(string pathGlob, string regex)
    {
        var trimmed = pathGlob.Trim();
        if (regex == HMailServer.Regex && trimmed.EndsWith(@"\" + AwstatsFileName, StringComparison.OrdinalIgnoreCase))
        {
            return trimmed[..^AwstatsFileName.Length] + "hmailserver_*.log";
        }

        return regex == Vnc.Regex && trimmed.Equals(OldVncPathGlob, StringComparison.OrdinalIgnoreCase)
            ? Vnc.PathGlob
            : pathGlob;
    }

    /// <summary>Whether a source using this regex must be read with CRLF as the only line end.</summary>
    public static bool UsesCrLfRecords(string? regex) =>
        All.Any(recipe => recipe.CrLfRecords && recipe.Regex == regex);
}
