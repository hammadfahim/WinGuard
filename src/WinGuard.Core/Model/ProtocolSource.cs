namespace WinGuard.Core.Model;

/// <summary>
/// Which detection engine produced a <see cref="FailedLogin"/> or triggered a ban. Stored as an
/// integer in the database and sent as one over IPC, so a new value goes at the end.
/// </summary>
public enum ProtocolSource
{
    Rdp = 0,
    MsSql = 1,
    Ftp = 2,
    Custom = 3,

    /// <summary>An administrator's ban. Not a detection engine: it has no detector or status tile.</summary>
    Manual = 4,
}

/// <summary>Kind of IP list (matches the <c>kind</c> column of the SQLite <c>lists</c> table).</summary>
public enum ListKind
{
    Whitelist = 0,
    Blacklist = 1,
}
