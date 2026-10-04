namespace WinGuard.Core.Model;

/// <summary>Which detection engine produced a <see cref="FailedLogin"/> or triggered a ban.</summary>
public enum ProtocolSource
{
    Rdp = 0,
    MsSql = 1,
    Ftp = 2,
    Custom = 3,
}

/// <summary>Kind of IP list (matches the <c>kind</c> column of the SQLite <c>lists</c> table).</summary>
public enum ListKind
{
    Whitelist = 0,
    Blacklist = 1,
}
