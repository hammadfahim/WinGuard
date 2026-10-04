using WinGuard.Core.Abstractions;
using WinGuard.Core.Model;

namespace WinGuard.Core.Tests.Fakes;

/// <summary>
/// In-memory <see cref="IStore"/> used by the engine tests. Every operation completes
/// synchronously (wrapped in <see cref="Task.FromResult{TResult}"/>) and is guarded by a
/// lock so the engine's housekeeping timer and the test thread cannot corrupt state.
/// </summary>
public sealed class FakeStore : IStore
{
    private readonly object _gate = new();
    private readonly List<FailedLogin> _failedLogins = new();
    private readonly Dictionary<string, BanEntry> _bans = new(StringComparer.Ordinal);
    private readonly Dictionary<ListKind, List<string>> _lists = new()
    {
        [ListKind.Whitelist] = new List<string>(),
        [ListKind.Blacklist] = new List<string>(),
    };
    private readonly List<LogEvent> _events = new();
    private long _nextEventId;
    private readonly Dictionary<string, string> _settings = new(StringComparer.Ordinal);

    /// <summary>Number of times <see cref="InitializeAsync"/> was called.</summary>
    public int InitializeCallCount { get; private set; }

    /// <summary>Snapshot of stored failed logins (oldest first).</summary>
    public List<FailedLogin> FailedLogins
    {
        get { lock (_gate) { return _failedLogins.Select(Clone).ToList(); } }
    }

    /// <summary>Snapshot of stored events, in insertion order.</summary>
    public List<LogEvent> Events
    {
        get { lock (_gate) { return _events.Select(Clone).ToList(); } }
    }

    /// <summary>Snapshot of the settings key/value pairs.</summary>
    public Dictionary<string, string> SettingValues
    {
        get { lock (_gate) { return new Dictionary<string, string>(_settings, StringComparer.Ordinal); } }
    }

    public Task InitializeAsync(CancellationToken ct = default)
    {
        lock (_gate)
        {
            InitializeCallCount++;
        }

        return Task.CompletedTask;
    }

    public Task AddFailedLoginAsync(FailedLogin failed, CancellationToken ct = default)
    {
        lock (_gate)
        {
            _failedLogins.Add(Clone(failed));
        }

        return Task.CompletedTask;
    }

    public Task<int> CountFailedLoginsAsync(string ip, DateTime sinceUtc, ProtocolSource? source = null, CancellationToken ct = default)
    {
        lock (_gate)
        {
            var count = _failedLogins.Count(f =>
                string.Equals(f.IpAddress, ip, StringComparison.Ordinal)
                && f.TimestampUtc >= sinceUtc
                && (source is null || f.Source == source));
            return Task.FromResult(count);
        }
    }

    public async Task<int> AddFailedLoginAndCountAsync(FailedLogin failed, DateTime sinceUtc, CancellationToken ct = default)
    {
        await AddFailedLoginAsync(failed, ct);
        return await CountFailedLoginsAsync(failed.IpAddress, sinceUtc, failed.Source, ct);
    }

    public Task RemoveLatestFailedLoginAsync(string ip, ProtocolSource source, CancellationToken ct = default)
    {
        lock (_gate)
        {
            var index = _failedLogins.FindLastIndex(f => string.Equals(f.IpAddress, ip, StringComparison.Ordinal) && f.Source == source);
            if (index >= 0)
            {
                _failedLogins.RemoveAt(index);
            }
        }

        return Task.CompletedTask;
    }

    public Task ClearFailedLoginsAsync(string ip, CancellationToken ct = default)
    {
        lock (_gate)
        {
            _failedLogins.RemoveAll(f => string.Equals(f.IpAddress, ip, StringComparison.Ordinal));
        }

        return Task.CompletedTask;
    }

    public Task PruneFailedLoginsAsync(DateTime olderThanUtc, CancellationToken ct = default)
    {
        lock (_gate)
        {
            _failedLogins.RemoveAll(f => f.TimestampUtc < olderThanUtc);
        }

        return Task.CompletedTask;
    }

    public Task<int> CountFailedLoginsSinceAsync(DateTime sinceUtc, ProtocolSource? source = null, CancellationToken ct = default)
    {
        lock (_gate)
        {
            var count = _failedLogins.Count(f =>
                f.TimestampUtc >= sinceUtc && (source is null || f.Source == source));
            return Task.FromResult(count);
        }
    }

    public Task<BanEntry?> GetBanAsync(string ip, CancellationToken ct = default)
    {
        lock (_gate)
        {
            return Task.FromResult(_bans.TryGetValue(ip, out var ban) ? Clone(ban) : null);
        }
    }

    /// <summary>
    /// Returns every ban, including expired ones: the engine applies its own clock
    /// (<c>TimeProvider</c>) to decide which bans are due, so the fake must not filter
    /// using the wall clock.
    /// </summary>
    public Task<IReadOnlyList<BanEntry>> GetActiveBansAsync(CancellationToken ct = default)
    {
        lock (_gate)
        {
            IReadOnlyList<BanEntry> result = _bans.Values.Select(Clone).ToList();
            return Task.FromResult(result);
        }
    }

    /// <summary>Due bans by the caller's clock (mirrors SqliteStore semantics).</summary>
    public Task<IReadOnlyList<BanEntry>> GetDueBansAsync(DateTime nowUtc, CancellationToken ct = default)
    {
        lock (_gate)
        {
            IReadOnlyList<BanEntry> result = _bans.Values
                .Where(b => !b.IsPermanent && b.ExpiresUtc <= nowUtc)
                .Select(Clone)
                .ToList();
            return Task.FromResult(result);
        }
    }

    public Task UpsertBanAsync(BanEntry ban, CancellationToken ct = default)
    {
        lock (_gate)
        {
            _bans[ban.IpAddress] = Clone(ban);
        }

        return Task.CompletedTask;
    }

    public Task RemoveBanAsync(string ip, CancellationToken ct = default)
    {
        lock (_gate)
        {
            _bans.Remove(ip);
        }

        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<string>> GetListAsync(ListKind kind, CancellationToken ct = default)
    {
        lock (_gate)
        {
            IReadOnlyList<string> values = _lists[kind].ToList();
            return Task.FromResult(values);
        }
    }

    public Task AddToListAsync(ListKind kind, string value, CancellationToken ct = default)
    {
        lock (_gate)
        {
            var list = _lists[kind];
            if (!list.Contains(value))
            {
                list.Add(value);
            }
        }

        return Task.CompletedTask;
    }

    public Task RemoveFromListAsync(ListKind kind, string value, CancellationToken ct = default)
    {
        lock (_gate)
        {
            _lists[kind].Remove(value);
        }

        return Task.CompletedTask;
    }

    public Task AddEventAsync(LogEvent logEvent, CancellationToken ct = default)
    {
        lock (_gate)
        {
            var copy = Clone(logEvent);
            copy.Id = ++_nextEventId;
            _events.Add(copy);
        }

        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<LogEvent>> GetEventsAsync(int limit, DateTime? sinceUtc = null, long? afterId = null, CancellationToken ct = default)
    {
        lock (_gate)
        {
            IReadOnlyList<LogEvent> result = _events
                .Where(e => (sinceUtc is null || e.TimestampUtc >= sinceUtc.Value) && (afterId is null || e.Id > afterId.Value))
                .OrderByDescending(e => e.TimestampUtc)
                .Take(limit)
                .Select(Clone)
                .ToList();
            return Task.FromResult(result);
        }
    }

    public Task PruneEventsAsync(DateTime olderThanUtc, CancellationToken ct = default)
    {
        lock (_gate)
        {
            _events.RemoveAll(e => e.TimestampUtc < olderThanUtc);
        }

        return Task.CompletedTask;
    }

    public Task<IReadOnlyDictionary<string, string>> GetAllSettingsAsync(CancellationToken ct = default)
    {
        lock (_gate)
        {
            IReadOnlyDictionary<string, string> result =
                new Dictionary<string, string>(_settings, StringComparer.Ordinal);
            return Task.FromResult(result);
        }
    }

    public Task SetSettingAsync(string key, string value, CancellationToken ct = default)
    {
        lock (_gate)
        {
            _settings[key] = value;
        }

        return Task.CompletedTask;
    }

    private static FailedLogin Clone(FailedLogin source) => new()
    {
        IpAddress = source.IpAddress,
        UserName = source.UserName,
        Source = source.Source,
        TimestampUtc = source.TimestampUtc,
        RawLog = source.RawLog,
    };

    private static BanEntry Clone(BanEntry source) => new()
    {
        IpAddress = source.IpAddress,
        Source = source.Source,
        BannedAtUtc = source.BannedAtUtc,
        ExpiresUtc = source.ExpiresUtc,
        OffenseCount = source.OffenseCount,
        IsPermanent = source.IsPermanent,
        Note = source.Note,
    };

    private static LogEvent Clone(LogEvent source) => new()
    {
        TimestampUtc = source.TimestampUtc,
        Level = source.Level,
        Source = source.Source,
        IpAddress = source.IpAddress,
        Message = source.Message,
    };
}