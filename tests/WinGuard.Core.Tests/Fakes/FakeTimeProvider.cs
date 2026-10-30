namespace WinGuard.Core.Tests.Fakes;

/// <summary>
/// A <see cref="TimeProvider"/> whose UTC clock can be set and advanced by tests.
/// Only <see cref="GetUtcNow"/> and, when <see cref="LocalZone"/> is set, the local time zone are
/// overridden; timestamp/stopwatch APIs keep the base implementation (irrelevant for the pure
/// engine logic under test).
/// </summary>
public sealed class FakeTimeProvider : TimeProvider
{
    private DateTimeOffset _utcNow;

    public FakeTimeProvider()
        : this(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero))
    {
    }

    public FakeTimeProvider(DateTimeOffset utcNow) => _utcNow = utcNow;

    /// <summary>Settable current UTC time.</summary>
    public DateTimeOffset UtcNow
    {
        get => _utcNow;
        set => _utcNow = value;
    }

    /// <summary>The local time zone to report; null keeps the machine's.</summary>
    public TimeZoneInfo? LocalZone { get; set; }

    public override TimeZoneInfo LocalTimeZone => LocalZone ?? base.LocalTimeZone;

    public override DateTimeOffset GetUtcNow() => _utcNow;

    /// <summary>Move the clock forward by <paramref name="delta"/>.</summary>
    public void Advance(TimeSpan delta) => _utcNow = _utcNow.Add(delta);
}