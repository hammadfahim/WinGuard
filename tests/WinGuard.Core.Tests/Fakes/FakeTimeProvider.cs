namespace WinGuard.Core.Tests.Fakes;

/// <summary>
/// A <see cref="TimeProvider"/> whose UTC clock can be set and advanced by tests.
/// Only <see cref="GetUtcNow"/> is overridden; timestamp/stopwatch APIs keep the base
/// implementation (irrelevant for the pure engine logic under test).
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

    public override DateTimeOffset GetUtcNow() => _utcNow;

    /// <summary>Move the clock forward by <paramref name="delta"/>.</summary>
    public void Advance(TimeSpan delta) => _utcNow = _utcNow.Add(delta);
}