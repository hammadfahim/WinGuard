using WinGuard.Core.Model;

namespace WinGuard.Core.Abstractions;

/// <summary>
/// Fan-out sink for engine events, next to their persistence in the store. The engine publishes
/// every event it records (blocks, unblocks, blacklist bans, errors); implementations decide what
/// to do with them — the default does nothing. Implementations must never throw and never block:
/// <see cref="Publish"/> is called on the engine's processing path.
/// </summary>
public interface IEventPublisher
{
    /// <summary>Offers one event to the publisher. Must be non-blocking and exception-free.</summary>
    void Publish(LogEvent logEvent);
}

/// <summary>Default no-op publisher (used when no sink is registered).</summary>
public sealed class NullEventPublisher : IEventPublisher
{
    /// <summary>Singleton instance.</summary>
    public static NullEventPublisher Instance { get; } = new();

    /// <inheritdoc />
    public void Publish(LogEvent logEvent)
    {
    }
}
