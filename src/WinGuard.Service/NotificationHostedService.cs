using Microsoft.Extensions.Hosting;
using WinGuard.Core.Notifications;

namespace WinGuard.Service;

/// <summary>
/// Starts and stops the <see cref="NotificationDispatcher"/> delivery loop with the host lifetime,
/// so webhook/Telegram/SMTP delivery shuts down cleanly with the service.
/// </summary>
public sealed class NotificationHostedService : BackgroundService
{
    private readonly NotificationDispatcher _dispatcher;

    public NotificationHostedService(NotificationDispatcher dispatcher)
    {
        _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
    }

    /// <inheritdoc />
    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _dispatcher.Start();
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        try
        {
            // Bounded by the host's shutdown timeout: a delivery stuck in a blocking call (the
            // event-log writer's) must not hold the whole service in STOP_PENDING.
            await _dispatcher.StopAsync().WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // The host gave up waiting; what is pending was best-effort anyway.
        }

        await base.StopAsync(cancellationToken).ConfigureAwait(false);
    }
}
