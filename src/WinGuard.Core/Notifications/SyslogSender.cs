using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using WinGuard.Core.Config;
using WinGuard.Core.Model;

namespace WinGuard.Core.Notifications;

/// <summary>One formatted message and where it goes.</summary>
internal sealed record SyslogMessage(string Host, int Port, SyslogProtocol Protocol, byte[] Payload);

/// <summary>Puts one message on the wire. Implementations honor the token for everything that can wait.</summary>
internal interface ISyslogTransport : IDisposable
{
    /// <summary>Sends a message; failures throw.</summary>
    Task SendAsync(SyslogMessage message, CancellationToken ct);
}

/// <summary>
/// The syslog channel. The dispatcher's loop hands every event over and moves on, so a receiver
/// that hangs costs this channel its own queue and nothing else: waiting for it on the dispatcher's
/// loop would hold every other channel back by a timeout per event.
/// </summary>
internal sealed class SyslogSender : IDisposable
{
    private const int QueueCapacity = 1000;

    private readonly ILogger _logger;
    private readonly ISyslogTransport _transport;
    private readonly Channel<SyslogMessage> _queue;
    private readonly string _hostName = LocalHostName();
    private readonly int _processId = Environment.ProcessId;
    private readonly string _version = typeof(SyslogSender).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";

    private CancellationTokenSource? _cts;
    private Task? _loop;

    // Dropped since the last message that got through; written by the queue's callback.
    private long _dropped;

    // Only the loop uses this: an outage is reported when it starts and when it ends.
    private bool _failing;

    /// <summary>Creates the sender. Call <see cref="Start"/> to begin delivery.</summary>
    public SyslogSender(ILogger logger, ISyslogTransport transport)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
        _queue = Channel.CreateBounded<SyslogMessage>(
            new BoundedChannelOptions(QueueCapacity)
            {
                SingleReader = true,
                FullMode = BoundedChannelFullMode.DropWrite,
            },
            _ => Interlocked.Increment(ref _dropped));
    }

    /// <summary>How long one message may take, connection included.</summary>
    internal TimeSpan SendTimeout { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>Messages dropped since the last one that got through.</summary>
    internal long Dropped => Interlocked.Read(ref _dropped);

    /// <summary>Queues an event when the channel is on. Never blocks and never throws.</summary>
    public void Enqueue(LogEvent logEvent, SyslogSettings? settings)
    {
        if (settings is not { Enabled: true } || string.IsNullOrWhiteSpace(settings.Host))
        {
            return;
        }

        try
        {
            var payload = SyslogFormatter.Format(logEvent, settings, _hostName, _processId, _version);
            _queue.Writer.TryWrite(new SyslogMessage(settings.Host.Trim(), settings.Port, settings.Protocol, payload));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not format a syslog message.");
        }
    }

    /// <summary>Starts the delivery loop.</summary>
    public void Start()
    {
        if (_loop is not null)
        {
            return;
        }

        _cts = new CancellationTokenSource();
        var token = _cts.Token;
        _loop = Task.Run(() => DeliverLoopAsync(token), CancellationToken.None);
    }

    /// <summary>Stops the delivery loop; what is still queued is dropped, as with the other channels.</summary>
    public async Task StopAsync()
    {
        _cts?.Cancel();
        if (_loop is not null)
        {
            await _loop.ConfigureAwait(false);
        }

        _loop = null;
        _cts?.Dispose();
        _cts = null;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;
        _transport.Dispose();
    }

    private async Task DeliverLoopAsync(CancellationToken ct)
    {
        try
        {
            await foreach (var message in _queue.Reader.ReadAllAsync(ct).ConfigureAwait(false))
            {
                await DeliverAsync(message, ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Normal stop.
        }
    }

    private async Task DeliverAsync(SyslogMessage message, CancellationToken ct)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(SendTimeout);
            await _transport.SendAsync(message, timeout.Token).ConfigureAwait(false);

            var dropped = Interlocked.Exchange(ref _dropped, 0);
            if (_failing || dropped > 0)
            {
                _failing = false;
                _logger.LogInformation("Syslog delivery to {Host}:{Port} works again; {Dropped} message(s) were dropped meanwhile.", message.Host, message.Port, dropped);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            if (!_failing)
            {
                _failing = true;
                var reason = ex is OperationCanceledException ? "timed out" : ex.GetBaseException().Message;
                _logger.LogWarning("Syslog delivery to {Host}:{Port} failed: {Reason}. Not reported again until it works.", message.Host, message.Port, reason);
            }
        }
    }

    /// <summary>RFC 5424 §6.2.4 prefers the FQDN. Both parts come from local configuration, so this sends no query.</summary>
    private static string LocalHostName()
    {
        try
        {
            var domain = IPGlobalProperties.GetIPGlobalProperties().DomainName;
            return string.IsNullOrEmpty(domain) ? Environment.MachineName : $"{Environment.MachineName}.{domain}";
        }
        catch (Exception)
        {
            return Environment.MachineName;
        }
    }
}

/// <summary>
/// UDP datagrams, or a kept-open TCP connection with one message per line. That is the
/// "non-transparent framing" of RFC 6587 §3.4.2, which every receiver of this format reads, and
/// safe here because the formatter leaves no line break inside a message.
/// </summary>
internal sealed class SocketSyslogTransport : ISyslogTransport
{
    private const byte LineFeed = (byte)'\n';

    // Only the sender's loop calls in, one message at a time.
    private TcpClient? _client;
    private string? _endpoint;

    /// <inheritdoc />
    public Task SendAsync(SyslogMessage message, CancellationToken ct) =>
        message.Protocol == SyslogProtocol.Tcp ? SendTcpAsync(message, ct) : SendUdpAsync(message, ct);

    /// <inheritdoc />
    public void Dispose() => Disconnect();

    private static async Task SendUdpAsync(SyslogMessage message, CancellationToken ct)
    {
        var address = await ResolveAsync(message.Host, ct).ConfigureAwait(false);
        using var socket = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        await socket.SendToAsync(message.Payload, SocketFlags.None, new IPEndPoint(address, message.Port), ct).ConfigureAwait(false);
    }

    private static async Task<IPAddress> ResolveAsync(string host, CancellationToken ct)
    {
        if (IPAddress.TryParse(host, out var literal))
        {
            return literal;
        }

        var addresses = await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
        return addresses.Length > 0 ? addresses[0] : throw new SocketException((int)SocketError.HostNotFound);
    }

    private async Task SendTcpAsync(SyslogMessage message, CancellationToken ct)
    {
        var frame = new byte[message.Payload.Length + 1];
        message.Payload.CopyTo(frame, 0);
        frame[^1] = LineFeed;

        var stream = await ConnectedStreamAsync(message, ct).ConfigureAwait(false);
        try
        {
            await stream.WriteAsync(frame, ct).ConfigureAwait(false);
            await stream.FlushAsync(ct).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // A half-written line would run into the next message.
            Disconnect();
            throw;
        }
    }

    private async Task<NetworkStream> ConnectedStreamAsync(SyslogMessage message, CancellationToken ct)
    {
        var endpoint = $"{message.Host}:{message.Port}";
        if (_client is null || !string.Equals(_endpoint, endpoint, StringComparison.OrdinalIgnoreCase) || IsClosedByPeer(_client))
        {
            Disconnect();
            var client = new TcpClient();
            try
            {
                await client.ConnectAsync(message.Host, message.Port, ct).ConfigureAwait(false);
            }
            catch (Exception)
            {
                client.Dispose();
                throw;
            }

            _client = client;
            _endpoint = endpoint;
        }

        return _client.GetStream();
    }

    /// <summary>A receiver that went away: the first write would still appear to work, and lose its message.</summary>
    private static bool IsClosedByPeer(TcpClient client)
    {
        try
        {
            return client.Client.Poll(0, SelectMode.SelectRead) && client.Client.Available == 0;
        }
        catch (Exception)
        {
            return true;
        }
    }

    private void Disconnect()
    {
        _client?.Dispose();
        _client = null;
        _endpoint = null;
    }
}
