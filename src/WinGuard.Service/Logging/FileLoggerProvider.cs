using Microsoft.Extensions.Logging;

namespace WinGuard.Service.Logging;

/// <summary>
/// Minimal file logger provider writing to <c>%ProgramData%\WinGuard\Logs\winguard-yyyyMMdd.log</c>
/// (PLAN.md §10). One daily file, one shared lock for the whole process, timestamp + level +
/// category + message + exception. No external logging package is used and I/O errors never take
/// the service down.
/// </summary>
public sealed class FileLoggerProvider : ILoggerProvider
{
    private readonly string _directory;
    private readonly LogLevel _minimumLevel;
    private readonly object _gate = new();

    /// <summary>Creates the provider and ensures the log directory exists.</summary>
    /// <param name="directory">Absolute log directory (typically <c>%ProgramData%\WinGuard\Logs</c>).</param>
    /// <param name="minimumLevel">Lowest level written to the file.</param>
    public FileLoggerProvider(string directory, LogLevel minimumLevel = LogLevel.Information)
    {
        _directory = directory ?? throw new ArgumentNullException(nameof(directory));
        _minimumLevel = minimumLevel;
        try
        {
            Directory.CreateDirectory(_directory);
        }
        catch (Exception)
        {
            // Logging must never prevent startup; writes will fail softly below.
        }
    }

    /// <summary>Lowest level written to the file.</summary>
    public LogLevel MinimumLevel => _minimumLevel;

    /// <inheritdoc />
    public ILogger CreateLogger(string categoryName) => new FileLogger(this, categoryName);

    /// <inheritdoc />
    public void Dispose()
    {
        // Files are opened/closed per write, so there is nothing to release.
    }

    internal void Write(LogLevel level, string category, string message)
    {
        try
        {
            var line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} [{Level(level)}] {category}: {message}{Environment.NewLine}";
            var path = Path.Combine(_directory, $"winguard-{DateTime.Now:yyyyMMdd}.log");
            lock (_gate)
            {
                File.AppendAllText(path, line);
            }
        }
        catch (Exception)
        {
            // Never let a logging failure propagate into the service.
        }
    }

    private static string Level(LogLevel level) => level switch
    {
        LogLevel.Trace => "TRC",
        LogLevel.Debug => "DBG",
        LogLevel.Information => "INF",
        LogLevel.Warning => "WRN",
        LogLevel.Error => "ERR",
        LogLevel.Critical => "CRT",
        _ => "___",
    };

    private sealed class FileLogger : ILogger
    {
        private readonly FileLoggerProvider _provider;
        private readonly string _category;

        public FileLogger(FileLoggerProvider provider, string category)
        {
            _provider = provider;
            _category = category;
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) =>
            logLevel != LogLevel.None && logLevel >= _provider.MinimumLevel;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel))
            {
                return;
            }

            var message = formatter(state, exception);
            if (exception is not null)
            {
                message += Environment.NewLine + exception;
            }

            _provider.Write(logLevel, _category, message);
        }
    }
}