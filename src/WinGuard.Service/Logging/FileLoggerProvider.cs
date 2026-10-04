using Microsoft.Extensions.Logging;

namespace WinGuard.Service.Logging;

/// <summary>
/// Minimal file logger provider writing to <c>%ProgramData%\WinGuard\Logs\winguard-yyyyMMdd.log</c>
/// (PLAN.md §10). One daily file kept open behind one shared lock, timestamp + level + category +
/// message + exception. A file that reaches the size cap is rolled to <c>winguard-yyyyMMdd.1.log</c>. No external
/// logging package is used and I/O errors never take the service down.
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
        lock (_gate)
        {
            CloseWriter();
        }
    }

    internal void Write(LogLevel level, string category, string message)
    {
        try
        {
            var now = DateTime.Now;
            var line = $"{now:yyyy-MM-dd HH:mm:ss.fff} [{Level(level)}] {category}: {message}{Environment.NewLine}";
            lock (_gate)
            {
                SweepRetention();
                EnsureWriter(now.Date);
                if (_writer is null)
                {
                    return;
                }

                // Size cap: when the day's file is full it becomes "<name>.1.log" (replacing an
                // earlier one) and a fresh file is started, so a log flood can use at most twice
                // the cap per day and the most recent entries — including errors — are never lost.
                if (_bytesWritten >= MaxFileBytes)
                {
                    Rotate(now.Date);
                    if (_writer is null)
                    {
                        return;
                    }
                }

                _writer.Write(line);
                _bytesWritten += System.Text.Encoding.UTF8.GetByteCount(line);
            }
        }
        catch (Exception)
        {
            // Never let a logging failure propagate into the service.
        }
    }

    private const long MaxFileBytes = 10 * 1024 * 1024;

    // The day's file stays open (one buffered writer) instead of being opened and closed per line.
    private StreamWriter? _writer;
    private DateTime _writerDate;
    private long _bytesWritten;

    private string PathFor(DateTime date) => Path.Combine(_directory, $"winguard-{date:yyyyMMdd}.log");

    private void EnsureWriter(DateTime date)
    {
        if (_writer is not null && _writerDate == date)
        {
            return;
        }

        CloseWriter();
        try
        {
            var stream = new FileStream(PathFor(date), FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
            _bytesWritten = stream.Length;
            _writer = new StreamWriter(stream, new System.Text.UTF8Encoding(false)) { AutoFlush = true };
            _writerDate = date;
        }
        catch (Exception)
        {
            _writer = null;
        }
    }

    private void Rotate(DateTime date)
    {
        CloseWriter();
        try
        {
            var rolled = Path.Combine(_directory, $"winguard-{date:yyyyMMdd}.1.log");
            File.Move(PathFor(date), rolled, overwrite: true);
        }
        catch (Exception)
        {
            // Could not roll (file in use elsewhere): start over in place rather than stop logging.
            try
            {
                File.Delete(PathFor(date));
            }
            catch (Exception)
            {
                // Keep appending to the oversized file as a last resort.
            }
        }

        EnsureWriter(date);
        _bytesWritten = 0;
    }

    private void CloseWriter()
    {
        try
        {
            _writer?.Dispose();
        }
        catch (Exception)
        {
            // Ignore.
        }

        _writer = null;
    }

    private const int RetentionDays = 30;

    private DateTime _lastRetentionSweep = DateTime.MinValue;

    /// <summary>Deletes winguard-*.log files older than <see cref="RetentionDays"/> (once per day). Call under _gate.</summary>
    private void SweepRetention()
    {
        var today = DateTime.Now.Date;
        if ((today - _lastRetentionSweep).TotalHours < 24)
        {
            return;
        }

        _lastRetentionSweep = today;
        try
        {
            var cutoff = today.AddDays(-RetentionDays);
            foreach (var file in Directory.GetFiles(_directory, "winguard-*.log"))
            {
                try
                {
                    if (File.GetLastWriteTime(file) < cutoff)
                    {
                        File.Delete(file);
                    }
                }
                catch (Exception)
                {
                    // Best effort per file.
                }
            }
        }
        catch (Exception)
        {
            // Best effort.
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