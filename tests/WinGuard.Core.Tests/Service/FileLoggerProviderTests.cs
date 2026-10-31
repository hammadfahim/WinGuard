using Microsoft.Extensions.Logging;
using WinGuard.Service.Logging;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>The file log: one line per entry, whatever an attacker managed to put in a message.</summary>
public sealed class FileLoggerProviderTests : IDisposable
{
    private const string ForgedEntry = "2026-01-01 00:00:00.000 [ERR] WinGuard.Service: forged";

    private readonly string _directory = Path.Combine(Path.GetTempPath(), "winguard-log-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    private string[] WriteAndRead(Action<ILogger> write)
    {
        using (var provider = new FileLoggerProvider(_directory))
        {
            write(provider.CreateLogger("Test"));
        }

        return File.ReadAllLines(Directory.GetFiles(_directory, "winguard-*.log").Single());
    }

    [Theory]
    [InlineData(0x0A)]
    [InlineData(0x0D)]
    [InlineData(0x85)]
    [InlineData(0x2028)]
    [InlineData(0x2029)]
    public void A_user_name_cannot_forge_a_log_entry(int lineBreak)
    {
        var lines = WriteAndRead(logger => logger.LogWarning("Failed login for {User}.", "bob" + (char)lineBreak + ForgedEntry));

        var line = Assert.Single(lines);
        Assert.Contains("Failed login for bob", line);
        Assert.DoesNotContain((char)lineBreak, line);
    }

    [Fact]
    public void Escaped_text_stays_readable()
    {
        Assert.Equal(@"a\r\nb\u0007c	d", FileLoggerProvider.Escape("a\r\nb\u0007c\td"));
    }

    [Fact]
    public void Clean_text_is_passed_through_untouched()
    {
        const string text = "BLOCKED 203.0.113.7 for 1d (offense #2)";

        Assert.Same(text, FileLoggerProvider.Escape(text));
    }

    [Fact]
    public void An_exception_keeps_its_lines_but_none_can_pass_for_an_entry()
    {
        var error = new InvalidOperationException("bad user bob\n" + ForgedEntry);

        var lines = WriteAndRead(logger => logger.LogError(error, "Request failed."));

        Assert.EndsWith("Request failed.", lines[0]);
        Assert.True(lines.Length >= 3, string.Join(Environment.NewLine, lines));
        Assert.All(lines.Skip(1), line => Assert.StartsWith("    ", line));
    }

    [Fact]
    public void Writes_after_disposal_do_not_reopen_the_file()
    {
        var provider = new FileLoggerProvider(_directory);
        var logger = provider.CreateLogger("Test");
        logger.LogInformation("before");
        provider.Dispose();

        logger.LogInformation("after");

        var file = Directory.GetFiles(_directory, "winguard-*.log").Single();
        File.Delete(file); // would fail if the late write had reopened it
        Assert.False(File.Exists(file));
    }
}
