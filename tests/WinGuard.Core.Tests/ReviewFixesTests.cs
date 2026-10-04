using System.Text;
using System.Text.Json;
using WinGuard.Core.Config;
using WinGuard.Core.Detection;
using Xunit;

namespace WinGuard.Core.Tests;

public class ReviewFixesTests
{
    [Fact]
    public void Normalize_survives_null_members_and_caps_huge_durations()
    {
        var settings = JsonSerializer.Deserialize<WinGuardSettings>(
            "{\"BlockedPorts\":null,\"Rdp\":null,\"Ftp\":null,\"CustomSources\":null,\"MaxBanDuration\":\"-1.00:00:00\",\"BanTiers\":[\"10000000.00:00:00\"]}")!;

        settings.Normalize();

        Assert.NotNull(settings.Rdp);
        Assert.NotNull(settings.Ftp);
        Assert.Empty(settings.BlockedPorts);
        Assert.True(settings.MaxBanDuration > TimeSpan.Zero);
        Assert.True(DateTime.UtcNow + settings.TierForOffense(1) < DateTime.MaxValue);
    }

    [Fact]
    public void Tailer_does_not_corrupt_multibyte_char_split_across_reads()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, string.Empty);
            var tailer = new LogFileTailer(maxBytesPerCycle: 1, processExistingContent: true);
            File.WriteAllBytes(path, Encoding.UTF8.GetBytes("café user\n"));

            var lines = new List<string>();
            for (var i = 0; i < 32; i++)
            {
                lines.AddRange(tailer.ReadNewLines(path));
            }

            Assert.Equal(new[] { "café user" }, lines);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Tailer_detects_rotation_to_an_equal_or_larger_file()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, "aaaa\n");
            var tailer = new LogFileTailer();
            Assert.Empty(tailer.ReadNewLines(path)); // first sight: skip to end

            File.Delete(path);
            File.WriteAllText(path, "bbbb\ncccc\n");
            File.SetCreationTimeUtc(path, DateTime.UtcNow.AddMinutes(5));

            Assert.Equal(new[] { "bbbb", "cccc" }, tailer.ReadNewLines(path));
        }
        finally
        {
            File.Delete(path);
        }
    }
}
