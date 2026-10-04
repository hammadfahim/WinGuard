using WinGuard.Core.Detection;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>
/// Tests for the shared tailer's first-sight/rotation cursor behavior (fix D1, PLAN.md §4.4):
/// a restart must never replay historical failures, while a rotated/truncated file is read fully.
/// </summary>
public sealed class LogFileTailerTests
{
    [Fact]
    public void First_sight_skips_existing_content_by_default()
    {
        var path = NewTempFile("old line 1\nold line 2\n");
        try
        {
            var tailer = new LogFileTailer();

            // Existing content is skipped: nothing to read on the first sight of the file.
            Assert.Empty(tailer.ReadNewLines(path));

            File.AppendAllText(path, "new line\n");
            Assert.Equal(new[] { "new line" }, tailer.ReadNewLines(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Process_existing_content_reads_from_the_start()
    {
        var path = NewTempFile("old line 1\nold line 2\n");
        try
        {
            var tailer = new LogFileTailer(processExistingContent: true);

            Assert.True(tailer.ProcessExistingContent);
            Assert.Equal(new[] { "old line 1", "old line 2" }, tailer.ReadNewLines(path));

            File.AppendAllText(path, "new line\n");
            Assert.Equal(new[] { "new line" }, tailer.ReadNewLines(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Shrinking_file_resets_offset_and_reads_rotated_content()
    {
        var path = NewTempFile("old line one\n");
        try
        {
            var tailer = new LogFileTailer();
            Assert.Empty(tailer.ReadNewLines(path)); // skip-to-end, offset = 13

            // Rotation via truncation to a shorter file: the offset must reset to 0.
            File.WriteAllText(path, "rot\n");
            Assert.Equal(new[] { "rot" }, tailer.ReadNewLines(path));

            File.AppendAllText(path, "ated\n");
            Assert.Equal(new[] { "ated" }, tailer.ReadNewLines(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static string NewTempFile(string content)
    {
        var path = Path.Combine(Path.GetTempPath(), "winguard-tailer-" + Guid.NewGuid().ToString("N") + ".log");
        File.WriteAllText(path, content);
        return path;
    }
}