using System.Text;
using WinGuard.Core.Config;
using WinGuard.Core.Detection;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>
/// Tailer behavior around BOM detection, rotation by identity, record framing and the local-path
/// check. Every test works in its own temp folder.
/// </summary>
public sealed class LogFileTailerEncodingAndRotationTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("winguard-tailer-").FullName;

    public void Dispose() => Directory.Delete(_dir, true);

    // ---------- encodings ----------

    public static TheoryData<string, byte[], Encoding> Encodings() => new()
    {
        { "utf-8", [0xEF, 0xBB, 0xBF], new UTF8Encoding(false) },
        { "utf-16 le", [0xFF, 0xFE], new UnicodeEncoding(false, false) },
        { "utf-16 be", [0xFE, 0xFF], new UnicodeEncoding(true, false) },
        { "utf-32 le", [0xFF, 0xFE, 0x00, 0x00], new UTF32Encoding(false, false) },
        { "utf-32 be", [0x00, 0x00, 0xFE, 0xFF], new UTF32Encoding(true, false) },
    };

    [Theory]
    [MemberData(nameof(Encodings))]
    public void A_bom_selects_the_encoding_when_reading_from_the_start(string name, byte[] bom, Encoding encoding)
    {
        var path = WriteBytes(name + ".log", bom, encoding.GetBytes("LOGIN FAILED é\r\nsecond\r\n"));

        var lines = new LogFileTailer(processExistingContent: true).ReadNewLines(path);

        Assert.Equal(new[] { "LOGIN FAILED é", "second" }, lines);
    }

    [Theory]
    [MemberData(nameof(Encodings))]
    public void A_bom_is_honored_after_skipping_to_the_end(string name, byte[] bom, Encoding encoding)
    {
        var path = WriteBytes(name + ".log", bom, encoding.GetBytes("history\r\n"));
        var tailer = new LogFileTailer();
        Assert.Empty(tailer.ReadNewLines(path));

        Append(path, encoding.GetBytes("appended\r\n"));

        Assert.Equal(new[] { "appended" }, tailer.ReadNewLines(path));
    }

    [Fact]
    public void A_file_that_is_empty_at_first_sight_gets_its_encoding_when_content_arrives()
    {
        var path = WriteBytes("empty.log");
        var tailer = new LogFileTailer();
        Assert.Empty(tailer.ReadNewLines(path));

        Append(path, [0xFF, 0xFE], Encoding.Unicode.GetBytes("first\n"));

        Assert.Equal(new[] { "first" }, tailer.ReadNewLines(path));
    }

    [Fact]
    public void A_half_written_utf16_character_at_first_sight_does_not_shift_later_lines()
    {
        var encoding = new UnicodeEncoding(false, false);
        var path = WriteBytes("odd.log", [0xFF, 0xFE], encoding.GetBytes("history\n"), [0x41]);
        var tailer = new LogFileTailer();
        Assert.Empty(tailer.ReadNewLines(path));

        // The writer finishes its 'A', then writes a whole line.
        Append(path, [0x00], encoding.GetBytes("\nnext line\n"));

        Assert.Equal(new[] { "A", "next line" }, tailer.ReadNewLines(path));
    }

    [Fact]
    public void A_utf16_character_split_across_reads_is_not_corrupted()
    {
        var path = WriteBytes("split.log", [0xFF, 0xFE], Encoding.Unicode.GetBytes("é\n"));
        var tailer = new LogFileTailer(maxBytesPerCycle: 1, processExistingContent: true);

        var lines = new List<string>();
        for (var i = 0; i < 16; i++)
        {
            lines.AddRange(tailer.ReadNewLines(path));
        }

        Assert.Equal(new[] { "é" }, lines);
    }

    [Fact]
    public void The_encoding_is_read_again_after_rotation()
    {
        var path = WriteBytes("app.log", new UTF8Encoding(false).GetBytes("old\n"));
        var tailer = new LogFileTailer();
        Assert.Empty(tailer.ReadNewLines(path));

        File.Move(path, path + ".1");
        WriteBytes("app.log", [0xFF, 0xFE], Encoding.Unicode.GetBytes("utf-16 now\n"));

        Assert.Equal(new[] { "utf-16 now" }, tailer.ReadNewLines(path));
    }

    [Fact]
    public void The_encoding_is_read_again_after_truncation()
    {
        var path = WriteBytes("app.log", [0xFF, 0xFE], Encoding.Unicode.GetBytes("a long utf-16 line\n"));
        var tailer = new LogFileTailer();
        Assert.Empty(tailer.ReadNewLines(path));

        File.WriteAllBytes(path, Encoding.UTF8.GetBytes("short\n"));

        Assert.Equal(new[] { "short" }, tailer.ReadNewLines(path));
    }

    // ---------- rotation ----------

    [Fact]
    public void A_rotated_file_entering_the_glob_is_not_read_again_from_the_start()
    {
        var path = WriteBytes("app.log", Encoding.UTF8.GetBytes("history\n"));
        var tailer = new LogFileTailer();
        Assert.Empty(tailer.ReadNewLines(path));

        File.Move(path, path + ".1");
        WriteBytes("app.log", Encoding.UTF8.GetBytes("fresh\n"));

        // In sort order, as the detectors poll: the new file, then the renamed one.
        Assert.Equal(new[] { "fresh" }, tailer.ReadNewLines(path));
        Assert.Empty(tailer.ReadNewLines(path + ".1", readFromStartIfNew: true));
    }

    [Fact]
    public void Lines_written_just_before_rotation_are_still_read_under_the_new_name()
    {
        var path = WriteBytes("app.log", Encoding.UTF8.GetBytes("history\n"));
        var tailer = new LogFileTailer();
        Assert.Empty(tailer.ReadNewLines(path));

        Append(path, Encoding.UTF8.GetBytes("last line\n"));
        File.Move(path, path + ".1");
        WriteBytes("app.log", Encoding.UTF8.GetBytes("fresh\n"));

        Assert.Equal(new[] { "fresh" }, tailer.ReadNewLines(path));
        Assert.Equal(new[] { "last line" }, tailer.ReadNewLines(path + ".1", readFromStartIfNew: true));
    }

    [Fact]
    public void A_rotated_name_polled_first_also_continues_from_the_old_position()
    {
        var path = WriteBytes("z.log", Encoding.UTF8.GetBytes("history\n"));
        var rotated = Path.Combine(_dir, "a-old.log");
        var tailer = new LogFileTailer();
        Assert.Empty(tailer.ReadNewLines(path));

        Append(path, Encoding.UTF8.GetBytes("last line\n"));
        File.Move(path, rotated);
        WriteBytes("z.log", Encoding.UTF8.GetBytes("fresh\n"));

        Assert.Equal(new[] { "last line" }, tailer.ReadNewLines(rotated, readFromStartIfNew: true));
        Assert.Equal(new[] { "fresh" }, tailer.ReadNewLines(path));
    }

    [Fact]
    public void A_different_file_under_a_new_name_is_still_read_from_the_start()
    {
        var path = WriteBytes("a.log", Encoding.UTF8.GetBytes("history\n"));
        var tailer = new LogFileTailer();
        Assert.Empty(tailer.ReadNewLines(path));

        var next = WriteBytes("b.log", Encoding.UTF8.GetBytes("new\n"));

        Assert.Equal(new[] { "new" }, tailer.ReadNewLines(next, readFromStartIfNew: true));
    }

    // ---------- record framing ----------

    [Fact]
    public void Client_text_with_a_bare_lf_cannot_become_a_line_of_its_own()
    {
        const string forged = "\"SMTPD\"\t1\t2\t\"2026-10-04 09:00:00.000\"\t\"198.51.100.9\"\t\"SENT: 535 Authentication failed.\"";
        var record = "\"SMTPD\"\t7\t8\t\"2026-10-04 09:00:00.000\"\t\"203.0.113.1\"\t\"RECEIVED: NOOP\n" + forged + "\r\n";
        var path = WriteBytes("hmail.log", Encoding.UTF8.GetBytes(record + "next record\r\n"));

        var strict = new LogFileTailer(processExistingContent: true).ReadNewLines(path, crLfRecords: true);
        var defaults = new LogFileTailer(processExistingContent: true).ReadNewLines(path);

        Assert.Equal(new[] { record[..^2], "next record" }, strict);
        Assert.Contains(forged, defaults); // what strict framing exists to prevent
    }

    [Fact]
    public void A_crlf_split_across_reads_still_ends_a_record()
    {
        var path = WriteBytes("hmail.log", Encoding.UTF8.GetBytes("one\r\ntwo\r\n"));
        var tailer = new LogFileTailer(maxBytesPerCycle: 4, processExistingContent: true);

        var lines = new List<string>();
        for (var i = 0; i < 4; i++)
        {
            lines.AddRange(tailer.ReadNewLines(path, crLfRecords: true));
        }

        Assert.Equal(new[] { "one", "two" }, lines);
    }

    [Fact]
    public void An_overlong_line_is_dropped_whole_instead_of_keeping_its_client_chosen_tail()
    {
        const int chunk = 32 * 1024;
        var text = new string('x', chunk * 4) + " LOGIN FAILED ip=198.51.100.9\nnext line\n";
        var path = WriteBytes("long.log", Encoding.UTF8.GetBytes(text));
        var tailer = new LogFileTailer(maxBytesPerCycle: chunk, processExistingContent: true);

        var lines = new List<string>();
        for (var i = 0; i < 8; i++)
        {
            lines.AddRange(tailer.ReadNewLines(path));
        }

        Assert.Equal(new[] { "next line" }, lines);
    }

    // ---------- local paths ----------

    [Theory]
    [InlineData(@"\/server\share\ftp.log")]
    [InlineData(@"/\server\share\ftp.log")]
    [InlineData(@"\\/server/share/ftp.log")]
    [InlineData(@"  \\server\share\ftp.log")]
    [InlineData(@"""\\server\share\ftp.log""")]
    [InlineData(@"\\.\C:\logs\ftp.log")]
    [InlineData(@"\\.\pipe\winguard")]
    [InlineData(@"\\?\UNC\server\share\ftp.log")]
    [InlineData(@"//?/C:/logs/ftp.log")]
    [InlineData(@"/\?\C:\logs\ftp.log")]
    [InlineData(@"\??\C:\logs\ftp.log")]
    [InlineData(@"\??\UNC\server\share\ftp.log")]
    [InlineData(@"/??/C:/logs/ftp.log")]
    public void Network_and_device_paths_are_refused_by_the_tailer_and_the_validator(string path)
    {
        Assert.False(LogFileTailer.IsLocalPath(path));
        Assert.Empty(LogFileTailer.ResolveFiles(path));
        AssertRefusedBySettingsValidator(path);
    }

    [Fact]
    public void An_environment_variable_cannot_smuggle_in_a_unc_path()
    {
        var direct = "WINGUARD_TEST_UNC_" + Guid.NewGuid().ToString("N");
        var indirect = "WINGUARD_TEST_INDIRECT_" + Guid.NewGuid().ToString("N");
        var padded = "WINGUARD_TEST_PADDED_" + Guid.NewGuid().ToString("N");
        Environment.SetEnvironmentVariable(direct, @"\\server\share");
        Environment.SetEnvironmentVariable(indirect, $"%{direct}%");
        Environment.SetEnvironmentVariable(padded, @"  /\server\share");
        try
        {
            foreach (var path in new[] { $@"%{direct}%\ftp.log", $@"%{indirect}%\ftp.log", $@"%{padded}%\ftp.log", $@"\%{direct}%" })
            {
                Assert.False(LogFileTailer.IsLocalPath(path));
                Assert.Empty(LogFileTailer.ResolveFiles(path));
                AssertRefusedBySettingsValidator(path);
            }
        }
        finally
        {
            Environment.SetEnvironmentVariable(direct, null);
            Environment.SetEnvironmentVariable(indirect, null);
            Environment.SetEnvironmentVariable(padded, null);
        }
    }

    [Theory]
    [InlineData(@"C:\logs\ftp.log")]
    [InlineData("C:/logs/ftp.log")]
    [InlineData(@"D:\logs\*.log")]
    [InlineData(@"logs\relative.log")]
    [InlineData(@"\rooted\ftp.log")]
    public void Ordinary_local_paths_are_still_accepted(string path) =>
        Assert.True(LogFileTailer.IsLocalPath(path));

    private static void AssertRefusedBySettingsValidator(string path)
    {
        var settings = new WinGuardSettings();
        settings.Ftp.Sources.Add(new FtpLogSource { Name = "ftp", Path = path });
        settings.CustomSources.Add(new CustomLogSource { Name = "custom", PathGlob = path, Regex = "(?<ipaddress>x)" });

        var problems = SettingsValidator.Validate(settings);

        Assert.Contains(problems, p => p.Contains("'ftp'") && p.Contains("UNC"));
        Assert.Contains(problems, p => p.Contains("'custom'") && p.Contains("UNC"));
    }

    private string WriteBytes(string name, params byte[][] parts)
    {
        var path = Path.Combine(_dir, name);
        File.WriteAllBytes(path, parts.SelectMany(part => part).ToArray());
        return path;
    }

    private static void Append(string path, params byte[][] parts)
    {
        using var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
        foreach (var part in parts)
        {
            stream.Write(part);
        }
    }
}
