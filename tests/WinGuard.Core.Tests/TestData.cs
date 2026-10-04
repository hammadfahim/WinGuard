using WinGuard.Core.Config;

namespace WinGuard.Core.Tests;

/// <summary>
/// Access to the sample fixtures copied next to the test assembly by the csproj
/// (<c>samples/&lt;file&gt;</c> under <see cref="AppContext.BaseDirectory"/>).
/// </summary>
internal static class TestData
{
    public static string PathOf(string fileName) =>
        System.IO.Path.Combine(AppContext.BaseDirectory, "samples", fileName);

    public static string ReadText(string fileName) => File.ReadAllText(PathOf(fileName));

    public static string[] ReadLines(string fileName) => File.ReadAllLines(PathOf(fileName));

    public static WinGuardSettings NewSettings() => new();
}