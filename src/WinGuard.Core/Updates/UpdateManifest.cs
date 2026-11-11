using System.Text;
using System.Text.Json;

namespace WinGuard.Core.Updates;

/// <summary>Why an update could not be checked, downloaded or trusted; the message is for the console to show.</summary>
public sealed class UpdateException : Exception
{
    /// <summary>Creates the exception.</summary>
    public UpdateException(string message, Exception? inner = null)
        : base(message, inner)
    {
    }
}

/// <summary>
/// What a release says about its installer: the file <c>latest.json</c> the release workflow
/// publishes next to it. The bytes are signed, and nothing here is believed before the signature
/// has been checked (<see cref="UpdateSignature"/>). Even then every field is held to a narrow
/// form, so a manifest can name one installer of this project and nothing else.
/// </summary>
/// <param name="Version">The release, three numbers.</param>
/// <param name="File">Name of the installer asset, always <c>WinGuard-Setup-&lt;version&gt;.exe</c>.</param>
/// <param name="Size">Size of the installer in bytes.</param>
/// <param name="Sha256">SHA-256 of the installer, 64 lower-case hex digits.</param>
public sealed record UpdateManifest(Version Version, string File, long Size, string Sha256)
{
    /// <summary>A manifest is four short fields; anything longer is not one.</summary>
    public const int MaxManifestBytes = 16 * 1024;

    /// <summary>No installer of this project comes near this; it bounds what a download may fill.</summary>
    public const long MaxInstallerBytes = 512L * 1024 * 1024;

    /// <summary>The version as it appears in tags and file names, e.g. "0.3.3".</summary>
    public string VersionText => Version.ToString(3);

    /// <summary>The only installer name a release of this version may carry.</summary>
    public static string InstallerName(Version version) => $"WinGuard-Setup-{version.ToString(3)}.exe";

    /// <summary>Reads "1.2.3" and nothing looser: no fourth number, no sign, no spaces.</summary>
    public static bool TryParseVersion(string? text, out Version version)
    {
        version = new Version(0, 0, 0);
        if (string.IsNullOrEmpty(text) || text.Length > 32 || text.Any(c => c != '.' && !char.IsAsciiDigit(c)))
        {
            return false;
        }

        if (!Version.TryParse(text, out var parsed) || parsed.Build < 0 || parsed.Revision >= 0)
        {
            return false;
        }

        version = parsed;
        return true;
    }

    /// <summary>Builds the manifest for an installer file; used by the release workflow's tool.</summary>
    public static UpdateManifest Create(Version version, long size, string sha256) =>
        Validate(new UpdateManifest(version, InstallerName(version), size, sha256.ToLowerInvariant()));

    /// <summary>The exact bytes that are signed and published.</summary>
    public byte[] ToJson() =>
        Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["version"] = VersionText,
            ["file"] = File,
            ["size"] = Size,
            ["sha256"] = Sha256,
        }));

    /// <summary>Reads a manifest whose signature has been checked.</summary>
    /// <exception cref="UpdateException">The text is not a manifest of the expected form.</exception>
    public static UpdateManifest Parse(ReadOnlySpan<byte> json)
    {
        if (json.Length > MaxManifestBytes)
        {
            throw new UpdateException("The update information is too large to be genuine.");
        }

        try
        {
            using var document = JsonDocument.Parse(json.ToArray());
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("version", out var versionNode) || versionNode.ValueKind != JsonValueKind.String
                || !root.TryGetProperty("file", out var fileNode) || fileNode.ValueKind != JsonValueKind.String
                || !root.TryGetProperty("size", out var sizeNode) || !sizeNode.TryGetInt64(out var size)
                || !root.TryGetProperty("sha256", out var hashNode) || hashNode.ValueKind != JsonValueKind.String
                || !TryParseVersion(versionNode.GetString(), out var version))
            {
                throw new UpdateException("The update information is not in the expected form.");
            }

            return Validate(new UpdateManifest(version, fileNode.GetString()!, size, hashNode.GetString()!));
        }
        catch (JsonException ex)
        {
            throw new UpdateException("The update information is not in the expected form.", ex);
        }
    }

    private static UpdateManifest Validate(UpdateManifest manifest)
    {
        if (!string.Equals(manifest.File, InstallerName(manifest.Version), StringComparison.Ordinal))
        {
            throw new UpdateException("The update information names a file that is not this release's installer.");
        }

        if (manifest.Size <= 0 || manifest.Size > MaxInstallerBytes)
        {
            throw new UpdateException("The update information gives an installer size that cannot be right.");
        }

        if (manifest.Sha256.Length != 64 || manifest.Sha256.Any(c => !char.IsAsciiHexDigitLower(c)))
        {
            throw new UpdateException("The update information gives a checksum that is not SHA-256.");
        }

        return manifest;
    }
}
