namespace WinGuard.Core.Updates;

/// <summary>
/// Where updates come from and whose signature counts. Everything is on GitHub: the manifest and
/// the installer are assets of the project's releases, and no other service is asked anything.
/// The addresses are built here from a version and never taken from what was downloaded.
/// </summary>
public sealed class UpdateSource
{
    /// <summary>The project's own releases and signing key.</summary>
    public static UpdateSource Default { get; } = new(
        "https://github.com/hammadfahim/WinGuard",
        [
            // The public half of the release workflow's WINGUARD_UPDATE_SIGNING_KEY secret. To
            // change keys, add the new one here, ship a release signed with the old one, and
            // only then sign with the new one: installs learn a key from the program they run.
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcPq+HrfsAUiZYpNGmdqsghIbAGrgEKFo+966ziQpv5hCAiOHCARDtWnI3b+m+eaSs7EtpA/aYAJ/NWn8RTJFyA==",
        ]);

    /// <summary>Creates a source; the tests use their own.</summary>
    /// <param name="repositoryUrl">The repository's address, without a trailing slash.</param>
    /// <param name="publicKeys">Trusted signing keys, each a base64 SubjectPublicKeyInfo.</param>
    public UpdateSource(string repositoryUrl, IReadOnlyList<string> publicKeys)
    {
        RepositoryUrl = repositoryUrl.TrimEnd('/');
        PublicKeys = publicKeys;
    }

    /// <summary>The repository's address.</summary>
    public string RepositoryUrl { get; }

    /// <summary>Trusted signing keys.</summary>
    public IReadOnlyList<string> PublicKeys { get; }

    /// <summary>The newest release's manifest. GitHub redirects this to that release's asset.</summary>
    public string LatestManifestUrl => $"{RepositoryUrl}/releases/latest/download/latest.json";

    /// <summary>The signature that belongs to <see cref="LatestManifestUrl"/>.</summary>
    public string LatestSignatureUrl => LatestManifestUrl + ".sig";

    /// <summary>Where a release's installer is.</summary>
    public string InstallerUrl(UpdateManifest manifest) =>
        $"{RepositoryUrl}/releases/download/v{manifest.VersionText}/{manifest.File}";

    /// <summary>The page a person reads about a release.</summary>
    public string ReleasePageUrl(Version version) => $"{RepositoryUrl}/releases/tag/v{version.ToString(3)}";
}
