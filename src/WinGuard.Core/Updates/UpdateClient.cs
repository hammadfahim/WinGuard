using System.Net;
using System.Security.Cryptography;

namespace WinGuard.Core.Updates;

/// <summary>
/// A downloaded installer that has been checked against its manifest. The file stays open, shared
/// for reading only, from before the check until this is disposed: nothing can swap or change it
/// between the check and the moment it is started.
/// </summary>
public sealed class UpdatePackage : IDisposable
{
    private readonly FileStream _lock;

    internal UpdatePackage(string path, FileStream fileLock, UpdateManifest manifest)
    {
        Path = path;
        _lock = fileLock;
        Manifest = manifest;
    }

    /// <summary>Full path of the installer.</summary>
    public string Path { get; }

    /// <summary>The release it belongs to.</summary>
    public UpdateManifest Manifest { get; }

    /// <summary>Lets go of the file. Call it once the installer has been started.</summary>
    public void Dispose() => _lock.Dispose();
}

/// <summary>
/// Asks the project's GitHub releases whether there is a newer version, and fetches its installer.
/// Three things have to hold before a file is handed back: the manifest carries a signature from a
/// key compiled into this program, its version is higher than the one running (an older release,
/// however genuine, is never offered), and the file has the size and SHA-256 the manifest gives.
/// </summary>
public sealed class UpdateClient
{
    private static readonly TimeSpan CheckTimeout = TimeSpan.FromSeconds(30);

    private readonly HttpClient _http;
    private readonly UpdateSource _source;

    /// <summary>Creates the client.</summary>
    /// <param name="http">From <see cref="CreateHttpClient"/>, or a test's own.</param>
    /// <param name="source">Where to ask; the project's releases when null.</param>
    public UpdateClient(HttpClient http, UpdateSource? source = null)
    {
        _http = http;
        _source = source ?? UpdateSource.Default;
    }

    /// <summary>The source this client asks.</summary>
    public UpdateSource Source => _source;

    /// <summary>An HTTP client set up for GitHub's release downloads.</summary>
    /// <param name="productVersion">This program's version, for the User-Agent.</param>
    public static HttpClient CreateHttpClient(string productVersion)
    {
        // GitHub answers a release download with a redirect to its file store. The handler never
        // follows one from https to http.
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = 5,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromSeconds(15),
        };
        var client = new HttpClient(handler, disposeHandler: true) { Timeout = Timeout.InfiniteTimeSpan };
        client.DefaultRequestHeaders.UserAgent.ParseAdd($"WinGuard/{productVersion}");
        return client;
    }

    /// <summary>The newer release, or null when the running version is the newest.</summary>
    /// <param name="current">The version that is running.</param>
    /// <param name="ct">Cancels the check.</param>
    /// <exception cref="UpdateException">The answer could not be fetched or is not trusted.</exception>
    public async Task<UpdateManifest?> CheckAsync(Version current, CancellationToken ct = default)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(CheckTimeout);
        try
        {
            var manifestBytes = await GetSmallAsync(_source.LatestManifestUrl, timeout.Token).ConfigureAwait(false);
            var signatureBytes = await GetSmallAsync(_source.LatestSignatureUrl, timeout.Token).ConfigureAwait(false);
            if (manifestBytes is null || signatureBytes is null)
            {
                throw new UpdateException("The newest release on GitHub has no update information, so it cannot be installed from here.");
            }

            if (!UpdateSignature.IsValid(manifestBytes, System.Text.Encoding.ASCII.GetString(signatureBytes), _source.PublicKeys))
            {
                throw new UpdateException("The update information is not signed by the WinGuard project. Nothing was downloaded.");
            }

            var manifest = UpdateManifest.Parse(manifestBytes);
            return manifest.Version > Normalize(current) ? manifest : null;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new UpdateException("GitHub did not answer in time.");
        }
        catch (HttpRequestException ex)
        {
            throw new UpdateException($"GitHub could not be reached: {ex.Message}", ex);
        }
    }

    /// <summary>Downloads a release's installer and checks it against the manifest.</summary>
    /// <param name="manifest">From <see cref="CheckAsync"/>.</param>
    /// <param name="folder">An existing folder only administrators can write to (<see cref="UpdateFolder"/>).</param>
    /// <param name="progress">Receives the share downloaded, 0 to 1.</param>
    /// <param name="ct">Cancels the download.</param>
    /// <exception cref="UpdateException">The download failed or the file is not the one the manifest describes.</exception>
    public async Task<UpdatePackage> DownloadAsync(UpdateManifest manifest, string folder, IProgress<double>? progress = null, CancellationToken ct = default)
    {
        var path = Path.Combine(folder, manifest.File);
        try
        {
            File.Delete(path);
            await FetchAsync(manifest, path, progress, ct).ConfigureAwait(false);

            // Opened for good before it is checked: what is checked is what will be run.
            var fileLock = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            try
            {
                var hash = Convert.ToHexStringLower(await SHA256.HashDataAsync(fileLock, ct).ConfigureAwait(false));
                if (fileLock.Length != manifest.Size || !string.Equals(hash, manifest.Sha256, StringComparison.Ordinal))
                {
                    throw new UpdateException("The downloaded installer does not match the signed checksum. It was deleted and nothing was installed.");
                }

                return new UpdatePackage(path, fileLock, manifest);
            }
            catch
            {
                fileLock.Dispose();
                throw;
            }
        }
        catch (Exception ex)
        {
            TryDelete(path);
            throw ex switch
            {
                UpdateException or OperationCanceledException => ex,
                HttpRequestException => new UpdateException($"The download failed: {ex.Message}", ex),
                IOException or UnauthorizedAccessException => new UpdateException($"The installer could not be saved: {ex.Message}", ex),
                _ => ex,
            };
        }
    }

    private async Task FetchAsync(UpdateManifest manifest, string path, IProgress<double>? progress, CancellationToken ct)
    {
        using var response = await _http.GetAsync(_source.InstallerUrl(manifest), HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        RequireHttps(response);
        if (!response.IsSuccessStatusCode)
        {
            throw new UpdateException($"GitHub answered {(int)response.StatusCode} for the installer of version {manifest.VersionText}.");
        }

        await using var source = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        await using var target = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        var buffer = new byte[81920];
        long total = 0;
        int read;
        while ((read = await source.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
        {
            total += read;
            if (total > manifest.Size)
            {
                throw new UpdateException("The download is larger than the signed size. It was deleted and nothing was installed.");
            }

            await target.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
            progress?.Report((double)total / manifest.Size);
        }
    }

    /// <summary>Fetches a small text asset; null when the release does not have it.</summary>
    private async Task<byte[]?> GetSmallAsync(string url, CancellationToken ct)
    {
        using var response = await _http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        RequireHttps(response);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }

        if (!response.IsSuccessStatusCode)
        {
            throw new UpdateException($"GitHub answered {(int)response.StatusCode} when asked for the newest release.");
        }

        await using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        var buffer = new byte[UpdateManifest.MaxManifestBytes + 1];
        var length = 0;
        int read;
        while (length < buffer.Length && (read = await stream.ReadAsync(buffer.AsMemory(length), ct).ConfigureAwait(false)) > 0)
        {
            length += read;
        }

        if (length > UpdateManifest.MaxManifestBytes)
        {
            throw new UpdateException("The update information is too large to be genuine.");
        }

        return buffer[..length];
    }

    private static void RequireHttps(HttpResponseMessage response)
    {
        if (response.RequestMessage?.RequestUri is { } uri && uri.Scheme != Uri.UriSchemeHttps)
        {
            throw new UpdateException("The download was redirected to an address that is not HTTPS. Nothing was downloaded.");
        }
    }

    private static Version Normalize(Version version) =>
        new(version.Major, version.Minor, Math.Max(version.Build, 0));

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Left for the next start to clear.
        }
    }
}
