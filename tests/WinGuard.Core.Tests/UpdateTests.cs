using System.Net;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using WinGuard.Core.Detection;
using WinGuard.Core.Updates;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>The in-app update: what is believed, what is offered, and what is handed to Setup.</summary>
public sealed class UpdateTests : IDisposable
{
    private const string Repository = "https://github.com/example/WinGuard";

    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly string _folder = Path.Combine(Path.GetTempPath(), "winguard-update-tests-" + Guid.NewGuid().ToString("N"));
    private readonly byte[] _installer = RandomNumberGenerator.GetBytes(4096);

    public UpdateTests() => Directory.CreateDirectory(_folder);

    public void Dispose()
    {
        _key.Dispose();
        try
        {
            Directory.Delete(_folder, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    private UpdateSource Source => new(Repository, [Convert.ToBase64String(_key.ExportSubjectPublicKeyInfo())]);

    private UpdateManifest ManifestFor(string version) =>
        UpdateManifest.Create(Version.Parse(version), _installer.Length, Convert.ToHexStringLower(SHA256.HashData(_installer)));

    private string Sign(byte[] json) => UpdateSignature.Sign(json, _key.ExportPkcs8PrivateKeyPem());

    /// <summary>A client whose "GitHub" serves the given release as the latest one.</summary>
    private UpdateClient ClientFor(UpdateManifest manifest, string? signature = null, byte[]? installer = null)
    {
        var json = manifest.ToJson();
        var handler = new FakeGitHub(new Dictionary<string, byte[]>
        {
            [$"{Repository}/releases/latest/download/latest.json"] = json,
            [$"{Repository}/releases/latest/download/latest.json.sig"] = Encoding.ASCII.GetBytes(signature ?? Sign(json)),
            [$"{Repository}/releases/download/v{manifest.VersionText}/{manifest.File}"] = installer ?? _installer,
        });
        return new UpdateClient(new HttpClient(handler), Source);
    }

    [Theory]
    [InlineData("0.3.3", true)]
    [InlineData("10.20.30", true)]
    [InlineData("0.3", false)]
    [InlineData("0.3.3.1", false)]
    [InlineData("v0.3.3", false)]
    [InlineData("0.3.3 ", false)]
    [InlineData("0.3.-1", false)]
    [InlineData("0.3.3/../x", false)]
    [InlineData("", false)]
    public void A_version_is_three_numbers_and_nothing_else(string text, bool expected) =>
        Assert.Equal(expected, UpdateManifest.TryParseVersion(text, out _));

    [Fact]
    public void A_manifest_survives_being_written_and_read()
    {
        var manifest = ManifestFor("1.2.3");
        Assert.Equal(manifest, UpdateManifest.Parse(manifest.ToJson()));
        Assert.Equal("WinGuard-Setup-1.2.3.exe", manifest.File);
    }

    [Theory]
    [InlineData("""{"version":"1.2.3","file":"evil.exe","size":10,"sha256":"HASH"}""")]
    [InlineData("""{"version":"1.2.3","file":"..\\WinGuard-Setup-1.2.3.exe","size":10,"sha256":"HASH"}""")]
    [InlineData("""{"version":"1.2.3","file":"WinGuard-Setup-1.2.4.exe","size":10,"sha256":"HASH"}""")]
    [InlineData("""{"version":"1.2.3","file":"WinGuard-Setup-1.2.3.exe","size":0,"sha256":"HASH"}""")]
    [InlineData("""{"version":"1.2.3","file":"WinGuard-Setup-1.2.3.exe","size":99999999999,"sha256":"HASH"}""")]
    [InlineData("""{"version":"1.2.3","file":"WinGuard-Setup-1.2.3.exe","size":10,"sha256":"abc"}""")]
    [InlineData("""{"version":"1.2","file":"WinGuard-Setup-1.2.exe","size":10,"sha256":"HASH"}""")]
    [InlineData("""{"version":"1.2.3","size":10,"sha256":"HASH"}""")]
    [InlineData("""["1.2.3"]""")]
    [InlineData("not json")]
    public void A_manifest_of_any_other_form_is_refused(string json)
    {
        var text = json.Replace("HASH", new string('a', 64));
        Assert.Throws<UpdateException>(() => UpdateManifest.Parse(Encoding.UTF8.GetBytes(text)));
    }

    [Fact]
    public void An_upper_case_checksum_is_refused()
    {
        var json = $$"""{"version":"1.2.3","file":"WinGuard-Setup-1.2.3.exe","size":10,"sha256":"{{new string('A', 64)}}"}""";
        Assert.Throws<UpdateException>(() => UpdateManifest.Parse(Encoding.UTF8.GetBytes(json)));
    }

    [Fact]
    public void Only_the_signed_bytes_and_only_a_trusted_key_pass()
    {
        var json = ManifestFor("1.2.3").ToJson();
        var signature = Sign(json);
        Assert.True(UpdateSignature.IsValid(json, signature, Source.PublicKeys));
        Assert.True(UpdateSignature.IsValid(json, signature + "\r\n", Source.PublicKeys));

        var changed = (byte[])json.Clone();
        changed[10] ^= 1;
        Assert.False(UpdateSignature.IsValid(changed, signature, Source.PublicKeys));

        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string[] otherKey = [Convert.ToBase64String(other.ExportSubjectPublicKeyInfo())];
        Assert.False(UpdateSignature.IsValid(json, signature, otherKey));
        Assert.True(UpdateSignature.IsValid(json, signature, [.. otherKey, .. Source.PublicKeys]));

        Assert.False(UpdateSignature.IsValid(json, signature, []));
        Assert.False(UpdateSignature.IsValid(json, signature, ["not a key"]));
        Assert.False(UpdateSignature.IsValid(json, null, Source.PublicKeys));
        Assert.False(UpdateSignature.IsValid(json, "", Source.PublicKeys));
        Assert.False(UpdateSignature.IsValid(json, "AAAA", Source.PublicKeys));
        Assert.False(UpdateSignature.IsValid(json, "not base64 !!", Source.PublicKeys));
    }

    [Fact]
    public void The_compiled_in_key_is_a_p256_key_and_the_addresses_are_the_projects()
    {
        var source = UpdateSource.Default;
        Assert.NotEmpty(source.PublicKeys);
        foreach (var publicKey in source.PublicKeys)
        {
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKey), out _);
            Assert.Equal(256, key.KeySize);
        }

        Assert.Equal("https://github.com/hammadfahim/WinGuard/releases/latest/download/latest.json", source.LatestManifestUrl);
        Assert.Equal("https://github.com/hammadfahim/WinGuard/releases/latest/download/latest.json.sig", source.LatestSignatureUrl);
        Assert.Equal(
            "https://github.com/hammadfahim/WinGuard/releases/download/v1.2.3/WinGuard-Setup-1.2.3.exe",
            source.InstallerUrl(ManifestFor("1.2.3")));
    }

    [Fact]
    public async Task A_newer_release_is_offered()
    {
        var found = await ClientFor(ManifestFor("1.2.4")).CheckAsync(new Version(1, 2, 3, 0));
        Assert.Equal("1.2.4", found?.VersionText);
    }

    [Theory]
    [InlineData("1.2.3")]
    [InlineData("1.2.2")]
    [InlineData("0.9.9")]
    public async Task The_same_or_an_older_release_is_never_offered(string published) =>
        Assert.Null(await ClientFor(ManifestFor(published)).CheckAsync(new Version(1, 2, 3)));

    [Fact]
    public async Task A_manifest_without_a_good_signature_is_refused()
    {
        var manifest = ManifestFor("9.9.9");
        using var stranger = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var forged = UpdateSignature.Sign(manifest.ToJson(), stranger.ExportPkcs8PrivateKeyPem());

        await Assert.ThrowsAsync<UpdateException>(() => ClientFor(manifest, forged).CheckAsync(new Version(1, 0, 0)));
        await Assert.ThrowsAsync<UpdateException>(() => ClientFor(manifest, "garbage").CheckAsync(new Version(1, 0, 0)));

        // A genuine signature of another release does not carry over.
        var older = Sign(ManifestFor("9.9.8").ToJson());
        await Assert.ThrowsAsync<UpdateException>(() => ClientFor(manifest, older).CheckAsync(new Version(1, 0, 0)));
    }

    [Fact]
    public async Task A_release_without_update_information_is_reported()
    {
        var client = new UpdateClient(new HttpClient(new FakeGitHub([])), Source);
        var error = await Assert.ThrowsAsync<UpdateException>(() => client.CheckAsync(new Version(1, 0, 0)));
        Assert.Contains("no update information", error.Message);
    }

    [Fact]
    public async Task A_server_error_and_an_unreachable_server_are_reported()
    {
        var failing = new UpdateClient(new HttpClient(new FakeGitHub([]) { Status = HttpStatusCode.InternalServerError }), Source);
        await Assert.ThrowsAsync<UpdateException>(() => failing.CheckAsync(new Version(1, 0, 0)));

        var unreachable = new UpdateClient(new HttpClient(new FakeGitHub([]) { Throw = true }), Source);
        await Assert.ThrowsAsync<UpdateException>(() => unreachable.CheckAsync(new Version(1, 0, 0)));
    }

    [Fact]
    public async Task An_oversized_manifest_is_refused()
    {
        var handler = new FakeGitHub(new Dictionary<string, byte[]>
        {
            [$"{Repository}/releases/latest/download/latest.json"] = new byte[UpdateManifest.MaxManifestBytes + 1],
            [$"{Repository}/releases/latest/download/latest.json.sig"] = [1],
        });
        await Assert.ThrowsAsync<UpdateException>(() => new UpdateClient(new HttpClient(handler), Source).CheckAsync(new Version(1, 0, 0)));
    }

    [Fact]
    public async Task A_matching_installer_is_handed_over_and_held()
    {
        var manifest = ManifestFor("1.2.4");
        var shares = new List<double>();
        using (var package = await ClientFor(manifest).DownloadAsync(manifest, _folder, new SynchronousProgress(shares)))
        {
            Assert.Equal(Path.Combine(_folder, "WinGuard-Setup-1.2.4.exe"), package.Path);
            Assert.Equal(_installer, await ReadSharedAsync(package.Path));
            Assert.Equal(1.0, shares[^1]);

            // Held: it cannot be rewritten or removed while Setup is being started.
            Assert.Throws<IOException>(() => File.WriteAllBytes(package.Path, [1, 2, 3]));
            Assert.Throws<IOException>(() => File.Delete(package.Path));
        }

        File.Delete(Path.Combine(_folder, "WinGuard-Setup-1.2.4.exe"));
    }

    [Fact]
    public async Task An_installer_with_another_content_is_deleted_and_refused()
    {
        var manifest = ManifestFor("1.2.4");
        var other = (byte[])_installer.Clone();
        other[100] ^= 1;

        var error = await Assert.ThrowsAsync<UpdateException>(() => ClientFor(manifest, installer: other).DownloadAsync(manifest, _folder));
        Assert.Contains("checksum", error.Message);
        Assert.Empty(Directory.GetFiles(_folder));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(-1)]
    public async Task An_installer_of_another_size_is_deleted_and_refused(int difference)
    {
        var manifest = ManifestFor("1.2.4");
        var other = new byte[_installer.Length + difference];

        await Assert.ThrowsAsync<UpdateException>(() => ClientFor(manifest, installer: other).DownloadAsync(manifest, _folder));
        Assert.Empty(Directory.GetFiles(_folder));
    }

    [Fact]
    public async Task A_missing_installer_is_reported_and_a_leftover_is_replaced()
    {
        var manifest = ManifestFor("1.2.4");
        File.WriteAllText(Path.Combine(_folder, manifest.File), "left over from an earlier try");

        var client = new UpdateClient(new HttpClient(new FakeGitHub([])), Source);
        await Assert.ThrowsAsync<UpdateException>(() => client.DownloadAsync(manifest, _folder));
        Assert.Empty(Directory.GetFiles(_folder));

        File.WriteAllText(Path.Combine(_folder, manifest.File), "left over from an earlier try");
        using var package = await ClientFor(manifest).DownloadAsync(manifest, _folder);
        Assert.Equal(_installer, await ReadSharedAsync(package.Path));
    }

    [Fact]
    public void The_download_folder_is_created_closed_and_emptied()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var me = identity.User!;
        var folder = Path.Combine(_folder, "Updates");

        // Not elevated here, so the owner stays the test's own account and counts as trusted.
        Assert.Equal(folder, UpdateFolder.Prepare(folder, owner => me.Equals(owner) || IsAdministrators(owner), newOwner: null, [me]));
        var security = new DirectoryInfo(folder).GetAccessControl();
        Assert.True(security.AreAccessRulesProtected);

        Directory.CreateDirectory(Path.Combine(folder, "old", "deeper"));
        File.WriteAllText(Path.Combine(folder, "old", "deeper", "x.txt"), "x");
        File.WriteAllText(Path.Combine(folder, "WinGuard-Setup-0.0.1.exe"), "old installer");
        UpdateFolder.Prepare(folder, owner => me.Equals(owner) || IsAdministrators(owner), newOwner: null, [me]);
        Assert.Empty(Directory.GetFileSystemEntries(folder));
    }

    [Fact]
    public void A_download_folder_somebody_else_made_is_refused_and_left_alone()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var me = identity.User!;
        var folder = Path.Combine(_folder, "Planted");
        Directory.CreateDirectory(folder);
        File.WriteAllText(Path.Combine(folder, "WinGuard-Setup-9.9.9.exe"), "planted");

        var error = Assert.Throws<UpdateException>(() => UpdateFolder.Prepare(folder, _ => false, newOwner: null, [me]));
        Assert.Contains("not by WinGuard", error.Message);
        Assert.Single(Directory.GetFiles(folder));
    }

    [Fact]
    public void A_user_name_from_a_custom_log_is_cut_to_a_sane_length()
    {
        var line = $"Failed password for {new string('a', 5000)} from 203.0.113.9 port 22";
        Assert.True(CustomLogDetector.TryParseLine(line, @"Failed password for (?<username>\S+) from (?<ipaddress>[0-9.]+)", out var failed));
        Assert.Equal(CustomLogDetector.MaxUserNameLength, failed!.UserName!.Length);
    }

    private static bool IsAdministrators(SecurityIdentifier? owner) =>
        owner is not null && owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid);

    private static async Task<byte[]> ReadSharedAsync(string path)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var content = new byte[stream.Length];
        await stream.ReadExactlyAsync(content);
        return content;
    }

    private sealed class SynchronousProgress(List<double> shares) : IProgress<double>
    {
        public void Report(double value) => shares.Add(value);
    }

    /// <summary>Serves a fixed set of addresses; everything else is 404, as on GitHub.</summary>
    private sealed class FakeGitHub(Dictionary<string, byte[]> files) : HttpMessageHandler
    {
        public HttpStatusCode? Status { get; init; }

        public bool Throw { get; init; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (Throw)
            {
                throw new HttpRequestException("No such host is known.");
            }

            var response = Status is { } status
                ? new HttpResponseMessage(status)
                : files.TryGetValue(request.RequestUri!.ToString(), out var content)
                    ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(content) }
                    : new HttpResponseMessage(HttpStatusCode.NotFound);
            response.RequestMessage = request;
            return Task.FromResult(response);
        }
    }
}
