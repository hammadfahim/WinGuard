using System.Security.Cryptography;

namespace WinGuard.Core.Updates;

/// <summary>
/// The signature on <c>latest.json</c>: ECDSA over P-256 with SHA-256, the 64 raw bytes (r then s)
/// in base64, published as <c>latest.json.sig</c>. The private key exists only as a secret of the
/// release workflow; the public half is compiled into this program (<see cref="UpdateSource"/>).
/// So a release page, a download server or a network path that has been tampered with can offer
/// any file it likes: without that key it cannot make this program run it.
/// </summary>
public static class UpdateSignature
{
    private const int SignatureBytes = 64;

    /// <summary>Whether one of the trusted keys signed exactly these bytes.</summary>
    /// <param name="manifest">The bytes of <c>latest.json</c> as downloaded.</param>
    /// <param name="signatureText">The content of <c>latest.json.sig</c>.</param>
    /// <param name="publicKeys">Trusted keys, each a base64 SubjectPublicKeyInfo.</param>
    public static bool IsValid(ReadOnlySpan<byte> manifest, string? signatureText, IEnumerable<string> publicKeys)
    {
        if (string.IsNullOrWhiteSpace(signatureText) || signatureText.Length > 256)
        {
            return false;
        }

        var signature = new byte[SignatureBytes];
        if (!Convert.TryFromBase64String(signatureText.Trim(), signature, out var written) || written != SignatureBytes)
        {
            return false;
        }

        foreach (var publicKey in publicKeys)
        {
            try
            {
                using var key = ECDsa.Create();
                key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKey), out _);
                if (key.VerifyData(manifest, signature, HashAlgorithmName.SHA256))
                {
                    return true;
                }
            }
            catch (Exception ex) when (ex is CryptographicException or FormatException)
            {
                // A key that cannot be read vouches for nothing; the next one is tried.
            }
        }

        return false;
    }

    /// <summary>Signs a manifest; only the release workflow's tool calls this.</summary>
    /// <param name="manifest">The bytes of <c>latest.json</c>.</param>
    /// <param name="privateKeyPem">The PKCS#8 private key in PEM.</param>
    public static string Sign(ReadOnlySpan<byte> manifest, string privateKeyPem)
    {
        using var key = ECDsa.Create();
        key.ImportFromPem(privateKeyPem);
        return Convert.ToBase64String(key.SignData(manifest, HashAlgorithmName.SHA256));
    }
}
