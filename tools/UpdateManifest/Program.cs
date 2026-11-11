using System.Security.Cryptography;
using System.Text;
using WinGuard.Core.Updates;

// Usage: UpdateManifest <installer.exe> <version> <output folder>
// The private key comes from the environment variable WINGUARD_UPDATE_SIGNING_KEY (PKCS#8 PEM), so
// it never appears on a command line. Writes latest.json and latest.json.sig, then checks them the
// way the console will: a release signed with a key the program does not know must not go out.
if (args.Length != 3)
{
    Console.Error.WriteLine("Usage: UpdateManifest <installer.exe> <version> <output folder>");
    return 2;
}

var installer = new FileInfo(args[0]);
var privateKey = Environment.GetEnvironmentVariable("WINGUARD_UPDATE_SIGNING_KEY");
if (!installer.Exists || string.IsNullOrWhiteSpace(privateKey) || !UpdateManifest.TryParseVersion(args[1], out var version))
{
    Console.Error.WriteLine("The installer, a MAJOR.MINOR.PATCH version and WINGUARD_UPDATE_SIGNING_KEY are all required.");
    return 2;
}

try
{
    if (installer.Name != UpdateManifest.InstallerName(version))
    {
        Console.Error.WriteLine($"The installer must be named {UpdateManifest.InstallerName(version)}, not {installer.Name}.");
        return 1;
    }

    string hash;
    await using (var stream = installer.OpenRead())
    {
        hash = Convert.ToHexStringLower(await SHA256.HashDataAsync(stream));
    }

    var json = UpdateManifest.Create(version, installer.Length, hash).ToJson();
    var signature = UpdateSignature.Sign(json, privateKey.Replace("\n", "\n"));
    if (!UpdateSignature.IsValid(json, signature, UpdateSource.Default.PublicKeys))
    {
        Console.Error.WriteLine("The signing key is not the one whose public half is in UpdateSource.cs. Installed copies would refuse this release.");
        return 1;
    }

    UpdateManifest.Parse(json);
    Directory.CreateDirectory(args[2]);
    await File.WriteAllBytesAsync(Path.Combine(args[2], "latest.json"), json);
    await File.WriteAllTextAsync(Path.Combine(args[2], "latest.json.sig"), signature, Encoding.ASCII);
    Console.WriteLine(Encoding.UTF8.GetString(json));
    return 0;
}
catch (Exception ex) when (ex is UpdateException or CryptographicException or ArgumentException)
{
    Console.Error.WriteLine(ex.Message);
    return 1;
}
