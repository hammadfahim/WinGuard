using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace WinGuard.Core.Config;

/// <summary>Encrypts secrets for storage. What it returns carries <see cref="Prefix"/>, so a stored value says what it is.</summary>
public interface ISecretProtector
{
    /// <summary>
    /// Whether this process runs as the account the secrets are meant for, LocalSystem. A
    /// <c>--console</c> run as an administrator can only encrypt for that administrator.
    /// </summary>
    bool RunsAsServiceAccount { get; }

    /// <summary>Encrypts a non-empty value; throws when it cannot.</summary>
    string Protect(string plaintext);

    /// <summary>Decrypts a value from <see cref="Protect"/>; false when this account or machine cannot.</summary>
    bool TryUnprotect(string stored, out string plaintext);
}

/// <summary>The marker of encrypted values, shared by the protector and whatever reads the settings.</summary>
public static class SecretValue
{
    /// <summary>Starts every encrypted value. Anything else is plaintext from an older version.</summary>
    public const string Prefix = "dpapi:";

    /// <summary>Whether a stored value is encrypted.</summary>
    public static bool IsProtected(string? stored) =>
        stored is not null && stored.StartsWith(Prefix, StringComparison.Ordinal);
}

/// <summary>
/// DPAPI through <c>crypt32.dll</c>, in user scope. Under LocalSystem that limits decryption to
/// SYSTEM; machine scope would let any local process decrypt. The entropy keeps a blob from being
/// mistaken for one that another program made with DPAPI for the same account. It is not a secret.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DpapiSecretProtector : ISecretProtector
{
    // CRYPTPROTECT_UI_FORBIDDEN: a service has no desktop to prompt on. CRYPTPROTECT_LOCAL_MACHINE
    // is deliberately not set.
    private const int UiForbidden = 0x1;

    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("WinGuard.Settings.Secrets.v1");

    /// <inheritdoc />
    public bool RunsAsServiceAccount
    {
        get
        {
            using var identity = WindowsIdentity.GetCurrent();
            return identity.IsSystem;
        }
    }

    /// <inheritdoc />
    public string Protect(string plaintext)
    {
        ArgumentException.ThrowIfNullOrEmpty(plaintext);

        var data = Encoding.UTF8.GetBytes(plaintext);
        try
        {
            var encrypted = Transform(data, protect: true)
                ?? throw new CryptographicException($"DPAPI could not encrypt the value: {new Win32Exception(Marshal.GetLastWin32Error()).Message}");
            return SecretValue.Prefix + Convert.ToBase64String(encrypted);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(data);
        }
    }

    /// <inheritdoc />
    public bool TryUnprotect(string stored, out string plaintext)
    {
        plaintext = string.Empty;
        if (!SecretValue.IsProtected(stored))
        {
            return false;
        }

        byte[] encrypted;
        try
        {
            encrypted = Convert.FromBase64String(stored[SecretValue.Prefix.Length..]);
        }
        catch (FormatException)
        {
            return false;
        }

        if (Transform(encrypted, protect: false) is not { } decrypted)
        {
            return false;
        }

        try
        {
            plaintext = Encoding.UTF8.GetString(decrypted);
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(decrypted);
        }
    }

    /// <summary>Runs one DPAPI call. Null when it fails; the Win32 error is still there to read.</summary>
    private static byte[]? Transform(byte[] input, bool protect)
    {
        var inputPin = GCHandle.Alloc(input, GCHandleType.Pinned);
        var entropyPin = GCHandle.Alloc(Entropy, GCHandleType.Pinned);
        try
        {
            var inputBlob = new DataBlob { Size = input.Length, Data = inputPin.AddrOfPinnedObject() };
            var entropyBlob = new DataBlob { Size = Entropy.Length, Data = entropyPin.AddrOfPinnedObject() };

            var succeeded = protect
                ? NativeMethods.CryptProtectData(ref inputBlob, null, ref entropyBlob, IntPtr.Zero, IntPtr.Zero, UiForbidden, out var output)
                : NativeMethods.CryptUnprotectData(ref inputBlob, IntPtr.Zero, ref entropyBlob, IntPtr.Zero, IntPtr.Zero, UiForbidden, out output);
            if (!succeeded)
            {
                return null;
            }

            try
            {
                var result = new byte[output.Size];
                Marshal.Copy(output.Data, result, 0, output.Size);
                return result;
            }
            finally
            {
                // The output of an unprotect is the secret itself.
                for (var offset = 0; offset < output.Size; offset++)
                {
                    Marshal.WriteByte(output.Data, offset, 0);
                }

                NativeMethods.LocalFree(output.Data);
            }
        }
        finally
        {
            inputPin.Free();
            entropyPin.Free();
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob
    {
        public int Size;
        public IntPtr Data;
    }

    private static class NativeMethods
    {
        [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptProtectData(
            ref DataBlob dataIn,
            string? description,
            ref DataBlob entropy,
            IntPtr reserved,
            IntPtr prompt,
            int flags,
            out DataBlob dataOut);

        [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptUnprotectData(
            ref DataBlob dataIn,
            IntPtr description,
            ref DataBlob entropy,
            IntPtr reserved,
            IntPtr prompt,
            int flags,
            out DataBlob dataOut);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr LocalFree(IntPtr memory);
    }
}

/// <summary>
/// Moves the settings' secrets between their stored form and the plaintext the running service and
/// the console need. Only the persistence path goes through here; IPC keeps seeing plaintext.
/// <para>
/// The care is in what must not happen. A value that cannot be decrypted (the database moved to
/// another machine, or <c>--console</c> reading what SYSTEM encrypted) reads as empty, and the
/// console then saves that empty field back with every unrelated change: the stored ciphertext is
/// kept through that, because it still works for the account that wrote it. Only a new value
/// replaces it.
/// </para>
/// </summary>
public sealed class SettingsSecrets
{
    private static readonly SecretField[] Fields =
    [
        new("webhook URL", settings => settings.Notifications.WebhookUrl, (settings, value) => settings.Notifications.WebhookUrl = value),
        new("Telegram bot token", settings => settings.Notifications.TelegramBotToken, (settings, value) => settings.Notifications.TelegramBotToken = value),
        new("SMTP password", settings => settings.Notifications.Smtp?.Password ?? string.Empty, (settings, value) => (settings.Notifications.Smtp ??= new()).Password = value),
    ];

    private readonly ISecretProtector _protector;

    // What the store holds per field. Replaced whole, and only once the store has taken it.
    private Dictionary<string, FieldState> _stored = new(StringComparer.Ordinal);

    /// <summary>Creates the converter.</summary>
    /// <param name="protector">The encryption to use.</param>
    public SettingsSecrets(ISecretProtector protector)
    {
        _protector = protector ?? throw new ArgumentNullException(nameof(protector));
    }

    /// <summary>The fields that could not be decrypted and read as empty.</summary>
    public IReadOnlyList<string> Undecryptable { get; private set; } = [];

    /// <summary>
    /// Turns settings as loaded from the store into plaintext, in place. Call on normalized
    /// settings. Returns whether old plaintext values are waiting to be encrypted.
    /// </summary>
    public bool Open(WinGuardSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        var stored = new Dictionary<string, FieldState>(StringComparer.Ordinal);
        var undecryptable = new List<string>();
        var hasPlaintext = false;
        foreach (var field in Fields)
        {
            var raw = field.Get(settings) ?? string.Empty;
            if (!SecretValue.IsProtected(raw))
            {
                hasPlaintext |= raw.Length > 0;
                stored[field.Name] = new FieldState(raw, raw);
            }
            else if (_protector.TryUnprotect(raw, out var plaintext))
            {
                field.Set(settings, plaintext);
                stored[field.Name] = new FieldState(raw, plaintext);
            }
            else
            {
                field.Set(settings, string.Empty);
                stored[field.Name] = new FieldState(raw, Plaintext: null);
                undecryptable.Add(field.Name);
            }
        }

        _stored = stored;
        Undecryptable = undecryptable;
        return hasPlaintext;
    }

    /// <summary>
    /// The form of the settings to store, as a copy: the live instance keeps its plaintext. Throws
    /// when a value cannot be encrypted, because writing it in the clear instead would quietly undo
    /// the protection. Nothing changes here until <see cref="SealedSettings.Commit"/>.
    /// </summary>
    public SealedSettings Seal(WinGuardSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        var sealedCopy = settings.Clone();
        var next = new Dictionary<string, FieldState>(StringComparer.Ordinal);
        var undecryptable = new List<string>();
        var tiedToThisAccount = new List<string>();
        foreach (var field in Fields)
        {
            var value = field.Get(settings) ?? string.Empty;
            var current = _stored.GetValueOrDefault(field.Name) ?? FieldState.Empty;
            var state = SealField(value, current);
            field.Set(sealedCopy, state.Raw);
            next[field.Name] = state;

            if (SecretValue.IsProtected(state.Raw) && state.Plaintext is null)
            {
                undecryptable.Add(field.Name);
            }

            if (!ReferenceEquals(state, current) && SecretValue.IsProtected(state.Raw) && !_protector.RunsAsServiceAccount)
            {
                tiedToThisAccount.Add(field.Name);
            }
        }

        return new SealedSettings(
            sealedCopy,
            () =>
            {
                _stored = next;
                Undecryptable = undecryptable;
            },
            tiedToThisAccount);
    }

    private FieldState SealField(string value, FieldState current)
    {
        // An empty field over a value nobody here can read is the console echoing what it was
        // shown, not a request to wipe it.
        if (current.Plaintext is null && string.IsNullOrWhiteSpace(value))
        {
            return current;
        }

        if (value.Length == 0)
        {
            return FieldState.Empty;
        }

        if (string.Equals(value, current.Plaintext, StringComparison.Ordinal))
        {
            // Unchanged. Encrypting old plaintext from a console run would tie it to that
            // administrator and lose it for the service, whose next start encrypts it instead.
            if (SecretValue.IsProtected(current.Raw) || !_protector.RunsAsServiceAccount)
            {
                return current;
            }
        }

        return new FieldState(_protector.Protect(value), value);
    }

    private sealed record SecretField(string Name, Func<WinGuardSettings, string?> Get, Action<WinGuardSettings, string> Set);

    /// <summary>One field: its stored form, and its plaintext, null when that cannot be had.</summary>
    private sealed record FieldState(string Raw, string? Plaintext)
    {
        public static readonly FieldState Empty = new(string.Empty, string.Empty);
    }
}

/// <summary>Settings ready to store, and what to do once the store has them.</summary>
/// <param name="Settings">The copy to serialize.</param>
/// <param name="Commit">Call after the store accepted the copy.</param>
/// <param name="TiedToThisAccount">
/// New secrets encrypted by a <c>--console</c> run. DPAPI cannot encrypt for another account, so this
/// administrator can read them and the Windows service cannot.
/// </param>
public sealed record SealedSettings(WinGuardSettings Settings, Action Commit, IReadOnlyList<string> TiedToThisAccount);
