using System.Text.Json;
using Microsoft.Extensions.Logging;
using WinGuard.Core.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Ipc;

namespace WinGuard.Service;

/// <summary>
/// Holds the single live <see cref="WinGuardSettings"/> instance behind an immutable-reference
/// swap (PLAN.md §8 "engine hot-reloads"). Loaded from the store's <c>engine</c> settings row at
/// startup; <see cref="ApplyAsync"/> normalizes, persists and atomically replaces the instance.
/// Every component that needs current settings receives <see cref="Current"/> through a
/// <c>Func&lt;WinGuardSettings&gt;</c> accessor, so they always observe the latest swap.
/// <para>
/// The notification secrets are encrypted here, on the way to and from the store, and nowhere
/// else: <see cref="Current"/> holds plaintext, because the channels and the console need it.
/// </para>
/// </summary>
public sealed class SettingsHolder
{
    /// <summary>Settings row key holding the serialized settings blob (matches the store contract).</summary>
    public const string SettingsKey = "engine";

    private readonly IStore _store;
    private readonly ILogger<SettingsHolder> _logger;
    private readonly ISecretProtector _protector;
    private readonly SettingsSecrets _secrets;

    // Two console saves at once must not race over which ciphertext is kept.
    private readonly SemaphoreSlim _saveGate = new(1, 1);
    private WinGuardSettings _current = new();

    /// <summary>Creates the holder. Call <see cref="LoadAsync"/> before the host starts.</summary>
    /// <param name="store">Persistence used to read/persist the settings blob.</param>
    /// <param name="logger">Diagnostic logger.</param>
    /// <param name="protector">Encrypts the stored secrets; DPAPI when null.</param>
    public SettingsHolder(IStore store, ILogger<SettingsHolder> logger, ISecretProtector? protector = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _protector = protector ?? new DpapiSecretProtector();
        _secrets = new SettingsSecrets(_protector);
    }

    /// <summary>Snapshot of the current settings (never null; swapped atomically).</summary>
    public WinGuardSettings Current => Volatile.Read(ref _current);

    /// <summary>The secrets stored but unreadable by this account or machine; they act as empty until re-entered.</summary>
    public IReadOnlyList<string> UndecryptableSecrets => _secrets.Undecryptable;

    /// <summary>
    /// Loads settings from the store (<c>engine</c> key) or falls back to defaults. Corrupt or
    /// missing JSON degrades to defaults rather than failing service startup.
    /// </summary>
    /// <param name="ct">Cancellation token.</param>
    public async Task LoadAsync(CancellationToken ct = default)
    {
        WinGuardSettings loaded;
        try
        {
            var all = await _store.GetAllSettingsAsync(ct).ConfigureAwait(false);
            if (all.TryGetValue(SettingsKey, out var json) && !string.IsNullOrWhiteSpace(json))
            {
                loaded = JsonSerializer.Deserialize<WinGuardSettings>(json, IpcJson.Options) ?? new WinGuardSettings();
                _logger.LogInformation("Loaded persisted engine settings from the store.");
            }
            else
            {
                loaded = new WinGuardSettings();
                _logger.LogInformation("No persisted engine settings found; using defaults.");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load engine settings; using defaults.");
            loaded = new WinGuardSettings();
        }

        loaded.Normalize();
        var hasPlaintext = _secrets.Open(loaded);
        if (_secrets.Undecryptable.Count > 0)
        {
            _logger.LogWarning(
                "Could not decrypt the stored {Secrets}: the database may come from another machine, or this runs under another account than the service. The channel stays off here and the stored value is kept; enter it again to replace it.",
                string.Join(", ", _secrets.Undecryptable));
        }

        Volatile.Write(ref _current, loaded);

        // Only the service encrypts what is already stored: from a console run it would be tied to
        // that administrator, out of the service's reach.
        if (hasPlaintext && _protector.RunsAsServiceAccount)
        {
            await EncryptStoredPlaintextAsync(loaded, ct).ConfigureAwait(false);
        }
    }

    /// <summary>Normalizes and persists the supplied settings, then atomically swaps them in.</summary>
    /// <param name="settings">New settings (mutated only by <see cref="WinGuardSettings.Normalize"/>).</param>
    /// <param name="ct">Cancellation token.</param>
    public async Task ApplyAsync(WinGuardSettings settings, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(settings);
        settings.Normalize();

        await _saveGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await PersistAsync(settings, ct).ConfigureAwait(false);
            Volatile.Write(ref _current, settings);
        }
        finally
        {
            _saveGate.Release();
        }

        _logger.LogInformation("Applied and persisted new engine settings.");
    }

    private async Task PersistAsync(WinGuardSettings settings, CancellationToken ct, bool scrub = false)
    {
        var sealedSettings = _secrets.Seal(settings);
        var json = JsonSerializer.Serialize(sealedSettings.Settings, IpcJson.Options);
        if (scrub && _store is ISecretScrubbingStore scrubbing)
        {
            await scrubbing.SetSettingAndScrubAsync(SettingsKey, json, ct).ConfigureAwait(false);
        }
        else
        {
            await _store.SetSettingAsync(SettingsKey, json, ct).ConfigureAwait(false);
        }

        sealedSettings.Commit();
        if (sealedSettings.TiedToThisAccount.Count > 0)
        {
            _logger.LogWarning(
                "The new {Secrets} can only be read by this account: the Windows service will not be able to decrypt it. If the service will run with this database, enter it again through the console connected to the service.",
                string.Join(", ", sealedSettings.TiedToThisAccount));
        }
    }

    /// <summary>
    /// Best effort: the plaintext keeps working, and the next start or save tries again. The old
    /// value has to leave the database files as well, or the encryption protects nothing there.
    /// </summary>
    private async Task EncryptStoredPlaintextAsync(WinGuardSettings settings, CancellationToken ct)
    {
        try
        {
            await PersistAsync(settings, ct, scrub: true).ConfigureAwait(false);
            _logger.LogInformation("Encrypted the notification secrets stored in plain text.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _logger.LogWarning(ex, "Could not encrypt the notification secrets stored in plain text; they stay as they are for now.");
        }
    }
}
