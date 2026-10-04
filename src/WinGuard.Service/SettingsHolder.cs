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
/// </summary>
public sealed class SettingsHolder
{
    /// <summary>Settings row key holding the serialized settings blob (matches the store contract).</summary>
    public const string SettingsKey = "engine";

    private readonly IStore _store;
    private readonly ILogger<SettingsHolder> _logger;
    private WinGuardSettings _current = new();

    /// <summary>Creates the holder. Call <see cref="LoadAsync"/> before the host starts.</summary>
    /// <param name="store">Persistence used to read/persist the settings blob.</param>
    /// <param name="logger">Diagnostic logger.</param>
    public SettingsHolder(IStore store, ILogger<SettingsHolder> logger)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>Snapshot of the current settings (never null; swapped atomically).</summary>
    public WinGuardSettings Current => Volatile.Read(ref _current);

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
        Volatile.Write(ref _current, loaded);
    }

    /// <summary>Normalizes and persists the supplied settings, then atomically swaps them in.</summary>
    /// <param name="settings">New settings (mutated only by <see cref="WinGuardSettings.Normalize"/>).</param>
    /// <param name="ct">Cancellation token.</param>
    public async Task ApplyAsync(WinGuardSettings settings, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(settings);
        settings.Normalize();

        var json = JsonSerializer.Serialize(settings, IpcJson.Options);
        await _store.SetSettingAsync(SettingsKey, json, ct).ConfigureAwait(false);
        Volatile.Write(ref _current, settings);
        _logger.LogInformation("Applied and persisted new engine settings.");
    }
}