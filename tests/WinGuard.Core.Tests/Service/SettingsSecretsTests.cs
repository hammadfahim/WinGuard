using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Engine;
using WinGuard.Core.Ipc;
using WinGuard.Core.Model;
using WinGuard.Core.Store;
using WinGuard.Core.Tests.Fakes;
using WinGuard.Service;
using WinGuard.Service.Ipc;
using Xunit;

namespace WinGuard.Core.Tests;

/// <summary>
/// The notification secrets at rest: what the store holds, what stays plaintext in memory, and
/// above all what happens to a stored value that cannot be decrypted.
/// </summary>
public sealed class SettingsSecretsTests
{
    private const string Webhook = "https://hooks.example.invalid/services/s3cr3t";
    private const string Telegram = "123456:s3cr3ttoken";
    private const string SmtpPassword = "s3cr3t-password";

    private static WinGuardSettings WithSecrets() => new()
    {
        Notifications = new NotificationSettings
        {
            WebhookUrl = Webhook,
            TelegramBotToken = Telegram,
            Smtp = new SmtpSettings { Host = "mail.example.invalid", Password = SmtpPassword },
        },
    };

    private static string StoredJson(FakeStore store) =>
        store.GetAllSettingsAsync().GetAwaiter().GetResult()[SettingsHolder.SettingsKey];

    private static NotificationSettings Stored(FakeStore store) =>
        JsonSerializer.Deserialize<WinGuardSettings>(StoredJson(store), IpcJson.Options)!.Notifications;

    private static async Task SeedAsync(FakeStore store, WinGuardSettings settings) =>
        await store.SetSettingAsync(SettingsHolder.SettingsKey, JsonSerializer.Serialize(settings, IpcJson.Options));

    // ---------- the plaintext leaves the database files ----------

    private const string Marker = "SECRETMARKER-7f3a9c";

    private static bool FileHolds(string path, string marker)
    {
        if (!File.Exists(path))
        {
            return false;
        }

        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var memory = new MemoryStream();
        stream.CopyTo(memory);
        return Encoding.Latin1.GetString(memory.ToArray()).Contains(marker, StringComparison.Ordinal);
    }

    private static async Task WithDatabaseAsync(Func<string, Task> test)
    {
        var folder = Path.Combine(Path.GetTempPath(), "wg-scrub-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            await test(Path.Combine(folder, "winguard.db"));
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }

    private static async Task SaveWebhookAsync(string path, params string[] webhooks)
    {
        var store = new SqliteStore(path, NullLogger<SqliteStore>.Instance, TimeProvider.System);
        await store.InitializeAsync();
        foreach (var webhook in webhooks)
        {
            var settings = new WinGuardSettings();
            settings.Notifications.WebhookUrl = webhook;
            await store.SetSettingAsync(SettingsHolder.SettingsKey, JsonSerializer.Serialize(settings, IpcJson.Options));
        }

        // An upgrade: the old version stopped cleanly, so the plaintext is in the main file.
        await store.DisposeAsync();
    }

    private static async Task AssertScrubbedWhileOpenAndAfterCloseAsync(string path)
    {
        var store = new SqliteStore(path, NullLogger<SqliteStore>.Instance, TimeProvider.System);
        await store.InitializeAsync();

        var holder = new SettingsHolder(store, NullLogger<SettingsHolder>.Instance, new FakeProtector());
        await holder.LoadAsync();

        var all = await store.GetAllSettingsAsync();
        Assert.DoesNotContain(Marker, all[SettingsHolder.SettingsKey]);
        Assert.False(FileHolds(path, Marker), "main file, while open");
        Assert.False(FileHolds(path + "-wal", Marker), "wal, while open");

        await store.DisposeAsync();
        Assert.False(FileHolds(path, Marker), "main file, after close");
        Assert.False(FileHolds(path + "-wal", Marker), "wal, after close");
    }

    [Fact]
    public async Task Encrypting_old_plaintext_leaves_none_of_it_in_the_database_files() =>
        await WithDatabaseAsync(async path =>
        {
            await SaveWebhookAsync(path, "https://hooks.example.invalid/" + Marker);
            Assert.True(FileHolds(path, Marker));

            await AssertScrubbedWhileOpenAndAfterCloseAsync(path);
        });

    [Fact]
    public async Task Encrypting_also_removes_what_earlier_saves_left_in_free_space() =>
        await WithDatabaseAsync(async path =>
        {
            // Different lengths move the row around, leaving old copies in the page and on the freelist.
            await SaveWebhookAsync(
                path,
                "https://hooks.example.invalid/" + Marker,
                "https://hooks.example.invalid/" + Marker + new string('x', 6000),
                "https://hooks.example.invalid/short");

            await AssertScrubbedWhileOpenAndAfterCloseAsync(path);
        });

    [Fact]
    public async Task Scrubbing_keeps_the_settings_and_a_later_write_works() =>
        await WithDatabaseAsync(async path =>
        {
            await SaveWebhookAsync(path, Webhook);
            await using var store = new SqliteStore(path, NullLogger<SqliteStore>.Instance, TimeProvider.System);
            await store.InitializeAsync();

            var holder = new SettingsHolder(store, NullLogger<SettingsHolder>.Instance, new FakeProtector());
            await holder.LoadAsync();

            Assert.Equal(Webhook, holder.Current.Notifications.WebhookUrl);
            await store.AddToListAsync(ListKind.Whitelist, "203.0.113.1");
            Assert.Contains("203.0.113.1", await store.GetListAsync(ListKind.Whitelist));
        });

    [Fact]
    public async Task A_blocked_checkpoint_does_not_stop_the_start_up() =>
        await WithDatabaseAsync(async path =>
        {
            await SaveWebhookAsync(path, Webhook);
            await using var store = new SqliteStore(path, NullLogger<SqliteStore>.Instance, TimeProvider.System);
            await store.InitializeAsync();

            // A reader in the middle of a transaction: the WAL cannot be reset under it.
            await using var reader = new SqliteConnection($"Data Source={path};Pooling=False");
            await reader.OpenAsync();
            await using var transaction = reader.BeginTransaction(deferred: true);
            await using var command = reader.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = "SELECT COUNT(*) FROM settings;";
            await command.ExecuteScalarAsync();

            var holder = new SettingsHolder(store, NullLogger<SettingsHolder>.Instance, new FakeProtector());
            await holder.LoadAsync();

            Assert.Equal(Webhook, holder.Current.Notifications.WebhookUrl);
            var stored = JsonSerializer.Deserialize<WinGuardSettings>((await store.GetAllSettingsAsync())[SettingsHolder.SettingsKey], IpcJson.Options)!;
            Assert.StartsWith(SecretValue.Prefix, stored.Notifications.WebhookUrl);
        });

    /// <summary>Encrypts into something visibly not the plaintext; can be told it is the wrong account.</summary>
    private sealed class FakeProtector : ISecretProtector
    {
        public bool RunsAsServiceAccount { get; init; } = true;

        public bool CanDecrypt { get; set; } = true;

        public bool CanEncrypt { get; set; } = true;

        public int ProtectCalls { get; private set; }

        public string Protect(string plaintext)
        {
            ProtectCalls++;
            if (!CanEncrypt)
            {
                throw new InvalidOperationException("DPAPI is unavailable");
            }

            return SecretValue.Prefix + Convert.ToBase64String(Encoding.UTF8.GetBytes(new string(plaintext.Reverse().ToArray())));
        }

        public bool TryUnprotect(string stored, out string plaintext)
        {
            plaintext = string.Empty;
            if (!CanDecrypt)
            {
                return false;
            }

            plaintext = new string(Encoding.UTF8.GetString(Convert.FromBase64String(stored[SecretValue.Prefix.Length..])).Reverse().ToArray());
            return true;
        }
    }

    private sealed class CountingLogger : ILogger<SettingsHolder>
    {
        public int Warnings { get; private set; }

        public List<string> Messages { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            Messages.Add(formatter(state, exception));
            if (logLevel == LogLevel.Warning)
            {
                Warnings++;
            }
        }
    }

    /// <summary>A database written by the service, as a console run or another machine finds it.</summary>
    private static async Task<(FakeStore Store, FakeProtector Protector)> StoredBySystemAsync()
    {
        var store = new FakeStore();
        var protector = new FakeProtector();
        var service = new SettingsHolder(store, NullLogger<SettingsHolder>.Instance, protector);
        await service.LoadAsync();
        await service.ApplyAsync(WithSecrets());
        protector.CanDecrypt = false;
        return (store, protector);
    }

    // ---- at rest ----

    [Fact]
    public async Task Secrets_never_reach_the_store_in_plain_text()
    {
        var store = new FakeStore();
        var holder = new SettingsHolder(store, NullLogger<SettingsHolder>.Instance, new FakeProtector());
        await holder.LoadAsync();

        await holder.ApplyAsync(WithSecrets());

        var json = StoredJson(store);
        Assert.DoesNotContain(Webhook, json);
        Assert.DoesNotContain(Telegram, json);
        Assert.DoesNotContain(SmtpPassword, json);

        var stored = Stored(store);
        Assert.StartsWith(SecretValue.Prefix, stored.WebhookUrl);
        Assert.StartsWith(SecretValue.Prefix, stored.TelegramBotToken);
        Assert.StartsWith(SecretValue.Prefix, stored.Smtp!.Password);
    }

    [Fact]
    public async Task The_live_settings_and_the_console_keep_seeing_plaintext()
    {
        var holder = new SettingsHolder(new FakeStore(), NullLogger<SettingsHolder>.Instance, new FakeProtector());
        await holder.LoadAsync();
        var settings = WithSecrets();

        await holder.ApplyAsync(settings);

        Assert.Same(settings, holder.Current);
        Assert.Equal(Webhook, holder.Current.Notifications.WebhookUrl);
        Assert.Equal(Telegram, holder.Current.Notifications.TelegramBotToken);
        Assert.Equal(SmtpPassword, holder.Current.Notifications.Smtp!.Password);
    }

    [Fact]
    public async Task Everything_but_the_secrets_is_stored_readable()
    {
        var store = new FakeStore();
        var holder = new SettingsHolder(store, NullLogger<SettingsHolder>.Instance, new FakeProtector());
        await holder.LoadAsync();
        var settings = WithSecrets();
        settings.FailedLoginThreshold = 9;
        settings.Notifications.TelegramChatId = "42";

        await holder.ApplyAsync(settings);

        var stored = JsonSerializer.Deserialize<WinGuardSettings>(StoredJson(store), IpcJson.Options)!;
        Assert.Equal(9, stored.FailedLoginThreshold);
        Assert.Equal("42", stored.Notifications.TelegramChatId);
        Assert.Equal("mail.example.invalid", stored.Notifications.Smtp!.Host);
    }

    [Fact]
    public async Task Secrets_survive_a_restart()
    {
        var store = new FakeStore();
        var protector = new FakeProtector();
        var first = new SettingsHolder(store, NullLogger<SettingsHolder>.Instance, protector);
        await first.LoadAsync();
        await first.ApplyAsync(WithSecrets());

        var second = new SettingsHolder(store, NullLogger<SettingsHolder>.Instance, protector);
        await second.LoadAsync();

        Assert.Equal(Webhook, second.Current.Notifications.WebhookUrl);
        Assert.Equal(Telegram, second.Current.Notifications.TelegramBotToken);
        Assert.Equal(SmtpPassword, second.Current.Notifications.Smtp!.Password);
        Assert.Empty(second.UndecryptableSecrets);
    }

    [Fact]
    public async Task Empty_secrets_stay_empty_rather_than_becoming_ciphertext()
    {
        var store = new FakeStore();
        var protector = new FakeProtector();
        var holder = new SettingsHolder(store, NullLogger<SettingsHolder>.Instance, protector);
        await holder.LoadAsync();

        await holder.ApplyAsync(new WinGuardSettings());

        Assert.Equal(0, protector.ProtectCalls);
        Assert.Equal(string.Empty, Stored(store).WebhookUrl);
    }

    [Fact]
    public async Task Clearing_a_readable_secret_really_clears_it()
    {
        var store = new FakeStore();
        var holder = new SettingsHolder(store, NullLogger<SettingsHolder>.Instance, new FakeProtector());
        await holder.LoadAsync();
        await holder.ApplyAsync(WithSecrets());

        var cleared = holder.Current.Clone();
        cleared.Notifications.TelegramBotToken = string.Empty;
        await holder.ApplyAsync(cleared);

        Assert.Equal(string.Empty, Stored(store).TelegramBotToken);
        Assert.StartsWith(SecretValue.Prefix, Stored(store).WebhookUrl);
    }

    [Fact]
    public async Task A_secret_that_did_not_change_keeps_its_stored_form()
    {
        var store = new FakeStore();
        var protector = new FakeProtector();
        var holder = new SettingsHolder(store, NullLogger<SettingsHolder>.Instance, protector);
        await holder.LoadAsync();
        await holder.ApplyAsync(WithSecrets());
        var calls = protector.ProtectCalls;

        var next = holder.Current.Clone();
        next.FailedLoginThreshold = 7;
        await holder.ApplyAsync(next);

        Assert.Equal(calls, protector.ProtectCalls);
    }

    [Fact]
    public async Task A_value_that_merely_looks_encrypted_is_treated_as_plaintext_on_the_way_in()
    {
        // Over IPC everything is plaintext. Trusting the marker here would let a saved value skip
        // encryption, and come back as garbage on the next load.
        var store = new FakeStore();
        var protector = new FakeProtector();
        var holder = new SettingsHolder(store, NullLogger<SettingsHolder>.Instance, protector);
        await holder.LoadAsync();
        var settings = new WinGuardSettings();
        settings.Notifications.WebhookUrl = "dpapi:not-really";

        await holder.ApplyAsync(settings);
        var reloaded = new SettingsHolder(store, NullLogger<SettingsHolder>.Instance, protector);
        await reloaded.LoadAsync();

        Assert.Equal("dpapi:not-really", reloaded.Current.Notifications.WebhookUrl);
    }

    // ---- old plaintext ----

    [Fact]
    public async Task Old_plaintext_keeps_working()
    {
        var store = new FakeStore();
        await SeedAsync(store, WithSecrets());
        var holder = new SettingsHolder(store, NullLogger<SettingsHolder>.Instance, new FakeProtector { RunsAsServiceAccount = false });

        await holder.LoadAsync();

        Assert.Equal(Webhook, holder.Current.Notifications.WebhookUrl);
        Assert.Equal(SmtpPassword, holder.Current.Notifications.Smtp!.Password);
    }

    [Fact]
    public async Task The_service_encrypts_old_plaintext_at_start_up()
    {
        var store = new FakeStore();
        await SeedAsync(store, WithSecrets());
        var holder = new SettingsHolder(store, NullLogger<SettingsHolder>.Instance, new FakeProtector());

        await holder.LoadAsync();

        Assert.DoesNotContain(Telegram, StoredJson(store));
        Assert.StartsWith(SecretValue.Prefix, Stored(store).TelegramBotToken);
        Assert.Equal(Telegram, holder.Current.Notifications.TelegramBotToken);
    }

    [Fact]
    public async Task A_console_run_leaves_old_plaintext_for_the_service_to_encrypt()
    {
        // Encrypted here it would be tied to this administrator and lost to the service.
        var store = new FakeStore();
        await SeedAsync(store, WithSecrets());
        var console = new FakeProtector { RunsAsServiceAccount = false };
        var holder = new SettingsHolder(store, NullLogger<SettingsHolder>.Instance, console);

        await holder.LoadAsync();
        var next = holder.Current.Clone();
        next.FailedLoginThreshold = 7;
        await holder.ApplyAsync(next);

        Assert.Equal(0, console.ProtectCalls);
        Assert.Equal(Telegram, Stored(store).TelegramBotToken);
    }

    [Fact]
    public async Task A_console_run_still_encrypts_a_value_typed_into_it()
    {
        var store = new FakeStore();
        await SeedAsync(store, WithSecrets());
        var holder = new SettingsHolder(store, NullLogger<SettingsHolder>.Instance, new FakeProtector { RunsAsServiceAccount = false });

        await holder.LoadAsync();
        var next = holder.Current.Clone();
        next.Notifications.TelegramBotToken = "new-token";
        await holder.ApplyAsync(next);

        Assert.DoesNotContain("new-token", StoredJson(store));
    }

    [Fact]
    public async Task A_failed_start_up_encryption_leaves_the_plaintext_working()
    {
        var store = new FakeStore();
        await SeedAsync(store, WithSecrets());
        var holder = new SettingsHolder(store, NullLogger<SettingsHolder>.Instance, new FakeProtector { CanEncrypt = false });

        await holder.LoadAsync();

        Assert.Equal(Telegram, holder.Current.Notifications.TelegramBotToken);
        Assert.Equal(Telegram, Stored(store).TelegramBotToken);
    }

    // ---- a value that cannot be decrypted ----

    [Fact]
    public async Task An_undecryptable_value_reads_as_empty_with_one_warning()
    {
        var (store, protector) = await StoredBySystemAsync();
        var logger = new CountingLogger();
        var console = new SettingsHolder(store, logger, protector);

        await console.LoadAsync();

        Assert.Equal(string.Empty, console.Current.Notifications.WebhookUrl);
        Assert.Equal(string.Empty, console.Current.Notifications.TelegramBotToken);
        Assert.Equal(string.Empty, console.Current.Notifications.Smtp!.Password);
        Assert.Equal(1, logger.Warnings);
        Assert.Equal(["webhook URL", "Telegram bot token", "SMTP password"], console.UndecryptableSecrets);
    }

    [Fact]
    public async Task Saving_an_unrelated_setting_does_not_wipe_a_value_that_cannot_be_decrypted()
    {
        var (store, protector) = await StoredBySystemAsync();
        var ciphertext = Stored(store);
        var console = new SettingsHolder(store, NullLogger<SettingsHolder>.Instance, protector);
        await console.LoadAsync();

        // Just what the console does: everything it was given comes back, with one field changed.
        var next = console.Current.Clone();
        next.FailedLoginThreshold = 9;
        await console.ApplyAsync(next);

        var stored = Stored(store);
        Assert.Equal(ciphertext.WebhookUrl, stored.WebhookUrl);
        Assert.Equal(ciphertext.TelegramBotToken, stored.TelegramBotToken);
        Assert.Equal(ciphertext.Smtp!.Password, stored.Smtp!.Password);
        Assert.Equal(9, JsonSerializer.Deserialize<WinGuardSettings>(StoredJson(store), IpcJson.Options)!.FailedLoginThreshold);

        // And it is still there for the account that can read it.
        protector.CanDecrypt = true;
        var service = new SettingsHolder(store, NullLogger<SettingsHolder>.Instance, protector);
        await service.LoadAsync();
        Assert.Equal(Webhook, service.Current.Notifications.WebhookUrl);
        Assert.Equal(Telegram, service.Current.Notifications.TelegramBotToken);
        Assert.Equal(SmtpPassword, service.Current.Notifications.Smtp!.Password);
    }

    [Fact]
    public async Task The_kept_value_survives_save_after_save_and_restart_after_restart()
    {
        var (store, protector) = await StoredBySystemAsync();
        var ciphertext = Stored(store).WebhookUrl;

        for (var run = 0; run < 3; run++)
        {
            var console = new SettingsHolder(store, NullLogger<SettingsHolder>.Instance, protector);
            await console.LoadAsync();
            for (var save = 0; save < 3; save++)
            {
                var next = console.Current.Clone();
                next.FailedLoginThreshold = 10 + run + save;
                await console.ApplyAsync(next);
            }
        }

        Assert.Equal(ciphertext, Stored(store).WebhookUrl);
    }

    [Fact]
    public async Task A_whitespace_field_does_not_replace_the_kept_value_either()
    {
        var (store, protector) = await StoredBySystemAsync();
        var ciphertext = Stored(store).WebhookUrl;
        var console = new SettingsHolder(store, NullLogger<SettingsHolder>.Instance, protector);
        await console.LoadAsync();

        var next = console.Current.Clone();
        next.Notifications.WebhookUrl = "   ";
        await console.ApplyAsync(next);

        Assert.Equal(ciphertext, Stored(store).WebhookUrl);
    }

    [Fact]
    public async Task A_new_value_replaces_the_kept_one_and_only_that_field()
    {
        var (store, protector) = await StoredBySystemAsync();
        var ciphertext = Stored(store);
        var console = new SettingsHolder(store, NullLogger<SettingsHolder>.Instance, protector);
        await console.LoadAsync();

        var next = console.Current.Clone();
        next.Notifications.TelegramBotToken = "new-token";
        await console.ApplyAsync(next);

        var stored = Stored(store);
        Assert.NotEqual(ciphertext.TelegramBotToken, stored.TelegramBotToken);
        Assert.StartsWith(SecretValue.Prefix, stored.TelegramBotToken);
        Assert.Equal(ciphertext.WebhookUrl, stored.WebhookUrl);
        Assert.Equal(["webhook URL", "SMTP password"], console.UndecryptableSecrets);
        Assert.Equal("new-token", console.Current.Notifications.TelegramBotToken);
    }

    [Fact]
    public async Task A_marker_with_garbage_after_it_counts_as_undecryptable_and_is_kept()
    {
        var store = new FakeStore();
        var settings = new WinGuardSettings();
        settings.Notifications.WebhookUrl = SecretValue.Prefix + "!!!not base64!!!";
        await SeedAsync(store, settings);
        var holder = new SettingsHolder(store, NullLogger<SettingsHolder>.Instance, new DpapiSecretProtector());

        await holder.LoadAsync();
        await holder.ApplyAsync(holder.Current.Clone());

        Assert.Equal(string.Empty, holder.Current.Notifications.WebhookUrl);
        Assert.Equal(SecretValue.Prefix + "!!!not base64!!!", Stored(store).WebhookUrl);
    }

    [Fact]
    public async Task An_undecryptable_value_becomes_a_prerequisite_warning()
    {
        var (store, protector) = await StoredBySystemAsync();
        var holder = new SettingsHolder(store, NullLogger<SettingsHolder>.Instance, protector);
        await holder.LoadAsync();
        var firewall = new FakeFirewall();
        var engine = new BanEngine(store, firewall, () => holder.Current, NullLogger<BanEngine>.Instance);
        var handler = new IpcRequestHandler(store, engine, holder, firewall, new DetectorRuntimeState(), TimeProvider.System, NullLogger<IpcRequestHandler>.Instance);

        var line = await handler.HandleLineAsync(JsonSerializer.Serialize(new IpcRequest { Id = 1, Method = IpcMethods.CheckPrereqs }, IpcJson.Options), CancellationToken.None);
        var response = JsonSerializer.Deserialize<IpcResponse>(line!, IpcJson.Options)!;
        var prereqs = JsonSerializer.Deserialize<PrereqsDto>(response.Result!.Value, IpcJson.Options)!;

        Assert.Contains(prereqs.Warnings, warning => warning.Contains("SMTP password") && warning.Contains("could not be decrypted"));
    }

    // ---- failures ----

    [Fact]
    public async Task A_value_that_cannot_be_encrypted_is_refused_never_stored_in_the_clear()
    {
        var store = new FakeStore();
        var protector = new FakeProtector();
        var holder = new SettingsHolder(store, NullLogger<SettingsHolder>.Instance, protector);
        await holder.LoadAsync();
        await holder.ApplyAsync(new WinGuardSettings());
        protector.CanEncrypt = false;

        await Assert.ThrowsAsync<InvalidOperationException>(() => holder.ApplyAsync(WithSecrets()));

        Assert.DoesNotContain(Telegram, StoredJson(store));
        Assert.Equal(string.Empty, holder.Current.Notifications.TelegramBotToken);
    }

    [Fact]
    public async Task A_refused_save_leaves_the_kept_value_and_the_state_alone()
    {
        var (store, protector) = await StoredBySystemAsync();
        var ciphertext = Stored(store).TelegramBotToken;
        var console = new SettingsHolder(store, NullLogger<SettingsHolder>.Instance, protector);
        await console.LoadAsync();

        var next = console.Current.Clone();
        next.Notifications.TelegramBotToken = "new-token";
        store.FailSettingWrites = true;
        await Assert.ThrowsAsync<IOException>(() => console.ApplyAsync(next));
        store.FailSettingWrites = false;

        // The save that failed must not count: the next one still sees the old ciphertext.
        await console.ApplyAsync(console.Current.Clone());

        Assert.Equal(ciphertext, Stored(store).TelegramBotToken);
        Assert.Contains("Telegram bot token", console.UndecryptableSecrets);
    }

    // ---- real DPAPI ----

    [SupportedOSPlatform("windows")]
    public sealed class RealDpapi
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct DataBlob
        {
            public int Size;
            public IntPtr Data;
        }

        [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptProtectData(ref DataBlob dataIn, string? description, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, out DataBlob dataOut);

        /// <summary>What another program running as this account would produce for the same text.</summary>
        private static string ProtectWithoutEntropy(string plaintext)
        {
            var data = Encoding.UTF8.GetBytes(plaintext);
            var pin = GCHandle.Alloc(data, GCHandleType.Pinned);
            try
            {
                var input = new DataBlob { Size = data.Length, Data = pin.AddrOfPinnedObject() };
                Assert.True(CryptProtectData(ref input, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out var output));
                var blob = new byte[output.Size];
                Marshal.Copy(output.Data, blob, 0, output.Size);
                return SecretValue.Prefix + Convert.ToBase64String(blob);
            }
            finally
            {
                pin.Free();
            }
        }

        [Theory]
        [InlineData("s3cr3t")]
        [InlineData("x")]
        [InlineData("pässwörd \U0001F512 with unicode")]
        public void A_value_comes_back_as_it_went_in(string plaintext)
        {
            var protector = new DpapiSecretProtector();

            var stored = protector.Protect(plaintext);

            Assert.StartsWith(SecretValue.Prefix, stored);
            Assert.True(protector.TryUnprotect(stored, out var decrypted));
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void Each_encryption_is_different()
        {
            var protector = new DpapiSecretProtector();

            Assert.NotEqual(protector.Protect("s3cr3t"), protector.Protect("s3cr3t"));
        }

        [Fact]
        public void Tampered_ciphertext_does_not_decrypt()
        {
            var protector = new DpapiSecretProtector();
            var stored = protector.Protect("s3cr3t");
            var blob = Convert.FromBase64String(stored[SecretValue.Prefix.Length..]);
            blob[^1] ^= 0xFF;

            Assert.False(protector.TryUnprotect(SecretValue.Prefix + Convert.ToBase64String(blob), out var plaintext));
            Assert.Equal(string.Empty, plaintext);
        }

        [Fact]
        public void A_blob_encrypted_without_our_entropy_does_not_decrypt()
        {
            Assert.False(new DpapiSecretProtector().TryUnprotect(ProtectWithoutEntropy("s3cr3t"), out _));
        }

        [Theory]
        [InlineData("plain value")]
        [InlineData("dpapi:")]
        [InlineData("dpapi:!!!")]
        [InlineData("dpapi:AAAA")]
        public void Anything_else_does_not_decrypt(string stored)
        {
            Assert.False(new DpapiSecretProtector().TryUnprotect(stored, out var plaintext));
            Assert.Equal(string.Empty, plaintext);
        }

        [Fact]
        public async Task The_default_holder_encrypts_for_real()
        {
            var store = new FakeStore();
            var holder = new SettingsHolder(store, NullLogger<SettingsHolder>.Instance);
            await holder.LoadAsync();

            await holder.ApplyAsync(WithSecrets());

            Assert.DoesNotContain(SmtpPassword, StoredJson(store));

            var reloaded = new SettingsHolder(store, NullLogger<SettingsHolder>.Instance);
            await reloaded.LoadAsync();
            Assert.Equal(SmtpPassword, reloaded.Current.Notifications.Smtp!.Password);
        }
    }
}
