using System.Security.Cryptography;
using System.Text.Json;
using PasswordManager.Core.Interfaces;
using PasswordManager.Core.Models;

namespace PasswordManager.Core.Services
{
    public sealed class PasswordManagerService : IDisposable, IAsyncDisposable
    {
        private readonly IPgpService _pgpService;
        private readonly IAesService _aesService;
        private readonly string _pgpPublicKeyPath;
        private readonly string _pgpPrivateKeyPath;
        private readonly string _pgpPassphrase;
        private readonly string _dataFolderPath;

        private byte[]? _aesKey;
        private bool _disposed;

        private const string VaultFileName = "vault.data.pgp";
        private const string AesKeyFileName = "vault.key.pgp";

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            WriteIndented = true
        };

        private PasswordManagerService(
            string dataFolderPath,
            string pgpPublicKeyPath,
            string pgpPrivateKeyPath,
            string pgpPassphrase,
            IPgpService pgpService,
            IAesService aesService)
        {
            _dataFolderPath = dataFolderPath;
            _pgpPublicKeyPath = pgpPublicKeyPath;
            _pgpPrivateKeyPath = pgpPrivateKeyPath;
            _pgpPassphrase = pgpPassphrase;
            _pgpService = pgpService;
            _aesService = aesService;
        }

        public static async Task<PasswordManagerService> CreateAsync(
            string dataFolderPath,
            IPgpService pgpService,
            IAesService aesService,
            string? pgpPublicKeyPath = null,
            string? pgpPrivateKeyPath = null,
            string pgpPassphrase = "")
        {
            if (string.IsNullOrEmpty(pgpPassphrase))
                throw new ArgumentException("PGP passphrase cannot be empty.");

            pgpPublicKeyPath ??= Path.Combine(dataFolderPath, "public_key.asc");
            pgpPrivateKeyPath ??= Path.Combine(dataFolderPath, "private_key.asc");

            if (!File.Exists(pgpPublicKeyPath))
                throw new FileNotFoundException("Public key not found.", pgpPublicKeyPath);
            if (!File.Exists(pgpPrivateKeyPath))
                throw new FileNotFoundException("Private key not found.", pgpPrivateKeyPath);

            var service = new PasswordManagerService(
                dataFolderPath, pgpPublicKeyPath, pgpPrivateKeyPath,
                pgpPassphrase, pgpService, aesService);

            await service.InitializeAesKeyAsync();
            return service;
        }

        private async Task InitializeAesKeyAsync()
        {
            var aesKeyPath = Path.Combine(_dataFolderPath, AesKeyFileName);
            if (File.Exists(aesKeyPath))
            {
                var encryptedKey = await File.ReadAllTextAsync(aesKeyPath);
                var keyBase64 = _pgpService.DecryptString(encryptedKey, _pgpPrivateKeyPath, _pgpPassphrase);
                _aesKey = Convert.FromBase64String(keyBase64);
            }
            else
            {
                _aesKey = RandomNumberGenerator.GetBytes(32); // 256-bit key
                var keyBase64 = Convert.ToBase64String(_aesKey);
                var encryptedKey = _pgpService.EncryptString(keyBase64, _pgpPublicKeyPath);
                await File.WriteAllTextAsync(aesKeyPath, encryptedKey);
            }
        }

        // ─── Vault I/O (all in-memory, no temp files) ───────────────────────

        private async Task<VaultData> LoadVaultAsync()
        {
            var vaultPath = Path.Combine(_dataFolderPath, VaultFileName);
            if (!File.Exists(vaultPath))
                return new VaultData();

            var encryptedBytes = await File.ReadAllBytesAsync(vaultPath);
            var jsonBytes = _pgpService.DecryptBytes(encryptedBytes, _pgpPrivateKeyPath, _pgpPassphrase);

            return JsonSerializer.Deserialize<VaultData>(jsonBytes, JsonOptions) ?? new VaultData();
        }

        private async Task SaveVaultAsync(VaultData vault)
        {
            vault.Version = VaultData.CurrentVersion;
            var vaultPath = Path.Combine(_dataFolderPath, VaultFileName);
            var jsonBytes = JsonSerializer.SerializeToUtf8Bytes(vault, JsonOptions);
            var encryptedBytes = _pgpService.EncryptBytes(jsonBytes, _pgpPublicKeyPath);
            await File.WriteAllBytesAsync(vaultPath, encryptedBytes);
        }

        // ─── Public API ──────────────────────────────────────────────────────

        public async Task<List<PasswordEntry>> GetAllEntriesAsync()
        {
            ThrowIfDisposed();
            var vault = await LoadVaultAsync();
            return vault.Entries;
        }

        public async Task<PasswordEntry?> GetEntryByIdAsync(Guid id)
        {
            ThrowIfDisposed();
            var vault = await LoadVaultAsync();
            return vault.Entries.FirstOrDefault(e => e.Id == id);
        }

        public async Task<List<PasswordEntry>> FindEntriesAsync(Func<PasswordEntry, bool> predicate)
        {
            ThrowIfDisposed();
            var vault = await LoadVaultAsync();
            return vault.Entries.Where(predicate).ToList();
        }

        public async Task AddEntryAsync(PasswordEntry entry, string plainPassword)
        {
            ThrowIfDisposed();
            var vault = await LoadVaultAsync();

            var (cipherText, nonce, tag) = _aesService.Encrypt(plainPassword, _aesKey!);
            entry.EncryptedPassword = cipherText;
            entry.Nonce = nonce;
            entry.Tag = tag;
            entry.CreationTime = DateTime.UtcNow;
            entry.LastUpdateTime = DateTime.UtcNow;

            vault.Entries.Add(entry);
            await SaveVaultAsync(vault);
        }

        public async Task UpdateEntryAsync(Guid id, Action<PasswordEntry> updateAction)
        {
            ThrowIfDisposed();
            var vault = await LoadVaultAsync();
            var entry = vault.Entries.FirstOrDefault(e => e.Id == id);
            if (entry is null) return;

            updateAction(entry);
            entry.LastUpdateTime = DateTime.UtcNow;
            await SaveVaultAsync(vault);
        }

        public async Task ChangePasswordAsync(Guid id, string newPlainPassword)
        {
            ThrowIfDisposed();
            var vault = await LoadVaultAsync();
            var entry = vault.Entries.FirstOrDefault(e => e.Id == id);
            if (entry is null) return;

            var (cipherText, nonce, tag) = _aesService.Encrypt(newPlainPassword, _aesKey!);
            entry.EncryptedPassword = cipherText;
            entry.Nonce = nonce;
            entry.Tag = tag;
            entry.LastUpdateTime = DateTime.UtcNow;
            await SaveVaultAsync(vault);
        }

        public async Task DeleteEntryAsync(Guid id)
        {
            ThrowIfDisposed();
            var vault = await LoadVaultAsync();
            vault.Entries.RemoveAll(e => e.Id == id);
            await SaveVaultAsync(vault);
        }

        public async Task SetExpireTimeAsync(Guid id, DateTime? expireTime)
        {
            ThrowIfDisposed();
            await UpdateEntryAsync(id, e => e.ExpireTime = expireTime);
        }

        /// <summary>Decrypts and returns the plaintext password. Throws if tampering is detected.</summary>
        public string DecryptPassword(PasswordEntry entry)
        {
            ThrowIfDisposed();
            if (string.IsNullOrEmpty(entry.EncryptedPassword)) return string.Empty;
            return _aesService.Decrypt(entry.EncryptedPassword, _aesKey!, entry.Nonce, entry.Tag);
        }

        // ─── IDisposable ─────────────────────────────────────────────────────

        public void Dispose()
        {
            if (_disposed) return;
            if (_aesKey is not null)
            {
                CryptographicOperations.ZeroMemory(_aesKey);
                _aesKey = null;
            }
            _disposed = true;
        }

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }

        private void ThrowIfDisposed()
        {
            if (_disposed) throw new ObjectDisposedException(nameof(PasswordManagerService));
        }
    }
}
