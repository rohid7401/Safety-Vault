using System.Security.Cryptography;
using PasswordManager.Core.Configuration;
using PasswordManager.Core.Interfaces;
using PasswordManager.Core.Models;

namespace PasswordManager.Core.Services
{
    public sealed class PasswordManagerService : IDisposable, IAsyncDisposable
    {
        private readonly IVaultRepository _repository;
        private readonly IAesService _aesService;
        private readonly IPgpService _pgpService;
        private readonly VaultOptions _options;

        private byte[]? _aesKey;
        private bool _disposed;

        private const string AesKeyFileName = "vault.key.pgp";

        private PasswordManagerService(
            IVaultRepository repository,
            IAesService aesService,
            IPgpService pgpService,
            VaultOptions options)
        {
            _repository = repository;
            _aesService = aesService;
            _pgpService = pgpService;
            _options = options;
        }

        public static async Task<PasswordManagerService> CreateAsync(
            IVaultRepository repository,
            IAesService aesService,
            IPgpService pgpService,
            VaultOptions options)
        {
            if (string.IsNullOrEmpty(options.Passphrase))
                throw new ArgumentException("Passphrase cannot be empty.");

            if (!File.Exists(options.ResolvedPublicKeyPath))
                throw new FileNotFoundException("Public key not found.", options.ResolvedPublicKeyPath);
            if (!File.Exists(options.ResolvedPrivateKeyPath))
                throw new FileNotFoundException("Private key not found.", options.ResolvedPrivateKeyPath);

            var service = new PasswordManagerService(repository, aesService, pgpService, options);
            await service.InitializeAesKeyAsync();
            return service;
        }

        private async Task InitializeAesKeyAsync()
        {
            var aesKeyPath = Path.Combine(_options.DataFolderPath, AesKeyFileName);
            if (File.Exists(aesKeyPath))
            {
                var encryptedKey = await File.ReadAllTextAsync(aesKeyPath);
                var keyBase64 = _pgpService.DecryptString(
                    encryptedKey, _options.ResolvedPrivateKeyPath, _options.Passphrase);
                _aesKey = Convert.FromBase64String(keyBase64);
            }
            else
            {
                _aesKey = RandomNumberGenerator.GetBytes(32);
                var keyBase64 = Convert.ToBase64String(_aesKey);
                var encryptedKey = _pgpService.EncryptString(keyBase64, _options.ResolvedPublicKeyPath);
                await File.WriteAllTextAsync(aesKeyPath, encryptedKey);
            }
        }

        // ─── Query ───────────────────────────────────────────────────────────

        public async Task<List<VaultEntry>> GetAllEntriesAsync()
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();
            return vault.Entries.Where(e => !e.IsDeleted).ToList();
        }

        public async Task<List<T>> GetEntriesAsync<T>() where T : VaultEntry
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();
            return vault.Entries.OfType<T>().Where(e => !e.IsDeleted).ToList();
        }

        public async Task<VaultEntry?> GetEntryByIdAsync(Guid id)
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();
            return vault.Entries.FirstOrDefault(e => e.Id == id && !e.IsDeleted);
        }

        public async Task<List<VaultEntry>> FindEntriesAsync(Func<VaultEntry, bool> predicate)
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();
            return vault.Entries.Where(e => !e.IsDeleted && predicate(e)).ToList();
        }

        // ─── Add entries ─────────────────────────────────────────────────────

        public async Task AddPasswordEntryAsync(PasswordEntry entry, string plainPassword)
        {
            ThrowIfDisposed();
            entry.Password = EncryptField(plainPassword);
            await AddEntryAsync(entry);
        }

        public async Task AddSecureNoteAsync(SecureNote note, string plainContent)
        {
            ThrowIfDisposed();
            note.Content = EncryptField(plainContent);
            await AddEntryAsync(note);
        }

        public async Task AddCardEntryAsync(CardEntry card, string plainCardNumber, string plainCvv)
        {
            ThrowIfDisposed();
            card.CardNumber = EncryptField(plainCardNumber);
            card.Cvv = EncryptField(plainCvv);
            await AddEntryAsync(card);
        }

        private async Task AddEntryAsync(VaultEntry entry)
        {
            entry.CreationTime = DateTime.UtcNow;
            entry.LastUpdateTime = DateTime.UtcNow;
            var vault = await _repository.LoadAsync();
            vault.Entries.Add(entry);
            await _repository.SaveAsync(vault);
        }

        // ─── Update ──────────────────────────────────────────────────────────

        public async Task UpdateEntryAsync(Guid id, Action<VaultEntry> updateAction)
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();
            var entry = vault.Entries.FirstOrDefault(e => e.Id == id && !e.IsDeleted);
            if (entry is null) return;

            updateAction(entry);
            entry.LastUpdateTime = DateTime.UtcNow;
            await _repository.SaveAsync(vault);
        }

        public async Task ChangePasswordAsync(Guid id, string newPlainPassword)
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();
            var entry = vault.Entries.OfType<PasswordEntry>().FirstOrDefault(e => e.Id == id && !e.IsDeleted);
            if (entry is null) return;

            entry.Password = EncryptField(newPlainPassword);
            entry.LastUpdateTime = DateTime.UtcNow;
            await _repository.SaveAsync(vault);
        }

        // ─── Soft delete / Restore / Purge ───────────────────────────────────

        public async Task DeleteEntryAsync(Guid id)
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();
            var entry = vault.Entries.FirstOrDefault(e => e.Id == id && !e.IsDeleted);
            if (entry is null) return;

            entry.IsDeleted = true;
            entry.DeletedAt = DateTime.UtcNow;
            await _repository.SaveAsync(vault);
        }

        public async Task RestoreEntryAsync(Guid id)
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();
            var entry = vault.Entries.FirstOrDefault(e => e.Id == id && e.IsDeleted);
            if (entry is null) return;

            entry.IsDeleted = false;
            entry.DeletedAt = null;
            await _repository.SaveAsync(vault);
        }

        public async Task<List<VaultEntry>> GetDeletedEntriesAsync()
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();
            return vault.Entries.Where(e => e.IsDeleted).ToList();
        }

        public async Task PurgeDeletedAsync()
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();
            vault.Entries.RemoveAll(e => e.IsDeleted);
            await _repository.SaveAsync(vault);
        }

        // ─── Expiration ──────────────────────────────────────────────────────

        public async Task SetExpireTimeAsync(Guid id, DateTime? expireTime)
        {
            await UpdateEntryAsync(id, e => e.ExpireTime = expireTime);
        }

        // ─── Decrypt ─────────────────────────────────────────────────────────

        public string DecryptField(EncryptedField field)
        {
            ThrowIfDisposed();
            if (string.IsNullOrEmpty(field.CipherText)) return string.Empty;
            return _aesService.Decrypt(field.CipherText, _aesKey!, field.Nonce, field.Tag);
        }

        public string DecryptPassword(PasswordEntry entry) => DecryptField(entry.Password);

        // ─── TOTP ────────────────────────────────────────────────────────────

        public async Task SetTotpSecretAsync(Guid id, string base32Secret)
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();
            var entry = vault.Entries.OfType<PasswordEntry>().FirstOrDefault(e => e.Id == id && !e.IsDeleted);
            if (entry is null) return;

            entry.TotpSecret = EncryptField(base32Secret);
            entry.LastUpdateTime = DateTime.UtcNow;
            await _repository.SaveAsync(vault);
        }

        public async Task RemoveTotpSecretAsync(Guid id)
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();
            var entry = vault.Entries.OfType<PasswordEntry>().FirstOrDefault(e => e.Id == id && !e.IsDeleted);
            if (entry is null) return;

            entry.TotpSecret = null;
            entry.LastUpdateTime = DateTime.UtcNow;
            await _repository.SaveAsync(vault);
        }

        public string? GetDecryptedTotpSecret(PasswordEntry entry)
        {
            ThrowIfDisposed();
            if (entry.TotpSecret is null) return null;
            return DecryptField(entry.TotpSecret);
        }

        // ─── Export / Import ─────────────────────────────────────────────────

        public async Task<List<PortableEntry>> ExportPasswordEntriesAsync()
        {
            ThrowIfDisposed();
            var entries = await GetEntriesAsync<PasswordEntry>();
            return entries.Select(e => new PortableEntry
            {
                Site = e.Site,
                Username = e.Username,
                Email = e.Email,
                Password = DecryptPassword(e),
                TotpSecret = GetDecryptedTotpSecret(e),
                Tags = new List<string>(e.Tags),
            }).ToList();
        }

        public async Task ImportPasswordEntriesAsync(IReadOnlyList<PortableEntry> portableEntries)
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();

            foreach (var portable in portableEntries)
            {
                var entry = new PasswordEntry
                {
                    Site = portable.Site,
                    Username = portable.Username,
                    Email = portable.Email,
                    Password = EncryptField(portable.Password),
                    Tags = new List<string>(portable.Tags),
                    CreationTime = DateTime.UtcNow,
                    LastUpdateTime = DateTime.UtcNow,
                };

                if (!string.IsNullOrEmpty(portable.TotpSecret))
                    entry.TotpSecret = EncryptField(portable.TotpSecret);

                vault.Entries.Add(entry);
            }

            await _repository.SaveAsync(vault);
        }

        // ─── Audit ───────────────────────────────────────────────────────────

        public async Task<AuditReport> AuditVaultAsync(IVaultAuditor auditor)
        {
            ThrowIfDisposed();
            var entries = await GetEntriesAsync<PasswordEntry>();
            return auditor.Audit(entries, DecryptPassword);
        }

        // ─── Helpers ─────────────────────────────────────────────────────────

        private EncryptedField EncryptField(string plainText)
        {
            var (cipher, nonce, tag) = _aesService.Encrypt(plainText, _aesKey!);
            return new EncryptedField { CipherText = cipher, Nonce = nonce, Tag = tag };
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
