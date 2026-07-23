using System.Security.Cryptography;
using PasswordManager.Core.Interfaces;
using PasswordManager.Core.Models;

namespace PasswordManager.Core.Services
{
    public sealed class PasswordManagerService : IDisposable, IAsyncDisposable
    {
        private readonly IVaultRepository _repository;
        private readonly IAesService _aesService;

        private byte[]? _aesKey;
        private bool _disposed;

        private PasswordManagerService(
            IVaultRepository repository,
            IAesService aesService,
            byte[] fieldKey)
        {
            _repository = repository;
            _aesService = aesService;
            _aesKey = fieldKey;
        }

        /// <summary>
        /// Takes ownership of <paramref name="fieldKey"/> (zeroized on Dispose) — the caller
        /// derives it from the already-unlocked Vault Key (see VaultKeyRing.DeriveSubkey in
        /// the Infrastructure layer).
        /// </summary>
        public static Task<PasswordManagerService> CreateAsync(
            IVaultRepository repository,
            IAesService aesService,
            byte[] fieldKey)
        {
            return Task.FromResult(new PasswordManagerService(repository, aesService, fieldKey));
        }

        /// <summary>
        /// Writes the account's PGP key pair (used for encrypting files for contacts) back to
        /// disk if missing, using the copy stored inside the vault. This is what lets a vault
        /// copied to a new device — without its loose key files — become fully usable again
        /// once unlocked with just the passphrase.
        /// </summary>
        public async Task EnsurePgpKeyFilesAsync(string vaultFolder)
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();

            var publicPath = Path.Combine(vaultFolder, "public_key.asc");
            var privatePath = Path.Combine(vaultFolder, "private_key.asc");

            if (!File.Exists(publicPath) && !string.IsNullOrEmpty(vault.PgpPublicKeyArmored))
                await File.WriteAllTextAsync(publicPath, vault.PgpPublicKeyArmored);
            if (!File.Exists(privatePath) && !string.IsNullOrEmpty(vault.PgpPrivateKeyArmored))
                await File.WriteAllTextAsync(privatePath, vault.PgpPrivateKeyArmored);
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

        // ─── Service entries (flexible credential model) ──────────────────────

        /// <summary>
        /// Encrypts a plaintext value into an <see cref="EncryptedField"/> for a secret
        /// credential field. The UI builds a <see cref="ServiceEntry"/>'s secret fields with
        /// this, then persists it via <see cref="AddServiceEntryAsync"/>.
        /// </summary>
        public EncryptedField EncryptValue(string plaintext)
        {
            ThrowIfDisposed();
            return EncryptField(plaintext);
        }

        /// <summary>Decrypts a secret field's current value (empty when it has none).</summary>
        public string DecryptSecret(CredentialField field)
        {
            ThrowIfDisposed();
            return field.SecretValue is null ? string.Empty : DecryptField(field.SecretValue);
        }

        /// <summary>Decrypts the single-slot previous value of a rotating field, or null if none.</summary>
        public string? DecryptPreviousSecret(CredentialField field)
        {
            ThrowIfDisposed();
            return field.PreviousSecret is null ? null : DecryptField(field.PreviousSecret);
        }

        /// <summary>Persists a new service entry (its secret fields already built via <see cref="EncryptValue"/>).</summary>
        public async Task AddServiceEntryAsync(ServiceEntry entry)
        {
            ThrowIfDisposed();
            await AddEntryAsync(entry);
        }

        /// <summary>
        /// Rotates a secret field: encrypts the new value, keeps the immediately-previous one
        /// (single slot) when the field has a rotation policy, restarts the rotation clock, and
        /// persists. Returns false when the entry/credential/field was not found.
        /// </summary>
        public async Task<bool> RotateFieldSecretAsync(Guid entryId, Guid credentialId, Guid fieldId, string newPlaintext)
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();

            var entry = vault.Entries.OfType<ServiceEntry>().FirstOrDefault(e => e.Id == entryId && !e.IsDeleted);
            var cred = entry?.Credentials.FirstOrDefault(c => c.Id == credentialId);
            var field = cred?.Fields.FirstOrDefault(f => f.Id == fieldId);
            if (entry is null || cred is null || field is null) return false;

            field.SetSecret(EncryptField(newPlaintext));
            cred.LastUpdateTime = DateTime.UtcNow;
            entry.LastUpdateTime = DateTime.UtcNow;
            await _repository.SaveAsync(vault);
            return true;
        }

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

        // ─── Vault integrity / recovery ──────────────────────────────────────

        /// <summary>
        /// Forces a verified load of the vault. Throws
        /// <see cref="Exceptions.VaultIntegrityException"/> if the vault has been
        /// tampered with or is corrupt. Call this right after unlocking.
        /// </summary>
        public async Task ValidateVaultAsync()
        {
            ThrowIfDisposed();
            await _repository.LoadAsync();
        }

        /// <summary>True if a known-good backup exists to restore from.</summary>
        public bool HasVaultBackup()
        {
            ThrowIfDisposed();
            return _repository.HasBackup();
        }

        /// <summary>Restores the vault from the last known-good backup and verifies it.</summary>
        public async Task RestoreVaultFromBackupAsync()
        {
            ThrowIfDisposed();
            await _repository.RestoreFromBackupAsync();
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
            // Zeroize any derived key material held by the repository (e.g. the blob key).
            (_repository as IDisposable)?.Dispose();
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
