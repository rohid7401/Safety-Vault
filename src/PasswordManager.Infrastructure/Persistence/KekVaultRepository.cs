using System.Security.Cryptography;
using System.Text.Json;
using PasswordManager.Core.Exceptions;
using PasswordManager.Core.Interfaces;
using PasswordManager.Core.Models;

namespace PasswordManager.Infrastructure.Persistence
{
    /// <summary>
    /// Persists the vault as an AES-256-GCM encrypted blob, keyed by a subkey derived from
    /// the Vault Key (see <see cref="Encryption.VaultKeyRing"/>) — never by PGP. GCM is an
    /// AEAD cipher, so the authentication tag alone detects tampering; no separate MAC layer
    /// is needed. Also provides:
    ///  - atomic writes (temp file + move) so a crash never leaves a half-written vault;
    ///  - a rotating backup of the last known-good state for recovery.
    /// </summary>
    public class KekVaultRepository : IVaultRepository, IDisposable
    {
        private const int NonceBytes = 12;
        private const int TagBytes = 16;

        private readonly byte[] _blobKey;
        private readonly string _vaultPath;
        private readonly string _backupPath;

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            WriteIndented = true
        };

        /// <summary>Takes ownership of <paramref name="blobKey"/> — it is zeroized on Dispose.</summary>
        public KekVaultRepository(byte[] blobKey, string dataFolder)
        {
            _blobKey = blobKey;
            _vaultPath = Path.Combine(dataFolder, "vault.data");
            _backupPath = _vaultPath + ".bak";
        }

        // ─── Load ────────────────────────────────────────────────────────────

        public async Task<VaultData> LoadAsync()
        {
            if (!File.Exists(_vaultPath))
                return new VaultData();

            return await LoadVerifiedAsync(_vaultPath, HasBackup());
        }

        public bool HasBackup() => File.Exists(_backupPath);

        public async Task<VaultData> RestoreFromBackupAsync()
        {
            if (!HasBackup())
                throw new VaultIntegrityException("No backup is available to restore from.");

            // Verify the backup BEFORE overwriting the live vault.
            var restored = await LoadVerifiedAsync(_backupPath, backupAvailable: false);

            File.Copy(_backupPath, _vaultPath, overwrite: true);
            RestrictPermissions(_vaultPath);

            return restored;
        }

        private async Task<VaultData> LoadVerifiedAsync(string path, bool backupAvailable)
        {
            var blob = await File.ReadAllBytesAsync(path);
            if (blob.Length < NonceBytes + TagBytes)
                throw new VaultIntegrityException("Vault file is truncated or corrupt.", backupAvailable);

            // Plain byte[] slices (not Span<byte>) — a ref struct can't be a local in an
            // async method under the project's C# language version.
            var nonce = blob[..NonceBytes];
            var tag = blob[NonceBytes..(NonceBytes + TagBytes)];
            var ciphertext = blob[(NonceBytes + TagBytes)..];
            var plaintext = new byte[ciphertext.Length];

            try
            {
                using var aesGcm = new AesGcm(_blobKey, TagBytes);
                aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
            }
            catch (CryptographicException ex)
            {
                throw new VaultIntegrityException(
                    "Vault authentication failed — the file has been modified, replaced, or the passphrase is wrong.",
                    ex, backupAvailable);
            }

            try
            {
                return JsonSerializer.Deserialize<VaultData>(plaintext, JsonOptions) ?? new VaultData();
            }
            catch (JsonException ex)
            {
                throw new VaultIntegrityException("Vault contents are corrupt.", ex, backupAvailable);
            }
        }

        // ─── Save ────────────────────────────────────────────────────────────

        public async Task SaveAsync(VaultData vault)
        {
            vault.Version = VaultData.CurrentVersion;

            var plaintext = JsonSerializer.SerializeToUtf8Bytes(vault, JsonOptions);
            var nonce = RandomNumberGenerator.GetBytes(NonceBytes);
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[TagBytes];

            using (var aesGcm = new AesGcm(_blobKey, TagBytes))
                aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);

            var blob = new byte[NonceBytes + TagBytes + ciphertext.Length];
            nonce.CopyTo(blob, 0);
            tag.CopyTo(blob, NonceBytes);
            ciphertext.CopyTo(blob, NonceBytes + TagBytes);

            // Snapshot the current known-good state before overwriting.
            if (File.Exists(_vaultPath))
                File.Copy(_vaultPath, _backupPath, overwrite: true);

            await AtomicWriteAsync(_vaultPath, blob);
            RestrictPermissions(_vaultPath);
        }

        // ─── File helpers ─────────────────────────────────────────────────────

        private static async Task AtomicWriteAsync(string path, byte[] bytes)
        {
            var tmp = path + ".tmp";
            await File.WriteAllBytesAsync(tmp, bytes);
            // Move with overwrite is atomic on the same volume (ReplaceFile on Windows).
            File.Move(tmp, path, overwrite: true);
        }

        /// <summary>Best-effort: restrict the file to the current user. No-op on failure.</summary>
        private static void RestrictPermissions(string path)
        {
            try
            {
                if (!OperatingSystem.IsWindows())
                    File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                // On Windows the vault lives under the per-user AppData folder, whose ACL
                // already restricts access to the owning user.
            }
            catch { /* best effort — never fail a save over permissions */ }
        }

        /// <summary>Zeroizes the blob key so it does not linger in the managed heap.</summary>
        public void Dispose() => CryptographicOperations.ZeroMemory(_blobKey);
    }
}
