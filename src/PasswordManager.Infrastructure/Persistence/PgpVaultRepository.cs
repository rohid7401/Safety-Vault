using System.Security.Cryptography;
using System.Text.Json;
using PasswordManager.Core.Configuration;
using PasswordManager.Core.Exceptions;
using PasswordManager.Core.Interfaces;
using PasswordManager.Core.Models;
using PasswordManager.Infrastructure.Encryption;

namespace PasswordManager.Infrastructure.Persistence
{
    /// <summary>
    /// Persists the vault as a PGP-encrypted blob, protected by:
    ///  - an HMAC-SHA256 authentication tag over the ciphertext (integrity / anti-tamper),
    ///    keyed by an Argon2id-derived MAC key so a forged-but-validly-encrypted vault is rejected;
    ///  - atomic writes (temp file + move) so a crash never leaves a half-written vault;
    ///  - a rotating backup of the last known-good state for recovery.
    /// The integrity sidecar is self-describing: it stores the KDF id and parameters used,
    /// so future parameter changes remain backward-compatible on load.
    /// </summary>
    public class PgpVaultRepository : IVaultRepository, IDisposable
    {
        private const string KdfId = "argon2id";
        private const int MacKeyBytes = 32;
        private const int SaltBytes = 16;
        private const int IntegrityVersion = 2;

        private readonly IPgpService _pgpService;
        private readonly string _dataFolder;
        private readonly string _vaultPath;
        private readonly string _backupPath;
        private readonly string _integrityPath;
        private readonly string _integrityBackupPath;
        private readonly string _publicKeyPath;
        private readonly string _privateKeyPath;
        private readonly string _passphrase;

        // Cached per session so the KDF runs at most once, not on every load/save.
        private byte[]? _macKey;
        private byte[]? _kdfSalt;

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            WriteIndented = true
        };

        public PgpVaultRepository(IPgpService pgpService, VaultOptions options)
        {
            _pgpService = pgpService;
            _dataFolder = options.DataFolderPath;
            _vaultPath = Path.Combine(_dataFolder, "vault.data.pgp");
            _backupPath = _vaultPath + ".bak";
            _integrityPath = Path.Combine(_dataFolder, "vault.integrity.json");
            _integrityBackupPath = _integrityPath + ".bak";
            _publicKeyPath = options.ResolvedPublicKeyPath;
            _privateKeyPath = options.ResolvedPrivateKeyPath;
            _passphrase = options.Passphrase;
        }

        // ─── Load ────────────────────────────────────────────────────────────

        public async Task<VaultData> LoadAsync()
        {
            if (!File.Exists(_vaultPath))
                return new VaultData();

            return await LoadVerifiedAsync(_vaultPath, _integrityPath, HasBackup());
        }

        public bool HasBackup() =>
            File.Exists(_backupPath) && File.Exists(_integrityBackupPath);

        public async Task<VaultData> RestoreFromBackupAsync()
        {
            if (!HasBackup())
                throw new VaultIntegrityException("No backup is available to restore from.");

            // Verify the backup BEFORE overwriting the live vault.
            var restored = await LoadVerifiedAsync(_backupPath, _integrityBackupPath, backupAvailable: false);

            File.Copy(_backupPath, _vaultPath, overwrite: true);
            File.Copy(_integrityBackupPath, _integrityPath, overwrite: true);
            RestrictPermissions(_vaultPath);
            RestrictPermissions(_integrityPath);

            return restored;
        }

        private async Task<VaultData> LoadVerifiedAsync(string vaultPath, string integrityPath, bool backupAvailable)
        {
            var ciphertext = await File.ReadAllBytesAsync(vaultPath);

            if (!File.Exists(integrityPath))
                throw new VaultIntegrityException(
                    "Vault integrity metadata is missing. The file may have been tampered with.",
                    backupAvailable);

            IntegrityMetadata meta;
            try
            {
                var metaJson = await File.ReadAllTextAsync(integrityPath);
                meta = JsonSerializer.Deserialize<IntegrityMetadata>(metaJson)
                       ?? throw new VaultIntegrityException("Vault integrity metadata is unreadable.", backupAvailable);
            }
            catch (JsonException ex)
            {
                throw new VaultIntegrityException("Vault integrity metadata is corrupt.", ex, backupAvailable);
            }

            if (!string.Equals(meta.Kdf, KdfId, StringComparison.Ordinal))
                throw new VaultIntegrityException(
                    $"Unsupported key-derivation function '{meta.Kdf}'.", backupAvailable);

            var salt = Convert.FromBase64String(meta.KdfSalt);
            var macKey = GetMacKey(salt, meta.MemoryKib, meta.Iterations, meta.Parallelism);
            var expectedMac = Convert.FromBase64String(meta.Mac);
            var actualMac = ComputeMac(macKey, ciphertext);

            if (!CryptographicOperations.FixedTimeEquals(expectedMac, actualMac))
                throw new VaultIntegrityException(
                    "Vault authentication failed — the file has been modified or replaced.",
                    backupAvailable);

            byte[] jsonBytes;
            try
            {
                jsonBytes = _pgpService.DecryptBytes(ciphertext, _privateKeyPath, _passphrase);
            }
            catch (Exception ex)
            {
                throw new VaultIntegrityException("Vault could not be decrypted.", ex, backupAvailable);
            }

            try
            {
                return JsonSerializer.Deserialize<VaultData>(jsonBytes, JsonOptions) ?? new VaultData();
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

            var jsonBytes = JsonSerializer.SerializeToUtf8Bytes(vault, JsonOptions);
            var ciphertext = _pgpService.EncryptBytes(jsonBytes, _publicKeyPath);

            var salt = EnsureSalt();
            var macKey = GetMacKey(
                salt,
                Argon2idKdf.DefaultMemoryKib,
                Argon2idKdf.DefaultIterations,
                Argon2idKdf.DefaultParallelism);
            var mac = ComputeMac(macKey, ciphertext);

            var meta = new IntegrityMetadata(
                IntegrityVersion,
                KdfId,
                Convert.ToBase64String(salt),
                Argon2idKdf.DefaultMemoryKib,
                Argon2idKdf.DefaultIterations,
                Argon2idKdf.DefaultParallelism,
                Convert.ToBase64String(mac));
            var metaJson = JsonSerializer.SerializeToUtf8Bytes(meta, JsonOptions);

            // Snapshot the current known-good state before overwriting.
            if (File.Exists(_vaultPath) && File.Exists(_integrityPath))
            {
                File.Copy(_vaultPath, _backupPath, overwrite: true);
                File.Copy(_integrityPath, _integrityBackupPath, overwrite: true);
            }

            await AtomicWriteAsync(_vaultPath, ciphertext);
            await AtomicWriteAsync(_integrityPath, metaJson);

            RestrictPermissions(_vaultPath);
            RestrictPermissions(_integrityPath);
        }

        // ─── Crypto / integrity helpers ───────────────────────────────────────

        private byte[] EnsureSalt()
        {
            if (_kdfSalt is not null)
                return _kdfSalt;

            // Reuse the salt of an existing vault so the MAC key stays stable across saves.
            if (File.Exists(_integrityPath))
            {
                try
                {
                    var existing = JsonSerializer.Deserialize<IntegrityMetadata>(
                        File.ReadAllText(_integrityPath));
                    if (existing is not null && !string.IsNullOrEmpty(existing.KdfSalt))
                    {
                        _kdfSalt = Convert.FromBase64String(existing.KdfSalt);
                        return _kdfSalt;
                    }
                }
                catch { /* fall through and generate a fresh salt */ }
            }

            _kdfSalt = RandomNumberGenerator.GetBytes(SaltBytes);
            return _kdfSalt;
        }

        private byte[] GetMacKey(byte[] salt, int memoryKib, int iterations, int parallelism)
        {
            if (_macKey is not null && _kdfSalt is not null &&
                CryptographicOperations.FixedTimeEquals(_kdfSalt, salt))
                return _macKey;

            _kdfSalt = salt;
            _macKey = Argon2idKdf.Derive(_passphrase, salt, MacKeyBytes, memoryKib, iterations, parallelism);
            return _macKey;
        }

        private static byte[] ComputeMac(byte[] macKey, byte[] ciphertext)
        {
            using var hmac = new HMACSHA256(macKey);
            return hmac.ComputeHash(ciphertext);
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

        private sealed record IntegrityMetadata(
            int Version, string Kdf, string KdfSalt,
            int MemoryKib, int Iterations, int Parallelism, string Mac);

        /// <summary>Zeroizes the cached MAC key so it does not linger in the managed heap.</summary>
        public void Dispose()
        {
            if (_macKey is not null)
            {
                CryptographicOperations.ZeroMemory(_macKey);
                _macKey = null;
            }
        }
    }
}
