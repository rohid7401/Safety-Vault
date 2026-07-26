using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PasswordManager.Core.Exceptions;

namespace PasswordManager.Infrastructure.Encryption
{
    /// <summary>
    /// Envelope encryption for the vault's root key (the "Vault Key", VK):
    ///  - a Key-Encryption-Key (KEK) is derived from the master passphrase with Argon2id;
    ///  - a random 256-bit VK is generated once, at registration, and never changes;
    ///  - the KEK wraps (AES-256-GCM) the VK, stored in <c>vault.keyring.json</c>.
    /// Unlocking re-derives the KEK from the passphrase and unwraps VK — the AES-GCM
    /// authentication tag is what proves the passphrase is correct (no separate password
    /// hash exists anywhere).
    ///
    /// Because VK is independent of the passphrase, any device that knows the passphrase
    /// can re-derive access to the same vault: nothing device-specific needs to be
    /// synchronized. Two purpose-bound subkeys are then derived from VK with HKDF so the
    /// vault blob and individual field values never reuse key material for different
    /// purposes.
    /// </summary>
    public static class VaultKeyRing
    {
        public const int VaultKeyBytes = 32;
        private const int SaltBytes = 16;
        private const int NonceBytes = 12;
        private const int TagBytes = 16;
        private const string KdfId = "argon2id";
        private const int KeyringVersion = 1;

        public const string BlobKeyInfo = "SecureVault:vault-blob:v1";
        public const string FieldKeyInfo = "SecureVault:field:v1";

        private static string KeyringPath(string vaultFolder) => Path.Combine(vaultFolder, "vault.keyring.json");

        /// <summary>Generates a fresh Vault Key and wraps it with a passphrase-derived KEK. Call once, at registration.</summary>
        public static byte[] Create(string vaultFolder, string passphrase)
        {
            var vaultKey = RandomNumberGenerator.GetBytes(VaultKeyBytes);
            try
            {
                var salt = RandomNumberGenerator.GetBytes(SaltBytes);
                var kek = Argon2idKdf.Derive(
                    passphrase, salt, VaultKeyBytes,
                    Argon2idKdf.DefaultMemoryKib, Argon2idKdf.DefaultIterations, Argon2idKdf.DefaultParallelism);
                try
                {
                    var nonce = RandomNumberGenerator.GetBytes(NonceBytes);
                    var wrapped = new byte[VaultKeyBytes];
                    var tag = new byte[TagBytes];
                    using (var aesGcm = new AesGcm(kek, TagBytes))
                        aesGcm.Encrypt(nonce, vaultKey, wrapped, tag);

                    var record = new KeyringRecord(
                        KeyringVersion, KdfId,
                        Convert.ToBase64String(salt),
                        Argon2idKdf.DefaultMemoryKib, Argon2idKdf.DefaultIterations, Argon2idKdf.DefaultParallelism,
                        Convert.ToBase64String(nonce),
                        Convert.ToBase64String(wrapped),
                        Convert.ToBase64String(tag));

                    File.WriteAllBytes(KeyringPath(vaultFolder), JsonSerializer.SerializeToUtf8Bytes(record));
                    return (byte[])vaultKey.Clone();
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(kek);
                }
            }
            catch
            {
                CryptographicOperations.ZeroMemory(vaultKey);
                throw;
            }
        }

        /// <summary>Re-derives the KEK from the passphrase and unwraps the Vault Key.</summary>
        /// <exception cref="FileNotFoundException">No keyring exists at this path yet.</exception>
        /// <exception cref="UnauthorizedAccessException">The passphrase is wrong (or the keyring is corrupt/tampered).</exception>
        public static byte[] Unlock(string vaultFolder, string passphrase)
        {
            var path = KeyringPath(vaultFolder);
            if (!File.Exists(path))
                throw new FileNotFoundException("No vault keyring found for this account.", path);

            KeyringRecord record;
            try
            {
                record = JsonSerializer.Deserialize<KeyringRecord>(File.ReadAllBytes(path))
                    ?? throw new LocalizedUnauthorizedAccessException(AppErrorCode.KeyringUnreadable);
            }
            catch (JsonException ex)
            {
                throw new LocalizedUnauthorizedAccessException(AppErrorCode.KeyringCorrupt, ex);
            }

            if (!string.Equals(record.Kdf, KdfId, StringComparison.Ordinal))
                throw new LocalizedUnauthorizedAccessException(AppErrorCode.UnsupportedKdf, record.Kdf);

            var salt = Convert.FromBase64String(record.KdfSalt);
            var kek = Argon2idKdf.Derive(passphrase, salt, VaultKeyBytes, record.MemoryKib, record.Iterations, record.Parallelism);
            try
            {
                var nonce = Convert.FromBase64String(record.WrappedKeyNonce);
                var wrapped = Convert.FromBase64String(record.WrappedKeyCipherText);
                var tag = Convert.FromBase64String(record.WrappedKeyTag);
                var vaultKey = new byte[VaultKeyBytes];

                using var aesGcm = new AesGcm(kek, TagBytes);
                try
                {
                    aesGcm.Decrypt(nonce, wrapped, tag, vaultKey);
                }
                catch (CryptographicException ex)
                {
                    throw new LocalizedUnauthorizedAccessException(AppErrorCode.BadCredentials, ex);
                }

                return vaultKey;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(kek);
            }
        }

        /// <summary>True if the passphrase successfully unlocks the vault keyring at this path.</summary>
        public static bool CanUnlock(string vaultFolder, string passphrase)
        {
            try
            {
                var vk = Unlock(vaultFolder, passphrase);
                CryptographicOperations.ZeroMemory(vk);
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Runs one Argon2id derivation with the default parameters and discards it. Called on
        /// the "no such account" login path so its response time matches a real unlock attempt
        /// (which always pays the Argon2id cost) — an attacker cannot then distinguish "account
        /// does not exist" from "wrong passphrase" by timing. The Argon2id cost dominates the
        /// real path, so equalizing it is what matters.
        /// </summary>
        public static void PerformDummyUnlock(string passphrase)
        {
            var salt = new byte[SaltBytes]; // value irrelevant — only the work matters
            var kek = Argon2idKdf.Derive(
                passphrase, salt, VaultKeyBytes,
                Argon2idKdf.DefaultMemoryKib, Argon2idKdf.DefaultIterations, Argon2idKdf.DefaultParallelism);
            CryptographicOperations.ZeroMemory(kek);
        }

        /// <summary>Derives a purpose-bound 256-bit subkey from the Vault Key via HKDF-Expand.</summary>
        public static byte[] DeriveSubkey(byte[] vaultKey, string info) =>
            HKDF.Expand(HashAlgorithmName.SHA256, vaultKey, VaultKeyBytes, Encoding.UTF8.GetBytes(info));

        private sealed record KeyringRecord(
            int Version, string Kdf, string KdfSalt,
            int MemoryKib, int Iterations, int Parallelism,
            string WrappedKeyNonce, string WrappedKeyCipherText, string WrappedKeyTag);
    }
}
