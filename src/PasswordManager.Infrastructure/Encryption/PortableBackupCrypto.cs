using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using PasswordManager.Core.Exceptions;
using PasswordManager.Core.Interfaces;

namespace PasswordManager.Infrastructure.Encryption
{
    /// <summary>
    /// Seals a backup with a passphrase chosen at export time.
    ///
    /// <para>Deliberately the same envelope <see cref="VaultKeyRing"/> already uses for the vault
    /// key — Argon2id to derive a key from the passphrase, AES-256-GCM to encrypt, parameters
    /// stored alongside so they can be reproduced. Nothing here is a new cryptographic design;
    /// inventing one is where this kind of code goes wrong.</para>
    ///
    /// <para>Why not PGP, which the app already has: a backup encrypted to the device's own key
    /// can only be opened by that device. If the phone is lost, the key is lost with it and the
    /// backup is unreadable exactly when it is needed. A passphrase travels in the user's head.
    /// The vault itself is already built this way — its key is independent of any device — so
    /// this only extends that property to the file that leaves the app.</para>
    /// </summary>
    public class PortableBackupCrypto : IPortableBackupCrypto
    {
        private const int Version = 1;
        private const string Magic = "SafetyVaultBackup";
        private const int SaltBytes = 16;
        private const int NonceBytes = 12;
        private const int TagBytes = 16;
        private const int KeyBytes = 32;

        public byte[] Seal(byte[] plaintext, string passphrase)
        {
            if (string.IsNullOrWhiteSpace(passphrase))
                throw new LocalizedArgumentException(AppErrorCode.BackupPassphraseRequired);

            var salt = RandomNumberGenerator.GetBytes(SaltBytes);
            var key = Argon2idKdf.Derive(
                passphrase, salt, KeyBytes,
                Argon2idKdf.DefaultMemoryKib, Argon2idKdf.DefaultIterations, Argon2idKdf.DefaultParallelism);
            try
            {
                var nonce = RandomNumberGenerator.GetBytes(NonceBytes);
                var cipher = new byte[plaintext.Length];
                var tag = new byte[TagBytes];
                using (var aes = new AesGcm(key, TagBytes))
                    aes.Encrypt(nonce, plaintext, cipher, tag);

                var envelope = new Envelope(
                    Magic, Version, "argon2id",
                    Convert.ToBase64String(salt),
                    Argon2idKdf.DefaultMemoryKib,
                    Argon2idKdf.DefaultIterations,
                    Argon2idKdf.DefaultParallelism,
                    Convert.ToBase64String(nonce),
                    Convert.ToBase64String(cipher),
                    Convert.ToBase64String(tag));

                return JsonSerializer.SerializeToUtf8Bytes(envelope, JsonOptions);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }

        public byte[] Open(byte[] sealedData, string passphrase)
        {
            if (string.IsNullOrWhiteSpace(passphrase))
                throw new LocalizedArgumentException(AppErrorCode.BackupPassphraseRequired);

            var envelope = ReadEnvelope(sealedData)
                ?? throw new LocalizedArgumentException(AppErrorCode.BackupNotRecognised);

            // The parameters travel with the file rather than being assumed, so a backup written
            // today still opens if the defaults are raised later.
            var key = Argon2idKdf.Derive(
                passphrase, Convert.FromBase64String(envelope.Salt), KeyBytes,
                envelope.MemoryKib, envelope.Iterations, envelope.Parallelism);
            try
            {
                var cipher = Convert.FromBase64String(envelope.CipherText);
                var plain = new byte[cipher.Length];
                using var aes = new AesGcm(key, TagBytes);
                aes.Decrypt(
                    Convert.FromBase64String(envelope.Nonce),
                    cipher,
                    Convert.FromBase64String(envelope.Tag),
                    plain);
                return plain;
            }
            catch (Exception ex) when (ex is CryptographicException or FormatException or ArgumentException)
            {
                // A wrong passphrase and a modified file both fail the GCM tag, and the error must
                // not say which: distinguishing them would confirm a guessed passphrase.
                // FormatException joins them because damage heavy enough to break the base64 is
                // still just a file that will not open — it reached the user as the generic
                // "something went wrong" until a test corrupted a file badly enough to hit it.
                throw new LocalizedArgumentException(AppErrorCode.BackupCannotOpen);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }

        public bool IsSealed(byte[] data) => ReadEnvelope(data) is not null;

        private static Envelope? ReadEnvelope(byte[] data)
        {
            // Cheap rejection before parsing: the marker is near the front of anything we wrote.
            if (data.Length is < 32 or > 64 * 1024 * 1024) return null;

            var head = Encoding.UTF8.GetString(data, 0, Math.Min(data.Length, 128));
            if (!head.Contains(Magic, StringComparison.Ordinal)) return null;

            try
            {
                var envelope = JsonSerializer.Deserialize<Envelope>(data, JsonOptions);
                if (envelope is null || envelope.Format != Magic) return null;
                if (envelope.Version > Version) return null;   // written by a newer app
                if (string.IsNullOrEmpty(envelope.Salt) ||
                    string.IsNullOrEmpty(envelope.Nonce) ||
                    string.IsNullOrEmpty(envelope.Tag)) return null;
                return envelope;
            }
            catch (JsonException)
            {
                return null;
            }
        }

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        };

        private sealed record Envelope(
            string Format,
            int Version,
            string Kdf,
            string Salt,
            int MemoryKib,
            int Iterations,
            int Parallelism,
            string Nonce,
            string CipherText,
            string Tag);
    }
}
