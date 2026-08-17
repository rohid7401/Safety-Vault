using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace PasswordManager.Infrastructure.Encryption
{
    /// <summary>How the vault key is unwrapped by a quick-unlock slot.</summary>
    public enum QuickUnlockMethod
    {
        /// <summary>A fingerprint or face releases a hardware-held secret; there is no PIN.</summary>
        Biometric,

        /// <summary>A short PIN, mixed with that same hardware-held secret.</summary>
        Pin,
    }

    /// <summary>What happened when a slot was opened, so the caller can say something true.</summary>
    public enum QuickUnlockResult
    {
        Success,

        /// <summary>No slot enrolled on this device.</summary>
        NotEnrolled,

        /// <summary>Wrong PIN, or a hardware secret that no longer matches. Attempts remain.</summary>
        Wrong,

        /// <summary>Too many failures: the slot is gone and only the passphrase is left.</summary>
        Exhausted,
    }

    /// <summary>
    /// A second way into the same vault, alongside the master passphrase.
    ///
    /// <para>This works at all because the Vault Key is independent of the passphrase: the keyring
    /// wraps VK under a passphrase-derived KEK, and nothing stops a second wrapping of the very
    /// same VK under a different key. That is all a slot is — the standard multiple-key-slot
    /// design, and the reason none of this required touching how the vault is encrypted.</para>
    ///
    /// <para><b>A PIN alone would destroy the app's security.</b> Four digits are ten thousand
    /// possibilities and Argon2id cannot fix that: anyone who copies the vault file tries them all
    /// in seconds. What makes it safe is that the slot key is derived from the PIN <em>and</em> a
    /// secret held in the phone's secure hardware that cannot be exported from it. Without the
    /// device an attacker cannot test even one guess; with the device the attempt limit below is
    /// the barrier. That is why banks can afford four digits.</para>
    ///
    /// <para>Deliberately its own file rather than another field in <c>vault.keyring.json</c>.
    /// That file is the only guaranteed way in, and enrolling — or wiping — a convenience feature
    /// must never rewrite it.</para>
    /// </summary>
    public static class QuickUnlockSlot
    {
        public const int MaxAttempts = 5;

        private const int SlotVersion = 1;
        private const int SaltBytes = 16;
        private const int NonceBytes = 12;
        private const int TagBytes = 16;
        private const int KeyBytes = 32;

        private const string BiometricInfo = "SafetyVault:quick-unlock:biometric:v1";
        private const string PinInfo = "SafetyVault:quick-unlock:pin:v1";

        private static string SlotPath(string vaultFolder) =>
            Path.Combine(vaultFolder, "vault.quickunlock.json");

        public static bool IsEnrolled(string vaultFolder) => File.Exists(SlotPath(vaultFolder));

        /// <summary>The method a slot uses, or null when there is no slot.</summary>
        public static QuickUnlockMethod? EnrolledMethod(string vaultFolder)
        {
            var record = TryRead(vaultFolder);
            return record is null ? null : record.Method;
        }

        /// <summary>Failed attempts left before the slot destroys itself.</summary>
        public static int AttemptsLeft(string vaultFolder)
        {
            var record = TryRead(vaultFolder);
            return record is null ? 0 : Math.Max(0, MaxAttempts - record.Failures);
        }

        /// <summary>
        /// Wraps the vault key under a slot. The caller has to have unlocked with the passphrase
        /// first to hold <paramref name="vaultKey"/> at all, which is the point: enrolling is
        /// something only someone already inside can do.
        /// </summary>
        /// <param name="hardwareSecret">
        /// Bytes the platform will only hand back on this device — for biometrics, only after the
        /// user authenticates. Everything rests on this not being exportable.
        /// </param>
        /// <param name="pin">Required for <see cref="QuickUnlockMethod.Pin"/>, ignored otherwise.</param>
        public static void Enroll(string vaultFolder, byte[] vaultKey, QuickUnlockMethod method,
                                  byte[] hardwareSecret, string? pin = null)
        {
            if (vaultKey is null || vaultKey.Length != KeyBytes)
                throw new ArgumentException("A 256-bit vault key is required.", nameof(vaultKey));
            if (hardwareSecret is null || hardwareSecret.Length == 0)
                throw new ArgumentException("A hardware-held secret is required.", nameof(hardwareSecret));
            if (method == QuickUnlockMethod.Pin && string.IsNullOrEmpty(pin))
                throw new ArgumentException("A PIN slot needs a PIN.", nameof(pin));

            var salt = RandomNumberGenerator.GetBytes(SaltBytes);
            var slotKey = DeriveSlotKey(method, hardwareSecret, salt, pin);
            try
            {
                var nonce = RandomNumberGenerator.GetBytes(NonceBytes);
                var wrapped = new byte[KeyBytes];
                var tag = new byte[TagBytes];
                using (var aes = new AesGcm(slotKey, TagBytes))
                    aes.Encrypt(nonce, vaultKey, wrapped, tag);

                Write(vaultFolder, new SlotRecord(
                    SlotVersion, method,
                    Convert.ToBase64String(salt),
                    Convert.ToBase64String(nonce),
                    Convert.ToBase64String(wrapped),
                    Convert.ToBase64String(tag),
                    Failures: 0));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(slotKey);
            }
        }

        /// <summary>
        /// Unwraps the vault key, or says why it could not.
        /// </summary>
        /// <remarks>
        /// The failure count is written <em>before</em> the attempt and cleared only on success.
        /// Counting afterwards would let anyone reset it by killing the app between the guess and
        /// the write, which is the whole attack this limit exists to stop.
        /// </remarks>
        public static QuickUnlockResult TryUnlock(string vaultFolder, byte[] hardwareSecret,
                                                  string? pin, out byte[] vaultKey)
        {
            vaultKey = Array.Empty<byte>();

            var record = TryRead(vaultFolder);
            if (record is null) return QuickUnlockResult.NotEnrolled;

            if (record.Failures >= MaxAttempts)
            {
                Destroy(vaultFolder);
                return QuickUnlockResult.Exhausted;
            }

            Write(vaultFolder, record with { Failures = record.Failures + 1 });

            var salt = Convert.FromBase64String(record.Salt);
            var slotKey = DeriveSlotKey(record.Method, hardwareSecret, salt, pin);
            try
            {
                var opened = new byte[KeyBytes];
                using var aes = new AesGcm(slotKey, TagBytes);
                try
                {
                    aes.Decrypt(Convert.FromBase64String(record.Nonce),
                                Convert.FromBase64String(record.CipherText),
                                Convert.FromBase64String(record.Tag),
                                opened);
                }
                catch (CryptographicException)
                {
                    CryptographicOperations.ZeroMemory(opened);
                    // The one just written is the count that matters.
                    if (record.Failures + 1 >= MaxAttempts)
                    {
                        Destroy(vaultFolder);
                        return QuickUnlockResult.Exhausted;
                    }
                    return QuickUnlockResult.Wrong;
                }

                Write(vaultFolder, record with { Failures = 0 });
                vaultKey = opened;
                return QuickUnlockResult.Success;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(slotKey);
            }
        }

        /// <summary>
        /// Removes the slot. Called when the user turns the feature off, when the attempt limit
        /// runs out, and by the platform when the enrolled fingerprints change — a new finger
        /// added to the phone must not inherit the old finger's way in.
        /// </summary>
        public static void Destroy(string vaultFolder)
        {
            try { File.Delete(SlotPath(vaultFolder)); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        /// <summary>
        /// Binds both factors. For a PIN the material is the hardware secret concatenated with an
        /// Argon2id stretch of the PIN, so neither alone opens anything: the device without the
        /// PIN gets nothing, and the PIN without the device gets nothing.
        /// </summary>
        private static byte[] DeriveSlotKey(QuickUnlockMethod method, byte[] hardwareSecret,
                                            byte[] salt, string? pin)
        {
            if (method == QuickUnlockMethod.Biometric)
                return HKDF.DeriveKey(HashAlgorithmName.SHA256, hardwareSecret, KeyBytes, salt,
                                      Encoding.UTF8.GetBytes(BiometricInfo));

            // Argon2id over four digits buys very little on its own — that is what the hardware
            // secret is for — but it costs one call and is the difference between "useless" and
            // "slow" if that secret ever leaks.
            var stretched = Argon2idKdf.Derive(
                pin ?? string.Empty, salt, KeyBytes,
                Argon2idKdf.DefaultMemoryKib, Argon2idKdf.DefaultIterations, Argon2idKdf.DefaultParallelism);
            try
            {
                var material = new byte[hardwareSecret.Length + stretched.Length];
                Buffer.BlockCopy(hardwareSecret, 0, material, 0, hardwareSecret.Length);
                Buffer.BlockCopy(stretched, 0, material, hardwareSecret.Length, stretched.Length);
                try
                {
                    return HKDF.DeriveKey(HashAlgorithmName.SHA256, material, KeyBytes, salt,
                                          Encoding.UTF8.GetBytes(PinInfo));
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(material);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(stretched);
            }
        }

        private static SlotRecord? TryRead(string vaultFolder)
        {
            var path = SlotPath(vaultFolder);
            if (!File.Exists(path)) return null;
            try
            {
                return JsonSerializer.Deserialize<SlotRecord>(File.ReadAllBytes(path));
            }
            catch (JsonException)
            {
                // Unreadable is treated as absent rather than as an error: the passphrase still
                // works, and refusing to start over a broken convenience file would be worse
                // than quietly losing the convenience.
                return null;
            }
            catch (IOException)
            {
                return null;
            }
        }

        private static void Write(string vaultFolder, SlotRecord record) =>
            File.WriteAllBytes(SlotPath(vaultFolder), JsonSerializer.SerializeToUtf8Bytes(record));

        private sealed record SlotRecord(
            int Version, QuickUnlockMethod Method, string Salt,
            string Nonce, string CipherText, string Tag, int Failures);
    }
}
