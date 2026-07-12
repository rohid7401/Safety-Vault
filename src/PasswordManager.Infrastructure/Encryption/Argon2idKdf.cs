using System.Text;
using Konscious.Security.Cryptography;

namespace PasswordManager.Infrastructure.Encryption
{
    /// <summary>
    /// Memory-hard key derivation from a passphrase using Argon2id.
    /// Default parameters follow the OWASP recommendation (m = 19 MiB, t = 2, p = 1),
    /// which resists GPU/ASIC cracking far better than PBKDF2. Parameters are passed
    /// alongside the derived output so they can be stored and reproduced on verify.
    /// </summary>
    public static class Argon2idKdf
    {
        public const int DefaultMemoryKib = 19_456; // 19 MiB
        public const int DefaultIterations = 2;
        public const int DefaultParallelism = 1;

        public static byte[] Derive(
            string passphrase,
            byte[] salt,
            int outputBytes,
            int memoryKib = DefaultMemoryKib,
            int iterations = DefaultIterations,
            int parallelism = DefaultParallelism)
        {
            var passwordBytes = Encoding.UTF8.GetBytes(passphrase);
            try
            {
                using var argon2 = new Argon2id(passwordBytes)
                {
                    Salt = salt,
                    MemorySize = memoryKib,
                    Iterations = iterations,
                    DegreeOfParallelism = parallelism,
                };
                return argon2.GetBytes(outputBytes);
            }
            finally
            {
                // Best-effort: clear the transient UTF-8 copy of the passphrase.
                Array.Clear(passwordBytes, 0, passwordBytes.Length);
            }
        }
    }
}
