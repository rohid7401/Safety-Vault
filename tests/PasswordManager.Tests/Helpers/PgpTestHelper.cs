using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace PasswordManager.Tests.Helpers
{
    /// <summary>
    /// Generates a temporary PGP key pair on disk for integration tests.
    /// Dispose to clean up all temp files.
    /// </summary>
    public sealed class PgpTestFixture : IDisposable
    {
        public string PublicKeyPath { get; }
        public string PrivateKeyPath { get; }
        public string DataDir { get; }
        public const string Passphrase = "test-passphrase-123";

        private bool _disposed;

        public PgpTestFixture()
        {
            DataDir = Path.Combine(Path.GetTempPath(), "pmgr_test_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(DataDir);
            PublicKeyPath = Path.Combine(DataDir, "public_key.asc");
            PrivateKeyPath = Path.Combine(DataDir, "private_key.asc");
            GenerateKeyPair();
        }

        private void GenerateKeyPair()
        {
            var rng = new SecureRandom();
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(new RsaKeyGenerationParameters(
                BigInteger.ValueOf(0x10001), rng, 2048, 25));
            var keyPair = keyPairGenerator.GenerateKeyPair();

            var pgpKeyPair = new PgpKeyPair(PublicKeyAlgorithmTag.RsaGeneral, keyPair, DateTime.UtcNow);

            var keyRingGenerator = new PgpKeyRingGenerator(
                PgpSignature.DefaultCertification,
                pgpKeyPair,
                "test@test.local",
                SymmetricKeyAlgorithmTag.Aes256,
                HashAlgorithmTag.Sha256,
                Passphrase.ToCharArray(),
                true,
                null,
                null,
                rng);

            // Write to MemoryStream first to avoid leaving file handles open
            // (ArmoredOutputStream wrapping FileStream can hold the handle until GC)
            File.WriteAllBytes(PublicKeyPath, ExportArmoredBytes(
                ms => keyRingGenerator.GeneratePublicKeyRing().Encode(ms)));

            File.WriteAllBytes(PrivateKeyPath, ExportArmoredBytes(
                ms => keyRingGenerator.GenerateSecretKeyRing().Encode(ms)));
        }

        private static byte[] ExportArmoredBytes(Action<ArmoredOutputStream> encode)
        {
            using var ms = new MemoryStream();
            using var armor = new ArmoredOutputStream(ms);
            encode(armor);
            armor.Close(); // flush armor end marker before reading ms
            return ms.ToArray();
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            try { Directory.Delete(DataDir, recursive: true); } catch { /* best effort */ }
        }
    }
}
