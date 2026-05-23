using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using PasswordManager.Core.Interfaces;

namespace PasswordManager.Infrastructure.Encryption
{
    public class PgpService : IPgpService
    {
        public byte[] EncryptBytes(byte[] data, string publicKeyPath) =>
            PgpOperations.EncryptBytes(data, publicKeyPath);

        public byte[] DecryptBytes(byte[] encryptedData, string privateKeyPath, string passphrase) =>
            PgpOperations.DecryptBytes(encryptedData, privateKeyPath, passphrase);

        public string EncryptString(string plainText, string publicKeyPath) =>
            PgpOperations.EncryptString(plainText, publicKeyPath);

        public string DecryptString(string encryptedBase64, string privateKeyPath, string passphrase) =>
            PgpOperations.DecryptString(encryptedBase64, privateKeyPath, passphrase);

        public void GenerateKeyPair(string publicKeyPath, string privateKeyPath, string passphrase)
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
                "vault@securevault.local",
                SymmetricKeyAlgorithmTag.Aes256,
                HashAlgorithmTag.Sha256,
                passphrase.ToCharArray(),
                true, null, null, rng);

            File.WriteAllBytes(publicKeyPath, ExportArmoredBytes(
                ms => keyRingGenerator.GeneratePublicKeyRing().Encode(ms)));

            File.WriteAllBytes(privateKeyPath, ExportArmoredBytes(
                ms => keyRingGenerator.GenerateSecretKeyRing().Encode(ms)));
        }

        private static byte[] ExportArmoredBytes(Action<ArmoredOutputStream> encode)
        {
            using var ms = new MemoryStream();
            using var armor = new ArmoredOutputStream(ms);
            encode(armor);
            armor.Close();
            return ms.ToArray();
        }
    }
}
