using System.Text;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using PasswordManager.Core.Exceptions;
using PasswordManager.Core.Interfaces;
using PasswordManager.Core.Models;

namespace PasswordManager.Infrastructure.Encryption
{
    public class PgpService : IPgpService
    {
        public byte[] EncryptBytes(byte[] data, string publicKeyPath) =>
            PgpOperations.EncryptBytes(data, publicKeyPath);

        public byte[] DecryptBytes(byte[] encryptedData, string privateKeyPath, string passphrase) =>
            PgpOperations.DecryptBytes(encryptedData, privateKeyPath, passphrase);

        public PgpKeyDetails InspectPublicKey(string armoredPublicKey)
        {
            using var stream = new MemoryStream(Encoding.UTF8.GetBytes(armoredPublicKey));
            return PgpKeyInspector.Inspect(stream);
        }

        public void GenerateKeyPair(string publicKeyPath, string privateKeyPath, string passphrase, string userId)
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
                userId,
                SymmetricKeyAlgorithmTag.Aes256,
                HashAlgorithmTag.Sha256,
                passphrase.ToCharArray(),
                true, null, null, rng);

            File.WriteAllBytes(publicKeyPath, ExportArmoredBytes(
                ms => keyRingGenerator.GeneratePublicKeyRing().Encode(ms)));

            File.WriteAllBytes(privateKeyPath, ExportArmoredBytes(
                ms => keyRingGenerator.GenerateSecretKeyRing().Encode(ms)));
        }

        public string ChangePrivateKeyPassphrase(
            string armoredPrivateKey, string oldPassphrase, string newPassphrase)
        {
            using var input = new MemoryStream(Encoding.UTF8.GetBytes(armoredPrivateKey));
            var bundle = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(input));

            var rings = bundle.GetKeyRings().Cast<PgpSecretKeyRing>().ToList();
            if (rings.Count == 0)
                throw new LocalizedArgumentException(AppErrorCode.NoPrivateKeyOrBadPassphrase);

            var rekeyed = new List<PgpSecretKeyRing>(rings.Count);
            foreach (var ring in rings)
            {
                try
                {
                    // Rewraps the secret material only. The key pair, its creation date and its
                    // fingerprint are untouched, so anything already encrypted to it still opens.
                    rekeyed.Add(PgpSecretKeyRing.CopyWithNewPassword(
                        ring,
                        oldPassphrase.ToCharArray(),
                        newPassphrase.ToCharArray(),
                        SymmetricKeyAlgorithmTag.Aes256,
                        new SecureRandom()));
                }
                catch (PgpException)
                {
                    // BouncyCastle reports a wrong passphrase this way; say what the user can act on.
                    throw new LocalizedArgumentException(AppErrorCode.NoPrivateKeyOrBadPassphrase);
                }
            }

            var bytes = ExportArmoredBytes(ms =>
            {
                foreach (var ring in rekeyed) ring.Encode(ms);
            });
            return Encoding.UTF8.GetString(bytes);
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
