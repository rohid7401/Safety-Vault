using System.Text;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace PasswordManager.Infrastructure.Encryption
{
    /// <summary>Low-level PGP encrypt/decrypt operations working entirely in memory.</summary>
    internal static class PgpOperations
    {
        internal static byte[] EncryptBytes(byte[] data, string publicKeyPath)
        {
            using var publicKeyStream = File.OpenRead(publicKeyPath);
            var publicKey = PgpEncryptionHelper.ReadPublicKey(publicKeyStream);

            using var outputStream = new MemoryStream();
            var generator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, withIntegrityPacket: true);
            generator.AddMethod(publicKey);

            // Wrap data in a literal data packet inside the encrypted stream
            using var literalOut = new MemoryStream();
            var literalGenerator = new PgpLiteralDataGenerator();
            using (var literalStream = literalGenerator.Open(literalOut, PgpLiteralData.Binary, "vault", data.Length, DateTime.UtcNow))
                literalStream.Write(data, 0, data.Length);

            var literalBytes = literalOut.ToArray();

            using (var encryptedStream = generator.Open(outputStream, literalBytes.Length))
                encryptedStream.Write(literalBytes, 0, literalBytes.Length);

            return outputStream.ToArray();
        }

        internal static byte[] DecryptBytes(byte[] encryptedData, string privateKeyPath, string passphrase)
        {
            using var privateKeyStream = File.OpenRead(privateKeyPath);
            var privateKey = PgpDecryptionHelper.ReadPrivateKey(privateKeyStream, passphrase);

            using var inputStream = new MemoryStream(encryptedData);
            var pgpFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
            var pgpObject = pgpFactory.NextPgpObject();

            var encryptedDataList = pgpObject is PgpEncryptedDataList list
                ? list
                : (PgpEncryptedDataList)pgpFactory.NextPgpObject();

            var publicKeyData = encryptedDataList.GetEncryptedDataObjects()
                .OfType<PgpPublicKeyEncryptedData>()
                .First();

            using var clearStream = publicKeyData.GetDataStream(privateKey);
            var plainFactory = new PgpObjectFactory(clearStream);
            var plainObject = plainFactory.NextPgpObject();

            if (plainObject is PgpLiteralData literalData)
            {
                using var result = new MemoryStream();
                literalData.GetInputStream().CopyTo(result);
                return result.ToArray();
            }

            // Fallback: raw bytes (for backward compatibility)
            using var fallback = new MemoryStream();
            clearStream.CopyTo(fallback);
            return fallback.ToArray();
        }

        internal static string EncryptString(string plainText, string publicKeyPath)
        {
            var data = Encoding.UTF8.GetBytes(plainText);
            var encrypted = EncryptBytes(data, publicKeyPath);
            return Convert.ToBase64String(encrypted);
        }

        internal static string DecryptString(string encryptedBase64, string privateKeyPath, string passphrase)
        {
            var encrypted = Convert.FromBase64String(encryptedBase64);
            var data = DecryptBytes(encrypted, privateKeyPath, passphrase);
            return Encoding.UTF8.GetString(data);
        }
    }
}
