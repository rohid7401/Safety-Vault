using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using System.IO;

namespace PasswordManager.Infrastructure.Encryption
{
    internal class PgpDecryption
    {
        public static void DecryptFile(string inputFilePath, string outputFilePath, string privateKeyPath, string passphrase)
        {
            using (var privateKeyStream = File.OpenRead(privateKeyPath))
            using (var inputFileStream = File.OpenRead(inputFilePath))
            using (var outputFileStream = File.Create(outputFilePath))
            {
                var privateKey = ReadPrivateKey(privateKeyStream, passphrase);
                var pgpObjectFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputFileStream));
                var encryptedDataList = (PgpEncryptedDataList)pgpObjectFactory.NextPgpObject();

                foreach (PgpEncryptedData encryptedData in encryptedDataList.GetEncryptedDataObjects())
                {
                    if (encryptedData is PgpPublicKeyEncryptedData publicKeyEncryptedData)
                    {
                        using (var clearStream = publicKeyEncryptedData.GetDataStream(privateKey))
                        {
                            clearStream.CopyTo(outputFileStream);
                        }
                    }
                }
            }
        }

        private static PgpPrivateKey ReadPrivateKey(Stream inputStream, string passphrase)
        {
            var secretKeyRingBundle = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(inputStream));
            foreach (PgpSecretKeyRing keyRing in secretKeyRingBundle.GetKeyRings())
            {
                foreach (PgpSecretKey secretKey in keyRing.GetSecretKeys())
                {
                    var privateKey = secretKey.ExtractPrivateKey(passphrase.ToCharArray());
                    if (privateKey != null)
                    {
                        return privateKey;
                    }
                }
            }
            throw new ArgumentException("No private key found or incorrect passphrase.");
        }
    }
}

