using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;


namespace PasswordManager.Infrastructure.Encryption
{
    internal class PgpEncryption
    {
        public static void EncryptFile(string inputFilePath, string outputFilePath, string publicKeyPath)
        {
            using (var publicKeyStream = File.OpenRead(publicKeyPath))
            using (var inputFileStream = File.OpenRead(inputFilePath))
            using (var outputFileStream = File.Create(outputFilePath))
            {
                var publicKey = ReadPublicKey(publicKeyStream);
                var encryptedDataGenerator = new PgpEncryptedDataGenerator(PgpEncryptedData.CipherAes256);
                encryptedDataGenerator.AddMethod(publicKey);

                using (var encryptedStream = encryptedDataGenerator.Open(outputFileStream, new byte[4096]))
                {
                    inputFileStream.CopyTo(encryptedStream);
                }
            }
        }

        private static PgpPublicKey ReadPublicKey(Stream inputStream)
        {
            var publicKeyRingBundle = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(inputStream));
            foreach (PgpPublicKeyRing keyRing in publicKeyRingBundle.GetKeyRings())
            {
                foreach (PgpPublicKey key in keyRing.GetPublicKeys())
                {
                    if (key.IsEncryptionKey)
                    {
                        return key;
                    }
                }
            }
            throw new ArgumentException("No encryption key found in the public key file.");
        }
    }
}
