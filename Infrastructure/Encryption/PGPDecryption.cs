using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using System;
using System.Linq;
using System.IO;

namespace PasswordManager.Infrastructure.Encryption
{
    public class PgpDecryption
    {
        public static void DecryptFile(string inputFilePath, string outputFilePath, string privateKeyPath, string passphrase)
        {
            using (var privateKeyStream = File.OpenRead(privateKeyPath))
            using (var inputFileStream = File.OpenRead(inputFilePath))
            using (var outputFileStream = File.Create(outputFilePath))
            {
                var privateKey = PgpDecryptionHelper.ReadPrivateKey(privateKeyStream, passphrase);
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

        public static string DecryptString(string encryptedBase64Text, string privateKeyPath, string passphrase)
        {
            using (var privateKeyStream = File.OpenRead(privateKeyPath))
            using (var inputStream = new MemoryStream(Convert.FromBase64String(encryptedBase64Text)))
            {
                var privateKey = PgpDecryptionHelper.ReadPrivateKey(privateKeyStream, passphrase);
                var pgpObjectFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
                var pgpObject = pgpObjectFactory.NextPgpObject();
                var encryptedDataList = pgpObject is PgpEncryptedDataList dataList ? dataList : (PgpEncryptedDataList)pgpObjectFactory.NextPgpObject();

                var publicKeyEncryptedData = encryptedDataList.GetEncryptedDataObjects().OfType<PgpPublicKeyEncryptedData>().First();

                using (var clearStream = publicKeyEncryptedData.GetDataStream(privateKey))
                using (var streamReader = new StreamReader(clearStream))
                {
                    return streamReader.ReadToEnd();
                }
            }
        }
    }
}
