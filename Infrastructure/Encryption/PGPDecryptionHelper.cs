using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using System.IO;

namespace PasswordManager.Infrastructure.Encryption
{
    public static class PgpDecryptionHelper
    {
        public static PgpPrivateKey ReadPrivateKey(Stream inputStream, string passphrase)
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
