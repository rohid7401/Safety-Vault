using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using System.IO;

namespace PasswordManager.Infrastructure.Encryption
{
    public static class PgpEncryptionHelper
    {
        public static PgpPublicKey ReadPublicKey(Stream inputStream)
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
