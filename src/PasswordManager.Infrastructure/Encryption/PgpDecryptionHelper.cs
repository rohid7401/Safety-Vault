using Org.BouncyCastle.Bcpg.OpenPgp;

namespace PasswordManager.Infrastructure.Encryption
{
    internal static class PgpDecryptionHelper
    {
        internal static PgpPrivateKey ReadPrivateKey(Stream inputStream, string passphrase)
        {
            var bundle = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(inputStream));
            foreach (PgpSecretKeyRing ring in bundle.GetKeyRings())
            {
                foreach (PgpSecretKey secretKey in ring.GetSecretKeys())
                {
                    var privateKey = secretKey.ExtractPrivateKey(passphrase.ToCharArray());
                    if (privateKey != null)
                        return privateKey;
                }
            }
            throw new ArgumentException("No private key found or incorrect passphrase.");
        }
    }
}
