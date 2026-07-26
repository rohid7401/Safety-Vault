using Org.BouncyCastle.Bcpg.OpenPgp;
using PasswordManager.Core.Exceptions;

namespace PasswordManager.Infrastructure.Encryption
{
    internal static class PgpEncryptionHelper
    {
        internal static PgpPublicKey ReadPublicKey(Stream inputStream)
        {
            var bundle = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(inputStream));
            foreach (PgpPublicKeyRing ring in bundle.GetKeyRings())
                foreach (PgpPublicKey key in ring.GetPublicKeys())
                    if (key.IsEncryptionKey)
                        return key;

            throw new LocalizedArgumentException(AppErrorCode.NoEncryptionKeyInFile);
        }
    }
}
