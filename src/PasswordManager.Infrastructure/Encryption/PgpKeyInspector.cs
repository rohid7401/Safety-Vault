using Org.BouncyCastle.Bcpg.OpenPgp;
using PasswordManager.Core.Models;
using PasswordManager.Core.Exceptions;

namespace PasswordManager.Infrastructure.Encryption
{
    /// <summary>Parses armored PGP public keys into human-verifiable details (fingerprint + UIDs).</summary>
    internal static class PgpKeyInspector
    {
        internal static PgpKeyDetails Inspect(Stream armoredPublicKey)
        {
            var bundle = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(armoredPublicKey));

            foreach (PgpPublicKeyRing ring in bundle.GetKeyRings())
            {
                // Prefer the master key: it carries the identity (UIDs) and the primary fingerprint.
                PgpPublicKey? master = null;
                foreach (PgpPublicKey key in ring.GetPublicKeys())
                {
                    if (key.IsMasterKey) { master = key; break; }
                }
                master ??= ring.GetPublicKey();

                var fingerprint = Convert.ToHexString(master.GetFingerprint());

                var uids = new List<string>();
                foreach (var uid in master.GetUserIds())
                {
                    if (uid is string s && !string.IsNullOrWhiteSpace(s))
                        uids.Add(s);
                }

                return new PgpKeyDetails(fingerprint, uids);
            }

            throw new LocalizedArgumentException(AppErrorCode.NoPublicKeyInData);
        }
    }
}
