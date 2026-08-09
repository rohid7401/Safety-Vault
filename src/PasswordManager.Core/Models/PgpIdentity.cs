namespace PasswordManager.Core.Models
{
    /// <summary>
    /// A PGP key pair in transit between a user's own devices.
    ///
    /// <para>The private half arrives still sealed with the passphrase of the account that
    /// created it — this type never holds an unprotected key. Whoever receives it re-seals it
    /// under the local passphrase.</para>
    /// </summary>
    public sealed record PgpIdentity(string PublicKeyArmored, string PrivateKeyArmored);
}
