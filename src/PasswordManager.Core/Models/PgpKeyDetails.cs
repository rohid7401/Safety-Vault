namespace PasswordManager.Core.Models
{
    /// <summary>
    /// Human-verifiable details parsed from an armored PGP public key. Used to inspect a key
    /// fetched from an untrusted source (e.g. a keyserver) before trusting it: the fingerprint
    /// can be checked out-of-band, and the user IDs reveal which identities the key claims.
    /// </summary>
    public sealed record PgpKeyDetails(string Fingerprint, IReadOnlyList<string> UserIds)
    {
        /// <summary>True if any user ID contains the given email address (case-insensitive).</summary>
        public bool HasUserIdFor(string email) =>
            !string.IsNullOrWhiteSpace(email) &&
            UserIds.Any(uid => uid.Contains(email, StringComparison.OrdinalIgnoreCase));

        /// <summary>Fingerprint grouped in 4-char blocks for readable display.</summary>
        public string FingerprintDisplay =>
            string.Join(" ", Enumerable.Range(0, (Fingerprint.Length + 3) / 4)
                .Select(i => Fingerprint.Substring(i * 4, Math.Min(4, Fingerprint.Length - i * 4))));
    }
}
