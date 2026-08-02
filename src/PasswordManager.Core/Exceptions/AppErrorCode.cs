namespace PasswordManager.Core.Exceptions
{
    /// <summary>
    /// Identifies a user-facing failure without naming it in any particular language.
    ///
    /// <para>Core and Infrastructure have no access to the UI's string catalogue — and should
    /// not: they would then have to know about locales, and a service would be untestable
    /// without one. So they throw a code, and the UI turns the code into a sentence in the
    /// user's language. This is the same arrangement <see cref="ImportFormatError"/> already
    /// uses for imports; anything a user can read on screen belongs here rather than in an
    /// exception's <c>Message</c>, which is English prose meant for logs.</para>
    /// </summary>
    public enum AppErrorCode
    {
        // ── Account / authentication ─────────────────────────────────────────
        UsernameRequired,
        EmailRequired,

        /// <summary>Takes the minimum length as an argument.</summary>
        PassphraseTooShort,

        UsernameTaken,
        EmailTaken,
        VaultFolderExists,

        /// <summary>Deliberately covers both "no such account" and "wrong passphrase" —
        /// distinguishing them would let an outsider enumerate who has an account here.</summary>
        BadCredentials,

        // ── Vault key ring ───────────────────────────────────────────────────
        KeyringUnreadable,
        KeyringCorrupt,

        /// <summary>Takes the unrecognised KDF name as an argument.</summary>
        UnsupportedKdf,

        // ── Vault integrity ──────────────────────────────────────────────────
        NoBackupAvailable,
        VaultTruncated,
        VaultCorrupt,

        /// <summary>The MAC did not verify: the file was modified or replaced, or the
        /// passphrase is wrong. Deliberately vague on screen — which of those it is would
        /// tell an attacker holding the file whether a guessed passphrase was close.</summary>
        VaultAuthenticationFailed,

        // ── PGP ──────────────────────────────────────────────────────────────
        NoPrivateKeyOrBadPassphrase,
        NoEncryptionKeyInFile,
        NoPublicKeyInData,

        // ── Files / import / export ──────────────────────────────────────────
        NoFilesToBundle,
        NoColumnsSelected,
        PathEscapesKeyDirectory,

        /// <summary>The public key server could not be reached (offline, DNS, TLS).</summary>
        KeyServerUnreachable,

        /// <summary>
        /// The stored 2FA secret is not valid Base32. Its alphabet is A–Z and 2–7, so a secret
        /// typed by hand from a screen full of digits is rejected on the 0, 1, 8 or 9.
        /// </summary>
        InvalidTotpSecret,

        // ── Password generator ───────────────────────────────────────────────
        /// <summary>Takes the minimum length as an argument.</summary>
        PasswordLengthTooShort,

        NoCharacterSetEnabled,
    }
}
