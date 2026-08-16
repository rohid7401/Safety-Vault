namespace PasswordManager.Core.Models
{
    /// <summary>
    /// SafetyVault's own backup format — the one export that survives a round trip between
    /// devices without losing anything. The flat CSV shapes exist to interoperate with other
    /// password managers and necessarily drop whatever those managers cannot represent
    /// (credential labels, PINs, phones, extra passwords, rotation policies, HOTP counters);
    /// this format drops nothing about a <see cref="ServiceEntry"/>.
    ///
    /// <para><b>Values are plaintext inside this document.</b> It cannot carry the stored
    /// <see cref="EncryptedField"/> ciphertexts instead: those are sealed with a field key
    /// derived from the passphrase of the account that wrote them, so the receiving device —
    /// a different account, with a different key — could never open them. The file's
    /// protection is therefore the PGP envelope wrapped around the whole thing on export,
    /// which is why an unencrypted backup carries an explicit warning in the UI.</para>
    ///
    /// <para>Version 2 adds secure notes, cards and application settings, so the file now holds
    /// everything the app knows rather than passwords alone. Version 1 files still read: they
    /// simply carry no notes or cards.</para>
    /// </summary>
    public sealed class VaultBackup
    {
        /// <summary>
        /// Bumped when the shape changes incompatibly; readers reject what they don't know.
        /// <list type="bullet">
        /// <item>1 — passwords only.</item>
        /// <item>2 — adds notes, cards and settings, and the reference scheme below.</item>
        /// </list>
        /// </summary>
        public const int CurrentVersion = 2;

        /// <summary>Marker used to tell this file apart from any other JSON offered for import.</summary>
        public const string ApplicationName = "SafetyVault";

        public int Version { get; set; } = CurrentVersion;
        public string Application { get; set; } = ApplicationName;
        public DateTime ExportedAt { get; set; } = DateTime.UtcNow;

        public List<BackupServiceEntry> Services { get; set; } = new();
        public List<BackupNote> Notes { get; set; } = new();
        public List<BackupCard> Cards { get; set; } = new();

        /// <summary>
        /// Application preferences, as free-form name/value pairs rather than a fixed shape.
        ///
        /// <para>Deliberately untyped: settings are still being designed, and a reader that meets
        /// a key it does not recognise should ignore it rather than refuse the whole file. Keeping
        /// this open means adding a preference later needs no format version bump.</para>
        /// </summary>
        public Dictionary<string, string> Settings { get; set; } = new();
    }

    /// <summary>
    /// <see cref="ServiceEntry"/> in transit. Ids are deliberately absent — an import always
    /// creates fresh entries rather than risking a collision with what's already there.
    /// </summary>
    public sealed class BackupServiceEntry
    {
        /// <summary>
        /// Identifies this entry *within this file only*, so a card can say which account it
        /// belongs to without either of them carrying a real id.
        ///
        /// <para>The link could not survive otherwise: ids are regenerated on import, so a card
        /// holding the old account's <c>Guid</c> would come back pointing at nothing — and would
        /// do it silently, which is the worst way for a reference to break.</para>
        /// </summary>
        public int Ref { get; set; }

        public string Site { get; set; } = string.Empty;

        /// <summary>Travels with the entry. Absent from files written before favourites existed,
        /// which reads back as false — the right answer, so no version bump is needed.</summary>
        public bool IsFavorite { get; set; }
        public List<string> Tags { get; set; } = new();
        public bool Grouped { get; set; } = true;
        public DateTime? ExpireTime { get; set; }
        public DateTime CreationTime { get; set; } = DateTime.UtcNow;
        public DateTime LastUpdateTime { get; set; } = DateTime.UtcNow;
        public List<BackupCredential> Credentials { get; set; } = new();
    }

    public sealed class BackupCredential
    {
        public string Label { get; set; } = string.Empty;
        public DateTime CreationTime { get; set; } = DateTime.UtcNow;
        public DateTime LastUpdateTime { get; set; } = DateTime.UtcNow;
        public List<BackupField> Fields { get; set; } = new();
    }

    public sealed class BackupField
    {
        public CredentialFieldType Type { get; set; }
        public string Label { get; set; } = string.Empty;
        public bool IsSecret { get; set; }

        /// <summary>Plaintext, whether or not the field is stored encrypted in the vault.</summary>
        public string Value { get; set; } = string.Empty;

        /// <summary>Carried across so a restored secret keeps reporting when it really changed,
        /// instead of appearing to have been changed on the day of the import. Null when unknown.</summary>
        public DateTime? LastChanged { get; set; }

        public BackupRotation? Rotation { get; set; }
        public TwoFactorKind TwoFactorKind { get; set; } = TwoFactorKind.Totp;
        public long HotpCounter { get; set; }
    }

    /// <summary>
    /// <see cref="RotationPolicy"/> without its computed <c>ExpiresAt</c> — the receiving
    /// device recomputes that from the interval and <see cref="LastChanged"/>, so a backup
    /// restored months later still reports the right "overdue" state.
    /// </summary>
    public sealed class BackupRotation
    {
        public int Interval { get; set; } = 90;
        public RotationUnit Unit { get; set; } = RotationUnit.Days;
        public DateTime LastChanged { get; set; } = DateTime.UtcNow;
    }

    /// <summary><see cref="SecureNote"/> in transit; the body travels as plaintext, for the same
    /// reason the fields above do.</summary>
    public sealed class BackupNote
    {
        public string Title { get; set; } = string.Empty;
        public string Content { get; set; } = string.Empty;
        public List<string> Tags { get; set; } = new();
        public bool IsCritical { get; set; }
        public bool IsFavorite { get; set; }
        public DateTime CreationTime { get; set; } = DateTime.UtcNow;
        public DateTime LastUpdateTime { get; set; } = DateTime.UtcNow;
    }

    /// <summary><see cref="CardEntry"/> in transit.</summary>
    public sealed class BackupCard
    {
        public string CardholderName { get; set; } = string.Empty;
        public string CardNumber { get; set; } = string.Empty;
        public string Cvv { get; set; } = string.Empty;

        /// <summary>Null when the card has no PIN, keeping "not set" distinct from "empty".</summary>
        public string? Pin { get; set; }

        public int ExpiryMonth { get; set; }
        public int ExpiryYear { get; set; }
        public bool IsFavorite { get; set; }

        /// <summary>
        /// The <see cref="BackupServiceEntry.Ref"/> of the account this card belongs to, or null.
        /// Resolved back to a real id on import; a value that matches no entry in the file is
        /// dropped rather than restored as a link to nowhere.
        /// </summary>
        public int? LinkedRef { get; set; }

        public DateTime CreationTime { get; set; } = DateTime.UtcNow;
        public DateTime LastUpdateTime { get; set; } = DateTime.UtcNow;
    }
}
