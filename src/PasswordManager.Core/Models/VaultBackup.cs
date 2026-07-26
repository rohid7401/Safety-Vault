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
    /// <para>Secure notes and cards are out of scope by design; this covers passwords only.</para>
    /// </summary>
    public sealed class VaultBackup
    {
        /// <summary>Bumped when the shape changes incompatibly; readers reject what they don't know.</summary>
        public const int CurrentVersion = 1;

        /// <summary>Marker used to tell this file apart from any other JSON offered for import.</summary>
        public const string ApplicationName = "SafetyVault";

        public int Version { get; set; } = CurrentVersion;
        public string Application { get; set; } = ApplicationName;
        public DateTime ExportedAt { get; set; } = DateTime.UtcNow;

        public List<BackupServiceEntry> Services { get; set; } = new();
    }

    /// <summary><see cref="ServiceEntry"/> in transit. Ids are deliberately absent — an import
    /// always creates fresh entries rather than risking a collision with what's already there.</summary>
    public sealed class BackupServiceEntry
    {
        public string Site { get; set; } = string.Empty;
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
}
