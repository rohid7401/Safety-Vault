namespace PasswordManager.Core.Models
{
    /// <summary>
    /// A single password to be audited, already flattened out of the vault: the plaintext value
    /// and its expiry are resolved by the service (which owns decryption and rotation policy) so
    /// the <see cref="Interfaces.IVaultAuditor"/> stays free of any encryption concern.
    /// One <see cref="ServiceEntry"/> credential can contribute several of these (one per
    /// password field).
    /// </summary>
    public sealed class AuditItem
    {
        /// <summary>Owning entry (used only to label/locate the issue; not required to be unique).</summary>
        public Guid EntryId { get; init; }

        /// <summary>Human label shown in the audit report (e.g. "github.com · Work").</summary>
        public string Label { get; init; } = string.Empty;

        /// <summary>Decrypted password value being audited.</summary>
        public string Password { get; init; } = string.Empty;

        /// <summary>When this secret is considered expired (rotation policy or entry expiry), if any.</summary>
        public DateTime? ExpiresAt { get; init; }

        /// <summary>
        /// Whether this secret should be scored for strength. False for a cash-machine PIN: four
        /// digits can never score well, so reporting every card as weak would be a wall of
        /// findings nobody can act on — the bank chooses the length, not the user. Such items are
        /// still compared against the others, because sharing one PIN across two cards *is*
        /// something the user can fix.
        /// </summary>
        public bool StrengthChecked { get; init; } = true;
    }
}
