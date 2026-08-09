namespace PasswordManager.Core.Models
{
    public enum TwoFactorKind { Totp, Hotp }

    /// <summary>
    /// One typed value inside a <see cref="Credential"/> (an email, a password, a PIN, a 2FA
    /// secret, a phone…). Fields combine freely, so a credential is really just a bag of these.
    /// Non-secret values (email/username/phone) are kept in clear so the list stays searchable;
    /// secret values (password/pin/2FA/hidden text) are stored encrypted.
    /// </summary>
    public class CredentialField
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public CredentialFieldType Type { get; set; }

        /// <summary>Optional custom label, e.g. "ATM PIN". The UI falls back to the type name.</summary>
        public string Label { get; set; } = string.Empty;

        /// <summary>Hidden by default and revealed on demand; also selects which value slot is used.</summary>
        public bool IsSecret { get; set; }

        /// <summary>Clear value for non-secret fields (searchable). Empty for secret fields.</summary>
        public string PlainValue { get; set; } = string.Empty;

        /// <summary>Encrypted value for secret fields. Null for non-secret fields.</summary>
        public EncryptedField? SecretValue { get; set; }

        /// <summary>
        /// When the secret was last replaced, for the user's own reference ("changed 3 months
        /// ago"). Distinct from <see cref="RotationPolicy.LastChanged"/>, which only exists
        /// while a rotation policy does and drives the expiry clock; this is tracked for every
        /// secret field regardless. Null means unknown — either a non-secret field, or a
        /// credential written before this was recorded, which must not be reported as "changed
        /// today" just because it was read today.
        /// </summary>
        public DateTime? LastChanged { get; set; }

        // ── Rotation (meaningful for Password / Pin) ─────────────────────────
        public RotationPolicy? Rotation { get; set; }

        /// <summary>Single-slot history: the value immediately before the current one (older discarded).</summary>
        public EncryptedField? PreviousSecret { get; set; }

        // ── Two-factor (meaningful for TwoFactor) ────────────────────────────
        public TwoFactorKind TwoFactorKind { get; set; } = TwoFactorKind.Totp;
        public long HotpCounter { get; set; }

        /// <summary>Whether a field of this type should be treated as a secret by default.</summary>
        public static bool IsSecretByDefault(CredentialFieldType type) =>
            type is CredentialFieldType.Password or CredentialFieldType.Pin
                or CredentialFieldType.TwoFactor or CredentialFieldType.Key;

        /// <summary>
        /// Replaces the secret value. When the field has a rotation policy, the immediately-
        /// previous value is kept in a single history slot (any older value is discarded) and
        /// the rotation clock is restarted. Fields without rotation are simply overwritten.
        /// Callers must only invoke this when the value actually changed — every call stamps
        /// <see cref="LastChanged"/>, so re-setting an unchanged secret would misreport it.
        /// </summary>
        public void SetSecret(EncryptedField newValue)
        {
            if (Rotation is not null)
            {
                if (SecretValue is not null)
                    PreviousSecret = SecretValue;
                Rotation.LastChanged = DateTime.UtcNow;
            }
            LastChanged = DateTime.UtcNow;
            SecretValue = newValue;
        }

        /// <summary>Rotation status relative to <paramref name="now"/> (None when not rotating).</summary>
        public ExpiryStatus GetExpiryStatus(DateTime now, int dueSoonDays = 14)
        {
            if (Rotation is null) return ExpiryStatus.None;
            var expires = Rotation.ExpiresAt;
            if (now >= expires) return ExpiryStatus.Expired;
            if (now >= expires.AddDays(-dueSoonDays)) return ExpiryStatus.DueSoon;
            return ExpiryStatus.Ok;
        }
    }
}
