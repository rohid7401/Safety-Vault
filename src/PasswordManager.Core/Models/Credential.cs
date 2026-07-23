namespace PasswordManager.Core.Models
{
    /// <summary>
    /// A set of fields that belong together — one "account" within a service. Any combination
    /// of field types is allowed: { email, password, 2FA }, { phone, PIN }, { username,
    /// password, PIN }, etc. Two credentials that happen to share a value (same password, or
    /// same email) are still separate credentials; the app just displays that overlap.
    /// </summary>
    public class Credential
    {
        public Guid Id { get; set; } = Guid.NewGuid();

        /// <summary>Optional name to tell credentials apart inside a grouped card ("Personal", "Work").</summary>
        public string Label { get; set; } = string.Empty;

        public List<CredentialField> Fields { get; set; } = new();

        public DateTime CreationTime { get; set; } = DateTime.UtcNow;
        public DateTime LastUpdateTime { get; set; } = DateTime.UtcNow;
    }
}
