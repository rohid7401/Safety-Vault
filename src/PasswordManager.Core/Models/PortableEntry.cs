namespace PasswordManager.Core.Models
{
    /// <summary>
    /// A single account read from, or written to, a flat file. This is the lossy shape used to
    /// interoperate with other password managers; <see cref="VaultBackup"/> is the one that
    /// round-trips a SafetyVault vault without losing anything.
    /// </summary>
    public class PortableEntry
    {
        public string Site { get; set; } = string.Empty;

        /// <summary>Name of the account within the service ("Personal", "Work"), when the file
        /// carried one — this is what keeps two accounts of the same site apart on re-import.</summary>
        public string CredentialLabel { get; set; } = string.Empty;

        public string Username { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string? TotpSecret { get; set; }

        /// <summary>Free text from the source's notes column.</summary>
        public string Notes { get; set; } = string.Empty;

        public List<string> Tags { get; set; } = new();
    }
}
