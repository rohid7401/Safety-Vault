namespace PasswordManager.Core.Models
{
    /// <summary>
    /// Local user account stored alongside the vault. Identifies the vault owner
    /// and lets us migrate to remote authentication in the future without losing data.
    /// </summary>
    public class UserAccount
    {
        public string Username { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string PassphraseHash { get; set; } = string.Empty;
        public string Salt { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime LastLogin { get; set; } = DateTime.UtcNow;

        /// <summary>Path to the vault data folder. Stored relatively where possible.</summary>
        public string VaultPath { get; set; } = string.Empty;
    }
}
