namespace PasswordManager.Core.Models
{
    public class PasswordEntry : VaultEntry
    {
        public string Site { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public EncryptedField Password { get; set; } = new();
    }
}
