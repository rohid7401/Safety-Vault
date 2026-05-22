namespace PasswordManager.Core.Models
{
    public class SecureNote : VaultEntry
    {
        public string Title { get; set; } = string.Empty;
        public EncryptedField Content { get; set; } = new();
    }
}
