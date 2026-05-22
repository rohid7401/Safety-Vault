namespace PasswordManager.Core.Models
{
    public class CardEntry : VaultEntry
    {
        public string CardholderName { get; set; } = string.Empty;
        public EncryptedField CardNumber { get; set; } = new();
        public EncryptedField Cvv { get; set; } = new();
        public int ExpiryMonth { get; set; }
        public int ExpiryYear { get; set; }
    }
}
