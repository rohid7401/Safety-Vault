namespace PasswordManager.Core.Models
{
    public class EncryptedField
    {
        public string CipherText { get; set; } = string.Empty;
        public string Nonce { get; set; } = string.Empty;
        public string Tag { get; set; } = string.Empty;
    }
}
