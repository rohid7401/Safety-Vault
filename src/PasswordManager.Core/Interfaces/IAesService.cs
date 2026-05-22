namespace PasswordManager.Core.Interfaces
{
    public interface IAesService
    {
        /// <summary>
        /// Encrypts plainText with AES-GCM. Returns ciphertext, nonce, and authentication tag (all Base64).
        /// </summary>
        (string CipherText, string Nonce, string Tag) Encrypt(string plainText, byte[] key);

        /// <summary>
        /// Decrypts and authenticates. Throws CryptographicException if tag is invalid (tampering detected).
        /// </summary>
        string Decrypt(string cipherText, byte[] key, string nonce, string tag);
    }
}
