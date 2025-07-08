namespace PasswordManager.Core.Interfaces
{
    /// <summary>
    /// Defines the contract for AES encryption and decryption services.
    /// </summary>
    public interface IAesService
    {
        (string CipherText, string IV) Encrypt(string plainText, string key);
        string Decrypt(string cipherText, string key, string iv);
    }
}
