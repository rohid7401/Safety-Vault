namespace PasswordManager.Core.Interfaces
{
    /// <summary>
    /// Defines the contract for PGP encryption and decryption services.
    /// </summary>
    public interface IPgpService
    {
        void EncryptFile(string inputFilePath, string outputFilePath, string publicKeyPath);
        void DecryptFile(string inputFilePath, string outputFilePath, string privateKeyPath, string passphrase);
        string EncryptString(string plainText, string publicKeyPath);
        string DecryptString(string encryptedBase64Text, string privateKeyPath, string passphrase);
    }
}
