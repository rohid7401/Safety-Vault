using PasswordManager.Core.Interfaces;

namespace PasswordManager.Infrastructure.Encryption
{
    /// <summary>
    /// Concrete implementation of IPgpService using the static PGP helper classes.
    /// </summary>
    public class PgpService : IPgpService
    {
        public void EncryptFile(string inputFilePath, string outputFilePath, string publicKeyPath) =>
            PgpEncryption.EncryptFile(inputFilePath, outputFilePath, publicKeyPath);

        public void DecryptFile(string inputFilePath, string outputFilePath, string privateKeyPath, string passphrase) =>
            PgpDecryption.DecryptFile(inputFilePath, outputFilePath, privateKeyPath, passphrase);

        public string EncryptString(string plainText, string publicKeyPath) =>
            PgpEncryption.EncryptString(plainText, publicKeyPath);

        public string DecryptString(string encryptedBase64Text, string privateKeyPath, string passphrase) =>
            PgpDecryption.DecryptString(encryptedBase64Text, privateKeyPath, passphrase);
    }
}
