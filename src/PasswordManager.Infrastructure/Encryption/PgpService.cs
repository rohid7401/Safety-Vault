using PasswordManager.Core.Interfaces;

namespace PasswordManager.Infrastructure.Encryption
{
    public class PgpService : IPgpService
    {
        public byte[] EncryptBytes(byte[] data, string publicKeyPath) =>
            PgpOperations.EncryptBytes(data, publicKeyPath);

        public byte[] DecryptBytes(byte[] encryptedData, string privateKeyPath, string passphrase) =>
            PgpOperations.DecryptBytes(encryptedData, privateKeyPath, passphrase);

        public string EncryptString(string plainText, string publicKeyPath) =>
            PgpOperations.EncryptString(plainText, publicKeyPath);

        public string DecryptString(string encryptedBase64, string privateKeyPath, string passphrase) =>
            PgpOperations.DecryptString(encryptedBase64, privateKeyPath, passphrase);
    }
}
