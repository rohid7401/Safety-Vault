using System.Security.Cryptography;
using System.Text;
using PasswordManager.Core.Interfaces;

namespace PasswordManager.Infrastructure.Encryption
{
    public class AesService : IAesService
    {
        private const int NonceSizeBytes = 12;  // 96-bit nonce (GCM standard)
        private const int TagSizeBytes = 16;    // 128-bit authentication tag

        public (string CipherText, string Nonce, string Tag) Encrypt(string plainText, byte[] key)
        {
            var plainBytes = Encoding.UTF8.GetBytes(plainText);
            var nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
            var cipherText = new byte[plainBytes.Length];
            var tag = new byte[TagSizeBytes];

            using var aesGcm = new AesGcm(key, TagSizeBytes);
            aesGcm.Encrypt(nonce, plainBytes, cipherText, tag);

            return (
                Convert.ToBase64String(cipherText),
                Convert.ToBase64String(nonce),
                Convert.ToBase64String(tag)
            );
        }

        public string Decrypt(string cipherTextBase64, byte[] key, string nonceBase64, string tagBase64)
        {
            var cipherBytes = Convert.FromBase64String(cipherTextBase64);
            var nonce = Convert.FromBase64String(nonceBase64);
            var tag = Convert.FromBase64String(tagBase64);
            var plainBytes = new byte[cipherBytes.Length];

            using var aesGcm = new AesGcm(key, TagSizeBytes);
            // Throws CryptographicException if authentication tag doesn't match (tampering detected)
            aesGcm.Decrypt(nonce, cipherBytes, tag, plainBytes);

            return Encoding.UTF8.GetString(plainBytes);
        }
    }
}
