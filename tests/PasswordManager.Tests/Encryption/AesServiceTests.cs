using System.Security.Cryptography;
using PasswordManager.Infrastructure.Encryption;
using Xunit;

namespace PasswordManager.Tests.Encryption
{
    public class AesServiceTests
    {
        private readonly AesService _sut = new();
        private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);

        [Fact]
        public void Encrypt_Decrypt_RoundTrip_ReturnsOriginalPlaintext()
        {
            const string original = "super-secret-password-123!";
            var (cipher, nonce, tag) = _sut.Encrypt(original, _key);
            var decrypted = _sut.Decrypt(cipher, _key, nonce, tag);
            Assert.Equal(original, decrypted);
        }

        [Fact]
        public void Encrypt_SamePlaintext_ProducesDifferentNonces()
        {
            const string plain = "same-password";
            var (_, nonce1, _) = _sut.Encrypt(plain, _key);
            var (_, nonce2, _) = _sut.Encrypt(plain, _key);
            Assert.NotEqual(nonce1, nonce2);
        }

        [Fact]
        public void Encrypt_EmptyString_RoundTripsCorrectly()
        {
            var (cipher, nonce, tag) = _sut.Encrypt(string.Empty, _key);
            var result = _sut.Decrypt(cipher, _key, nonce, tag);
            Assert.Equal(string.Empty, result);
        }

        [Fact]
        public void Decrypt_WrongKey_ThrowsCryptographicException()
        {
            var (cipher, nonce, tag) = _sut.Encrypt("secret", _key);
            var wrongKey = RandomNumberGenerator.GetBytes(32);
            Assert.ThrowsAny<CryptographicException>(() => _sut.Decrypt(cipher, wrongKey, nonce, tag));
        }

        [Fact]
        public void Decrypt_TamperedCiphertext_ThrowsCryptographicException()
        {
            var (cipher, nonce, tag) = _sut.Encrypt("secret", _key);
            var cipherBytes = Convert.FromBase64String(cipher);
            cipherBytes[0] ^= 0xFF;
            Assert.ThrowsAny<CryptographicException>(() =>
                _sut.Decrypt(Convert.ToBase64String(cipherBytes), _key, nonce, tag));
        }

        [Fact]
        public void Decrypt_TamperedTag_ThrowsCryptographicException()
        {
            var (cipher, nonce, tag) = _sut.Encrypt("secret", _key);
            var tagBytes = Convert.FromBase64String(tag);
            tagBytes[0] ^= 0xFF;
            Assert.ThrowsAny<CryptographicException>(() =>
                _sut.Decrypt(cipher, _key, nonce, Convert.ToBase64String(tagBytes)));
        }

        [Fact]
        public void Decrypt_TamperedNonce_ThrowsCryptographicException()
        {
            var (cipher, nonce, tag) = _sut.Encrypt("secret", _key);
            var nonceBytes = Convert.FromBase64String(nonce);
            nonceBytes[0] ^= 0xFF;
            Assert.ThrowsAny<CryptographicException>(() =>
                _sut.Decrypt(cipher, _key, Convert.ToBase64String(nonceBytes), tag));
        }

        [Fact]
        public void Encrypt_UnicodePassword_RoundTripsCorrectly()
        {
            const string unicode = "P@ssw0rd-ñoño-🔐-Ünïcödé";
            var (cipher, nonce, tag) = _sut.Encrypt(unicode, _key);
            Assert.Equal(unicode, _sut.Decrypt(cipher, _key, nonce, tag));
        }
    }
}
