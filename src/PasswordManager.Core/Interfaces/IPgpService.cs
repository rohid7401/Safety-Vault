using PasswordManager.Core.Models;

namespace PasswordManager.Core.Interfaces
{
    public interface IPgpService
    {
        /// <summary>Encrypts raw bytes with the given PGP public key. Returns PGP binary data.</summary>
        byte[] EncryptBytes(byte[] data, string publicKeyPath);

        /// <summary>Decrypts PGP binary data with the given private key. Returns plaintext bytes.</summary>
        byte[] DecryptBytes(byte[] encryptedData, string privateKeyPath, string passphrase);

        /// <summary>Generates a new PGP key pair and writes armored files to disk.</summary>
        void GenerateKeyPair(string publicKeyPath, string privateKeyPath, string passphrase);

        /// <summary>
        /// Parses an armored public key and returns its real PGP fingerprint and user IDs, so a
        /// key fetched from an untrusted source (e.g. a keyserver) can be shown for out-of-band
        /// verification before it is trusted. Throws if the input is not a valid public key.
        /// </summary>
        PgpKeyDetails InspectPublicKey(string armoredPublicKey);
    }
}
