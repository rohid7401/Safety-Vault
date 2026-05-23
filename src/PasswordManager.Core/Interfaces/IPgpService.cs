namespace PasswordManager.Core.Interfaces
{
    public interface IPgpService
    {
        /// <summary>Encrypts raw bytes with the given PGP public key. Returns PGP binary data.</summary>
        byte[] EncryptBytes(byte[] data, string publicKeyPath);

        /// <summary>Decrypts PGP binary data with the given private key. Returns plaintext bytes.</summary>
        byte[] DecryptBytes(byte[] encryptedData, string privateKeyPath, string passphrase);

        /// <summary>Encrypts a string and returns Base64-encoded PGP data (for small values like AES key).</summary>
        string EncryptString(string plainText, string publicKeyPath);

        /// <summary>Decrypts Base64-encoded PGP data and returns the original string.</summary>
        string DecryptString(string encryptedBase64, string privateKeyPath, string passphrase);

        /// <summary>Generates a new PGP key pair and writes armored files to disk.</summary>
        void GenerateKeyPair(string publicKeyPath, string privateKeyPath, string passphrase);
    }
}
