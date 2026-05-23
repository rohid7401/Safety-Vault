namespace PasswordManager.Core.Interfaces
{
    public interface IFileEncryptionService
    {
        /// <summary>Encrypts a file with the given PGP public key. Returns the output path.</summary>
        Task<string> EncryptFileAsync(string inputPath, string publicKeyPath, string? outputPath = null);

        /// <summary>Decrypts a PGP-encrypted file with the given private key and passphrase.</summary>
        Task<string> DecryptFileAsync(string inputPath, string privateKeyPath, string passphrase, string? outputPath = null);

        /// <summary>Zips a directory and encrypts the zip with PGP. Returns the .pgp path.</summary>
        Task<string> EncryptDirectoryAsync(string directoryPath, string publicKeyPath, string? outputPath = null);

        /// <summary>Decrypts a .pgp file that contains a zipped directory and extracts it.</summary>
        Task<string> DecryptDirectoryAsync(string inputPath, string privateKeyPath, string passphrase, string? extractToPath = null);
    }
}
