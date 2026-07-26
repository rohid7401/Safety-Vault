namespace PasswordManager.Core.Interfaces
{
    public interface IFileEncryptionService
    {
        // ─── Stream-based (platform-agnostic) ────────────────────────────────
        // Mobile file pickers hand back a Stream / content-URI rather than a
        // filesystem path, so these are the primitives the UI should prefer.

        /// <summary>Reads plaintext from <paramref name="input"/>, PGP-encrypts it with the
        /// given public key, and writes the ciphertext to <paramref name="output"/>.</summary>
        Task EncryptAsync(Stream input, string publicKeyPath, Stream output);

        /// <summary>Reads ciphertext from <paramref name="input"/>, decrypts it with the given
        /// private key + passphrase, and writes the plaintext to <paramref name="output"/>.</summary>
        Task DecryptAsync(Stream input, string privateKeyPath, string passphrase, Stream output);

        /// <summary>
        /// Bundles several already-in-memory files into a zip and PGP-encrypts the zip to
        /// <paramref name="output"/>. The mobile equivalent of <see cref="EncryptDirectoryAsync"/>:
        /// where a picked folder yields no real filesystem path to walk, the caller picks
        /// individual files instead and this does the bundling.
        /// </summary>
        Task EncryptFilesAsync(IReadOnlyList<(string Name, byte[] Content)> files, string publicKeyPath, Stream output);

        // ─── Path-based convenience (desktop) ────────────────────────────────
        // Thin wrappers over the stream methods for the filesystem-friendly platforms.

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
