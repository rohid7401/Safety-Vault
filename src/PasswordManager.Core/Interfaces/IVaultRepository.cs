using PasswordManager.Core.Models;

namespace PasswordManager.Core.Interfaces
{
    public interface IVaultRepository
    {
        /// <summary>
        /// Loads and verifies the vault. Returns an empty vault if none exists yet.
        /// Throws <see cref="Exceptions.VaultIntegrityException"/> if the vault exists
        /// but its authentication tag is invalid, its integrity metadata is missing,
        /// or it cannot be decrypted/deserialized. Never returns partial/empty data on error.
        /// </summary>
        Task<VaultData> LoadAsync();

        /// <summary>
        /// Atomically persists the vault (temp file + move), keeping a rotating backup of
        /// the previous known-good version, and writes an authentication tag over the ciphertext.
        /// </summary>
        Task SaveAsync(VaultData vault);

        /// <summary>True if a backup of the previous known-good vault exists on disk.</summary>
        bool HasBackup();

        /// <summary>
        /// Restores the vault from the last known-good backup, verifies it, and returns it.
        /// Throws <see cref="Exceptions.VaultIntegrityException"/> if no valid backup exists.
        /// </summary>
        Task<VaultData> RestoreFromBackupAsync();
    }
}
