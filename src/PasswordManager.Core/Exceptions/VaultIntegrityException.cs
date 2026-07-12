namespace PasswordManager.Core.Exceptions
{
    /// <summary>
    /// Thrown when the vault on disk cannot be trusted: the authentication tag (MAC)
    /// does not match, the integrity metadata is missing, or the ciphertext fails to
    /// decrypt/deserialize. Callers should NEVER overwrite the vault when this is thrown —
    /// instead offer the user a restore from the last known-good backup.
    /// </summary>
    public class VaultIntegrityException : Exception
    {
        /// <summary>True when a verified backup exists that the user can restore from.</summary>
        public bool BackupAvailable { get; }

        public VaultIntegrityException(string message, bool backupAvailable = false)
            : base(message)
        {
            BackupAvailable = backupAvailable;
        }

        public VaultIntegrityException(string message, Exception inner, bool backupAvailable = false)
            : base(message, inner)
        {
            BackupAvailable = backupAvailable;
        }
    }
}
