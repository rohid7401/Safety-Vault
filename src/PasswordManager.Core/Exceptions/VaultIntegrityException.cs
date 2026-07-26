namespace PasswordManager.Core.Exceptions
{
    /// <summary>
    /// Thrown when the vault on disk cannot be trusted: the authentication tag (MAC)
    /// does not match, the integrity metadata is missing, or the ciphertext fails to
    /// decrypt/deserialize. Callers should NEVER overwrite the vault when this is thrown —
    /// instead offer the user a restore from the last known-good backup.
    /// </summary>
    public class VaultIntegrityException : Exception, ILocalizedError
    {
        /// <summary>True when a verified backup exists that the user can restore from.</summary>
        public bool BackupAvailable { get; }

        public AppErrorCode Code { get; }
        public object?[] Args { get; } = Array.Empty<object?>();

        public VaultIntegrityException(AppErrorCode code, bool backupAvailable = false)
            : base($"{code}")
        {
            Code = code;
            BackupAvailable = backupAvailable;
        }

        public VaultIntegrityException(AppErrorCode code, Exception inner, bool backupAvailable = false)
            : base($"{code}", inner)
        {
            Code = code;
            BackupAvailable = backupAvailable;
        }
    }
}
