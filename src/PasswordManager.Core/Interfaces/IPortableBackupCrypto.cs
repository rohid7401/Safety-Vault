namespace PasswordManager.Core.Interfaces
{
    /// <summary>
    /// Seals a backup with a passphrase the user chooses at export time, so it can be opened on
    /// any device rather than only the one that wrote it.
    /// </summary>
    public interface IPortableBackupCrypto
    {
        /// <summary>Wraps <paramref name="plaintext"/> so only the passphrase opens it.</summary>
        byte[] Seal(byte[] plaintext, string passphrase);

        /// <summary>
        /// Reverses <see cref="Seal"/>. Throws if the passphrase is wrong or the file was
        /// altered — the two are indistinguishable, and deliberately so.
        /// </summary>
        byte[] Open(byte[] sealedData, string passphrase);

        /// <summary>Whether these bytes look like something <see cref="Seal"/> produced.</summary>
        bool IsSealed(byte[] data);
    }
}
