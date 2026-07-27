namespace PasswordManager.Core.Models
{
    /// <summary>
    /// Which part of account creation is running, so the UI can say what it is waiting on.
    /// Registration is unavoidable CPU work — an Argon2id derivation — and a spinner with no
    /// words reads as a hang, which is exactly what testers reported. (The other big cost,
    /// generating the PGP key pair, no longer happens here — see
    /// PasswordManagerService.GenerateOwnPgpIdentityAsync — because most accounts never use the
    /// file-encryption feature it exists for.)
    /// </summary>
    public enum RegistrationStage
    {
        /// <summary>Deriving the key-encryption key with Argon2id and wrapping the vault key.</summary>
        SecuringVault,

        /// <summary>Writing the initial vault and registering the account.</summary>
        Finishing,
    }
}
