namespace PasswordManager.Core.Models
{
    /// <summary>
    /// Which part of account creation is running, so the UI can say what it is waiting on.
    /// Registration is several seconds of unavoidable CPU work — an RSA key pair and an
    /// Argon2id derivation — and a spinner with no words reads as a hang, which is exactly
    /// what testers reported.
    /// </summary>
    public enum RegistrationStage
    {
        /// <summary>Generating the PGP key pair. The long one, and the variable one: the
        /// generator searches for random primes, so it can take twice as long on one run as
        /// the next with no fault at all.</summary>
        GeneratingKeys,

        /// <summary>Deriving the key-encryption key with Argon2id and wrapping the vault key.</summary>
        SecuringVault,

        /// <summary>Writing the initial vault and registering the account.</summary>
        Finishing,
    }
}
