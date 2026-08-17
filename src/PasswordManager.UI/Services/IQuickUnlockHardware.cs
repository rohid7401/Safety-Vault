namespace PasswordManager.UI.Services
{
    /// <summary>What this device can offer as a second way into the vault.</summary>
    public enum QuickUnlockCapability
    {
        /// <summary>
        /// No secure hardware. Neither option is offered — and that is the right answer, not a
        /// limitation to work around: without a key the chip refuses to export, a four-digit PIN
        /// is ten thousand guesses against a file an attacker already has. Offering it here would
        /// be handing someone a downgrade labelled as a feature.
        /// </summary>
        None,

        /// <summary>Secure hardware, but no biometrics enrolled. A PIN slot is safe here.</summary>
        PinOnly,

        /// <summary>Secure hardware and a usable fingerprint or face.</summary>
        Biometric,
    }

    /// <summary>
    /// The half of quick unlock that only the platform can do: hold a secret in hardware that
    /// cannot be exported, and release it after the user proves who they are.
    ///
    /// <para>The cryptography lives in <c>QuickUnlockSlot</c> and is the same everywhere. This is
    /// the part that differs per device, and it is where the whole guarantee sits — if this ever
    /// returns a secret that could be lifted off the phone, the PIN slot becomes four digits of
    /// nothing.</para>
    /// </summary>
    public interface IQuickUnlockHardware
    {
        QuickUnlockCapability Capability { get; }

        /// <summary>
        /// Creates the hardware-held secret for a slot and returns a copy for wrapping the vault
        /// key. Called once, at enrolment, by someone who has already unlocked with the
        /// passphrase.
        /// </summary>
        /// <remarks>
        /// The biometric variant must be created so the platform destroys it when the enrolled
        /// fingerprints change. A finger added to the phone tomorrow must not inherit today's way
        /// into the vault, and the slot must fail closed rather than quietly widen.
        /// </remarks>
        Task<byte[]?> EnrollAsync(bool biometric);

        /// <summary>
        /// Asks the platform for the secret again, prompting the user if the slot is biometric.
        /// Null when they cancelled, failed, or the platform has invalidated the key.
        /// </summary>
        Task<byte[]?> RetrieveAsync(bool biometric, string promptTitle, string promptSubtitle, string cancelLabel);

        /// <summary>Drops the hardware secret. Called alongside destroying the slot, so neither
        /// half outlives the other.</summary>
        void Forget();
    }
}
