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
    /// Why biometrics are not on offer, when they are not.
    ///
    /// <para>Exists so the settings screen can say something true instead of silently showing one
    /// button less. "Your face does not count" is a strange thing to be told, but it is far better
    /// than leaving someone to conclude the feature is broken — which is exactly what happened.</para>
    /// </summary>
    public enum BiometricAvailability
    {
        /// <summary>A strong biometric is enrolled and usable.</summary>
        Available,

        /// <summary>
        /// The hardware is there but nothing strong is enrolled. Face unlock on most phones is
        /// Class 2 and does not qualify: it cannot gate a Keystore key, so a prompt backed by it
        /// would look like protection while gating nothing. Enrolling a fingerprint fixes this.
        /// </summary>
        NoneEnrolled,

        /// <summary>No Class 3 sensor on this device at all.</summary>
        NoStrongSensor,

        /// <summary>Present but unusable right now — locked out after too many attempts, or
        /// disabled by policy.</summary>
        Unavailable,
    }

    /// <summary>
    /// The half of quick unlock that only the platform can do: hold a secret in hardware that
    /// cannot be exported, and release it after the user proves who they are.
    ///
    /// <para>The cryptography lives in <c>QuickUnlockSlot</c> and is the same everywhere. This is
    /// the part that differs per device, and it is where the whole guarantee sits — if this ever
    /// returns a secret that could be lifted off the phone, the PIN slot becomes four digits of
    /// nothing.</para>
    ///
    /// <para><b>Every method is scoped to one vault.</b> The secret and the slot file are two
    /// halves of the same thing, and the slot is per-vault; a device-wide secret would mean the
    /// second account to enrol silently overwrote the first account's half, leaving a slot that
    /// still counts down attempts against a secret that no longer exists. Whatever key or alias
    /// the implementation uses must therefore include <c>vaultId</c>.</para>
    /// </summary>
    public interface IQuickUnlockHardware
    {
        QuickUnlockCapability Capability { get; }

        /// <summary>Why <see cref="Capability"/> is not <c>Biometric</c>. Meaningless when it is.</summary>
        BiometricAvailability BiometricStatus { get; }

        /// <summary>
        /// Whether a secret for this vault still exists on this device.
        /// </summary>
        /// <remarks>
        /// A slot file whose secret is gone can never be opened again — cleared app data, a
        /// restored backup, a key the platform destroyed. Callers use this to retire the slot
        /// rather than leave a button that fails forever and burns attempts doing it.
        /// </remarks>
        bool HasSecret(string vaultId);

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
        Task<byte[]?> EnrollAsync(string vaultId, bool biometric);

        /// <summary>
        /// Asks the platform for the secret again, prompting the user if the slot is biometric.
        /// Null when they cancelled, failed, or the platform has invalidated the key.
        /// </summary>
        Task<byte[]?> RetrieveAsync(string vaultId, bool biometric, string promptTitle,
                                    string promptSubtitle, string cancelLabel);

        /// <summary>Drops this vault's hardware secret, leaving every other vault's alone. Called
        /// alongside destroying the slot, so neither half outlives the other.</summary>
        void Forget(string vaultId);
    }
}
