using PasswordManager.Infrastructure.Encryption;

namespace PasswordManager.UI.Services
{
    /// <summary>What a quick-unlock attempt ended up doing, in terms the UI can speak.</summary>
    public enum QuickUnlockOutcome
    {
        Success,
        NotEnrolled,

        /// <summary>The prompt was dismissed, or the platform would not release the secret.</summary>
        Cancelled,

        /// <summary>Wrong PIN. Attempts remain.</summary>
        Wrong,

        /// <summary>Attempts ran out; the slot is gone and only the passphrase is left.</summary>
        Exhausted,
    }

    /// <summary>
    /// Joins the two halves of quick unlock: the hardware that holds a secret this device cannot
    /// export, and the slot file that wraps the vault key under it.
    ///
    /// <para>Neither half is useful alone, and keeping the join in one place means the rules —
    /// destroy the slot when the hardware forgets, destroy the hardware secret when the slot
    /// dies — cannot be applied in one direction and forgotten in the other.</para>
    /// </summary>
    public class QuickUnlockService
    {
        private readonly IQuickUnlockHardware _hardware;

        public QuickUnlockService(IQuickUnlockHardware hardware) => _hardware = hardware;

        public QuickUnlockCapability Capability => _hardware.Capability;

        public bool IsEnrolled(string vaultPath) => QuickUnlockSlot.IsEnrolled(vaultPath);

        public QuickUnlockMethod? Method(string vaultPath) => QuickUnlockSlot.EnrolledMethod(vaultPath);

        public int AttemptsLeft(string vaultPath) => QuickUnlockSlot.AttemptsLeft(vaultPath);

        /// <summary>
        /// Enrols a slot. Only reachable from inside an unlocked vault, because that is the only
        /// place the vault key exists — quick unlock can never be set up by someone who could not
        /// already get in with the passphrase.
        /// </summary>
        public async Task<bool> EnrollAsync(string vaultPath, byte[] vaultKey, QuickUnlockMethod method, string? pin = null)
        {
            if (Capability == QuickUnlockCapability.None) return false;
            if (method == QuickUnlockMethod.Biometric && Capability != QuickUnlockCapability.Biometric) return false;

            var biometric = method == QuickUnlockMethod.Biometric;
            var secret = await _hardware.EnrollAsync(biometric);
            if (secret is null) return false;

            try
            {
                QuickUnlockSlot.Enroll(vaultPath, vaultKey, method, secret, pin);
                return true;
            }
            finally
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(secret);
            }
        }

        /// <summary>Opens the slot and hands back the vault key, or says why not.</summary>
        public async Task<(QuickUnlockOutcome Outcome, byte[] VaultKey)> UnlockAsync(
            string vaultPath, string? pin, string promptTitle, string promptSubtitle, string cancelLabel)
        {
            if (!QuickUnlockSlot.IsEnrolled(vaultPath))
                return (QuickUnlockOutcome.NotEnrolled, Array.Empty<byte>());

            var biometric = QuickUnlockSlot.EnrolledMethod(vaultPath) == QuickUnlockMethod.Biometric;
            var secret = await _hardware.RetrieveAsync(biometric, promptTitle, promptSubtitle, cancelLabel);

            if (secret is null)
            {
                // For a biometric slot this is usually just "cancelled". But it is also what a
                // key destroyed by new fingerprints looks like, and the two are indistinguishable
                // from here — so the slot is left alone and the next real attempt decides. Wiping
                // it on a cancelled prompt would punish a mis-tap with a lost setting.
                return (QuickUnlockOutcome.Cancelled, Array.Empty<byte>());
            }

            try
            {
                var result = QuickUnlockSlot.TryUnlock(vaultPath, secret, pin, out var vaultKey);
                if (result == QuickUnlockResult.Exhausted) _hardware.Forget();

                return (result switch
                {
                    QuickUnlockResult.Success => QuickUnlockOutcome.Success,
                    QuickUnlockResult.Wrong => QuickUnlockOutcome.Wrong,
                    QuickUnlockResult.Exhausted => QuickUnlockOutcome.Exhausted,
                    _ => QuickUnlockOutcome.NotEnrolled,
                }, vaultKey);
            }
            finally
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(secret);
            }
        }

        /// <summary>Turns it off. Both halves go, so neither can outlive the other and leave a
        /// hardware secret guarding nothing or a slot no secret can open.</summary>
        public void Disable(string vaultPath)
        {
            QuickUnlockSlot.Destroy(vaultPath);
            _hardware.Forget();
        }
    }
}
