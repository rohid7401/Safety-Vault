using System.Security.Cryptography;
using System.Text;
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
    ///
    /// <para>This class is also the only place that knows how a vault folder becomes the
    /// <c>vaultId</c> the hardware is keyed by. Callers pass paths and never see the id.</para>
    /// </summary>
    public class QuickUnlockService
    {
        private readonly IQuickUnlockHardware _hardware;

        public QuickUnlockService(IQuickUnlockHardware hardware) => _hardware = hardware;

        public QuickUnlockCapability Capability => _hardware.Capability;

        public BiometricAvailability BiometricStatus => _hardware.BiometricStatus;

        /// <summary>
        /// A short, stable, filesystem- and Keystore-safe name for one vault.
        ///
        /// <para>Hashed rather than used raw because it ends up in a Keystore alias and in a
        /// preferences key, and a vault path contains separators and a username. The path is the
        /// right thing to key on: a slot lives beside the vault, so a vault that moves has left
        /// its slot behind anyway.</para>
        /// </summary>
        private static string VaultId(string vaultPath)
        {
            var normalized = Path.TrimEndingDirectorySeparator(
                Path.GetFullPath(vaultPath)).ToLowerInvariant();
            var digest = SHA256.HashData(Encoding.UTF8.GetBytes(normalized));
            return Convert.ToHexString(digest, 0, 8).ToLowerInvariant();
        }

        /// <summary>
        /// Whether this vault has a slot that can actually be opened on this device.
        /// </summary>
        /// <remarks>
        /// A slot whose hardware secret has vanished is worse than no slot: the button still
        /// appears, every press fails, and on a PIN slot each press spends one of five attempts.
        /// So a half-slot is retired here rather than left to rot — the passphrase was always the
        /// guaranteed way in, and nothing is lost by admitting the shortcut is gone.
        /// </remarks>
        public bool IsEnrolled(string vaultPath)
        {
            if (!QuickUnlockSlot.IsEnrolled(vaultPath)) return false;
            if (_hardware.HasSecret(VaultId(vaultPath))) return true;

            QuickUnlockSlot.Destroy(vaultPath);
            return false;
        }

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
            var secret = await _hardware.EnrollAsync(VaultId(vaultPath), biometric);
            if (secret is null) return false;

            try
            {
                QuickUnlockSlot.Enroll(vaultPath, vaultKey, method, secret, pin);
                return true;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(secret);
            }
        }

        /// <summary>Opens the slot and hands back the vault key, or says why not.</summary>
        public async Task<(QuickUnlockOutcome Outcome, byte[] VaultKey)> UnlockAsync(
            string vaultPath, string? pin, string promptTitle, string promptSubtitle, string cancelLabel)
        {
            if (!QuickUnlockSlot.IsEnrolled(vaultPath))
                return (QuickUnlockOutcome.NotEnrolled, Array.Empty<byte>());

            var vaultId = VaultId(vaultPath);
            var biometric = QuickUnlockSlot.EnrolledMethod(vaultPath) == QuickUnlockMethod.Biometric;
            var secret = await _hardware.RetrieveAsync(vaultId, biometric, promptTitle, promptSubtitle, cancelLabel);

            if (secret is null)
            {
                // A slot whose secret is simply gone is a dead end, and telling it apart from a
                // cancelled prompt matters: one should retire the slot, the other must leave it
                // alone so a mis-tap does not cost a setting.
                if (!_hardware.HasSecret(vaultId))
                {
                    QuickUnlockSlot.Destroy(vaultPath);
                    return (QuickUnlockOutcome.NotEnrolled, Array.Empty<byte>());
                }

                // For a biometric slot this is usually just "cancelled". But it is also what a
                // key destroyed by new fingerprints looks like, and the two are indistinguishable
                // from here — so the slot is left alone and the next real attempt decides. Wiping
                // it on a cancelled prompt would punish a mis-tap with a lost setting.
                return (QuickUnlockOutcome.Cancelled, Array.Empty<byte>());
            }

            try
            {
                var result = QuickUnlockSlot.TryUnlock(vaultPath, secret, pin, out var vaultKey);
                if (result == QuickUnlockResult.Exhausted) _hardware.Forget(vaultId);

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
                CryptographicOperations.ZeroMemory(secret);
            }
        }

        /// <summary>Turns it off for this vault. Both halves go, so neither can outlive the other
        /// and leave a hardware secret guarding nothing or a slot no secret can open. Other
        /// accounts on the same phone are untouched.</summary>
        public void Disable(string vaultPath)
        {
            QuickUnlockSlot.Destroy(vaultPath);
            _hardware.Forget(VaultId(vaultPath));
        }
    }
}
