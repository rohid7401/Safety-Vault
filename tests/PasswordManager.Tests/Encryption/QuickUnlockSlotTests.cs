using System.Security.Cryptography;
using PasswordManager.Infrastructure.Encryption;
using Xunit;

namespace PasswordManager.Tests.Encryption
{
    public class QuickUnlockSlotTests : IDisposable
    {
        private readonly string _dir =
            Path.Combine(Path.GetTempPath(), "qu_test_" + Guid.NewGuid().ToString("N"));

        /// <summary>Stands in for the bytes the phone's secure hardware releases. In the tests it
        /// is a plain array; on the device it never leaves the chip.</summary>
        private readonly byte[] _hardware = RandomNumberGenerator.GetBytes(32);

        private readonly byte[] _vaultKey = RandomNumberGenerator.GetBytes(32);

        public QuickUnlockSlotTests() => Directory.CreateDirectory(_dir);

        [Fact]
        public void Biometric_RoundTripsTheVaultKey()
        {
            QuickUnlockSlot.Enroll(_dir, _vaultKey, QuickUnlockMethod.Biometric, _hardware);

            var result = QuickUnlockSlot.TryUnlock(_dir, _hardware, pin: null, out var opened);

            Assert.Equal(QuickUnlockResult.Success, result);
            Assert.Equal(_vaultKey, opened);
        }

        [Fact]
        public void Pin_RoundTripsTheVaultKey()
        {
            QuickUnlockSlot.Enroll(_dir, _vaultKey, QuickUnlockMethod.Pin, _hardware, "1234");

            var result = QuickUnlockSlot.TryUnlock(_dir, _hardware, "1234", out var opened);

            Assert.Equal(QuickUnlockResult.Success, result);
            Assert.Equal(_vaultKey, opened);
        }

        [Fact]
        public void Pin_WithoutTheHardwareSecret_IsUseless()
        {
            // The claim this whole design rests on. Someone who copies the vault folder off the
            // phone holds the slot file and can try every four-digit PIN there is — and none of
            // them opens anything, because the other half of the key never left the device.
            QuickUnlockSlot.Enroll(_dir, _vaultKey, QuickUnlockMethod.Pin, _hardware, "1234");

            var stolenCopy = RandomNumberGenerator.GetBytes(32);   // an attacker's own device
            var result = QuickUnlockSlot.TryUnlock(_dir, stolenCopy, "1234", out var opened);

            Assert.NotEqual(QuickUnlockResult.Success, result);
            Assert.Empty(opened);
        }

        [Fact]
        public void Pin_WrongDigitsDoNotOpenIt()
        {
            QuickUnlockSlot.Enroll(_dir, _vaultKey, QuickUnlockMethod.Pin, _hardware, "1234");

            Assert.Equal(QuickUnlockResult.Wrong,
                QuickUnlockSlot.TryUnlock(_dir, _hardware, "1235", out var opened));
            Assert.Empty(opened);
        }

        [Fact]
        public void Attempts_RunOutAndTakeTheSlotWithThem()
        {
            QuickUnlockSlot.Enroll(_dir, _vaultKey, QuickUnlockMethod.Pin, _hardware, "1234");

            QuickUnlockResult last = QuickUnlockResult.Wrong;
            for (var i = 0; i < QuickUnlockSlot.MaxAttempts; i++)
                last = QuickUnlockSlot.TryUnlock(_dir, _hardware, "0000", out _);

            Assert.Equal(QuickUnlockResult.Exhausted, last);
            Assert.False(QuickUnlockSlot.IsEnrolled(_dir));

            // And the right PIN no longer helps: what is left is the passphrase, which is the
            // point of the limit.
            Assert.Equal(QuickUnlockResult.NotEnrolled,
                QuickUnlockSlot.TryUnlock(_dir, _hardware, "1234", out _));
        }

        [Fact]
        public void Attempts_AreCountedBeforeTheGuessIsChecked()
        {
            // Counting after would let an attacker kill the app between the guess and the write
            // and try forever. Reading the count straight after a failed attempt has to show it
            // already spent.
            QuickUnlockSlot.Enroll(_dir, _vaultKey, QuickUnlockMethod.Pin, _hardware, "1234");
            var before = QuickUnlockSlot.AttemptsLeft(_dir);

            QuickUnlockSlot.TryUnlock(_dir, _hardware, "9999", out _);

            Assert.Equal(before - 1, QuickUnlockSlot.AttemptsLeft(_dir));
        }

        [Fact]
        public void Attempts_ResetOnSuccess()
        {
            QuickUnlockSlot.Enroll(_dir, _vaultKey, QuickUnlockMethod.Pin, _hardware, "1234");

            QuickUnlockSlot.TryUnlock(_dir, _hardware, "0000", out _);
            QuickUnlockSlot.TryUnlock(_dir, _hardware, "0000", out _);
            QuickUnlockSlot.TryUnlock(_dir, _hardware, "1234", out _);

            Assert.Equal(QuickUnlockSlot.MaxAttempts, QuickUnlockSlot.AttemptsLeft(_dir));
        }

        [Fact]
        public void Biometric_ChangedHardwareSecret_ClosesTheSlot()
        {
            // What happens when the platform invalidates the key because the enrolled
            // fingerprints changed: a newly added finger must not inherit the old one's way in.
            QuickUnlockSlot.Enroll(_dir, _vaultKey, QuickUnlockMethod.Biometric, _hardware);

            var reissued = RandomNumberGenerator.GetBytes(32);
            var result = QuickUnlockSlot.TryUnlock(_dir, reissued, pin: null, out var opened);

            Assert.NotEqual(QuickUnlockResult.Success, result);
            Assert.Empty(opened);
        }

        [Fact]
        public void Enroll_TwiceProducesDifferentCipherText()
        {
            // Same key, same PIN, same device: the salt and nonce still have to be fresh, or two
            // vaults on one phone would leak that they hold the same vault key.
            QuickUnlockSlot.Enroll(_dir, _vaultKey, QuickUnlockMethod.Pin, _hardware, "1234");
            var first = File.ReadAllText(Path.Combine(_dir, "vault.quickunlock.json"));

            QuickUnlockSlot.Enroll(_dir, _vaultKey, QuickUnlockMethod.Pin, _hardware, "1234");
            var second = File.ReadAllText(Path.Combine(_dir, "vault.quickunlock.json"));

            Assert.NotEqual(first, second);
        }

        [Fact]
        public void NoSlot_ReportsNotEnrolledRatherThanFailing()
        {
            Assert.False(QuickUnlockSlot.IsEnrolled(_dir));
            Assert.Null(QuickUnlockSlot.EnrolledMethod(_dir));
            Assert.Equal(QuickUnlockResult.NotEnrolled,
                QuickUnlockSlot.TryUnlock(_dir, _hardware, "1234", out _));
        }

        [Fact]
        public void CorruptSlotFile_ReadsAsAbsentAndLeavesThePassphraseWorking()
        {
            QuickUnlockSlot.Enroll(_dir, _vaultKey, QuickUnlockMethod.Biometric, _hardware);
            File.WriteAllText(Path.Combine(_dir, "vault.quickunlock.json"), "{ not json");

            // Refusing to start over a damaged convenience file would be worse than losing the
            // convenience — the vault itself is untouched either way.
            Assert.Equal(QuickUnlockResult.NotEnrolled,
                QuickUnlockSlot.TryUnlock(_dir, _hardware, pin: null, out _));
        }

        [Fact]
        public void Enroll_NeverTouchesTheKeyring()
        {
            // The keyring is the only guaranteed way in. A convenience feature must not be able
            // to damage it, which is why the slot is a separate file.
            var keyringPath = Path.Combine(_dir, "vault.keyring.json");
            var vk = VaultKeyRing.Create(_dir, "una frase larga de prueba");
            var before = File.ReadAllBytes(keyringPath);

            QuickUnlockSlot.Enroll(_dir, vk, QuickUnlockMethod.Pin, _hardware, "1234");
            QuickUnlockSlot.TryUnlock(_dir, _hardware, "0000", out _);
            QuickUnlockSlot.Destroy(_dir);

            Assert.Equal(before, File.ReadAllBytes(keyringPath));
            Assert.True(VaultKeyRing.CanUnlock(_dir, "una frase larga de prueba"));
        }

        [Fact]
        public void Slot_OpensTheSameVaultAsThePassphrase()
        {
            // Both doors, one room: the key that comes back from the slot has to be the very key
            // the passphrase produces, or the vault would decrypt under one and not the other.
            var fromPassphrase = VaultKeyRing.Create(_dir, "una frase larga de prueba");
            QuickUnlockSlot.Enroll(_dir, fromPassphrase, QuickUnlockMethod.Biometric, _hardware);

            QuickUnlockSlot.TryUnlock(_dir, _hardware, pin: null, out var fromSlot);

            Assert.Equal(fromPassphrase, fromSlot);
            Assert.Equal(VaultKeyRing.Unlock(_dir, "una frase larga de prueba"), fromSlot);
        }

        public void Dispose()
        {
            try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
        }
    }
}
