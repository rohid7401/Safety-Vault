using PasswordManager.Infrastructure.Encryption;
using Xunit;

namespace PasswordManager.Tests.Encryption
{
    public class VaultKeyRingTests : IDisposable
    {
        private readonly string _dataDir =
            Path.Combine(Path.GetTempPath(), "pmgr_test_" + Guid.NewGuid().ToString("N"));

        private const string Passphrase = "correct-horse-battery-staple";

        public VaultKeyRingTests() => Directory.CreateDirectory(_dataDir);

        [Fact]
        public void Create_ThenUnlock_ReturnsTheSameVaultKey()
        {
            var created = VaultKeyRing.Create(_dataDir, Passphrase);
            var unlocked = VaultKeyRing.Unlock(_dataDir, Passphrase);

            Assert.Equal(created, unlocked);
        }

        [Fact]
        public void Unlock_WrongPassphrase_Throws()
        {
            VaultKeyRing.Create(_dataDir, Passphrase);

            Assert.Throws<UnauthorizedAccessException>(
                () => VaultKeyRing.Unlock(_dataDir, "a-totally-different-passphrase"));
        }

        [Fact]
        public void Unlock_NoKeyringYet_ThrowsFileNotFoundException()
        {
            Assert.Throws<FileNotFoundException>(() => VaultKeyRing.Unlock(_dataDir, Passphrase));
        }

        [Fact]
        public void CanUnlock_CorrectPassphrase_ReturnsTrue()
        {
            VaultKeyRing.Create(_dataDir, Passphrase);
            Assert.True(VaultKeyRing.CanUnlock(_dataDir, Passphrase));
        }

        [Fact]
        public void CanUnlock_WrongPassphrase_ReturnsFalse()
        {
            VaultKeyRing.Create(_dataDir, Passphrase);
            Assert.False(VaultKeyRing.CanUnlock(_dataDir, "nope"));
        }

        [Fact]
        public void CanUnlock_NoKeyringYet_ReturnsFalse()
        {
            Assert.False(VaultKeyRing.CanUnlock(_dataDir, Passphrase));
        }

        [Fact]
        public void DeriveSubkey_DifferentInfo_ProducesDifferentKeys()
        {
            var vk = VaultKeyRing.Create(_dataDir, Passphrase);

            var blobKey = VaultKeyRing.DeriveSubkey(vk, VaultKeyRing.BlobKeyInfo);
            var fieldKey = VaultKeyRing.DeriveSubkey(vk, VaultKeyRing.FieldKeyInfo);

            Assert.NotEqual(blobKey, fieldKey);
        }

        [Fact]
        public void DeriveSubkey_SameInputs_IsDeterministic()
        {
            var vk = VaultKeyRing.Create(_dataDir, Passphrase);

            var first = VaultKeyRing.DeriveSubkey(vk, VaultKeyRing.BlobKeyInfo);
            var second = VaultKeyRing.DeriveSubkey(vk, VaultKeyRing.BlobKeyInfo);

            Assert.Equal(first, second);
        }

        public void Dispose()
        {
            try { Directory.Delete(_dataDir, recursive: true); } catch { /* best effort */ }
        }
    }
}
