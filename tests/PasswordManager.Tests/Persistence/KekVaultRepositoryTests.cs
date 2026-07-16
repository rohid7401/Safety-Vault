using System.Security.Cryptography;
using PasswordManager.Core.Exceptions;
using PasswordManager.Core.Models;
using PasswordManager.Infrastructure.Persistence;
using Xunit;

namespace PasswordManager.Tests.Persistence
{
    public class KekVaultRepositoryTests : IDisposable
    {
        private readonly string _dataDir =
            Path.Combine(Path.GetTempPath(), "pmgr_test_" + Guid.NewGuid().ToString("N"));

        public KekVaultRepositoryTests() => Directory.CreateDirectory(_dataDir);

        private static byte[] NewKey() => RandomNumberGenerator.GetBytes(32);

        private KekVaultRepository CreateRepo(byte[]? key = null) =>
            new(key ?? NewKey(), _dataDir);

        private static VaultData VaultWith(params string[] labels)
        {
            var vault = new VaultData();
            foreach (var label in labels)
                vault.Entries.Add(new SecureNote { Label = label, Title = label });
            return vault;
        }

        private string VaultPath => Path.Combine(_dataDir, "vault.data");

        // ─── Round trip ──────────────────────────────────────────────────────

        [Fact]
        public async Task LoadAsync_NoVault_ReturnsEmpty()
        {
            var vault = await CreateRepo().LoadAsync();
            Assert.Empty(vault.Entries);
        }

        [Fact]
        public async Task SaveThenLoad_RoundTrips()
        {
            var key = NewKey();
            await CreateRepo(key).SaveAsync(VaultWith("alpha", "beta"));

            var loaded = await CreateRepo(key).LoadAsync();
            Assert.Equal(2, loaded.Entries.Count);
            Assert.Contains(loaded.Entries, e => e.Label == "alpha");
            Assert.Contains(loaded.Entries, e => e.Label == "beta");
        }

        [Fact]
        public async Task SaveThenLoad_PreservesPgpKeyFields()
        {
            var key = NewKey();
            var vault = new VaultData
            {
                PgpPublicKeyArmored = "-----BEGIN PGP PUBLIC KEY-----\nfake\n-----END-----",
                PgpPrivateKeyArmored = "-----BEGIN PGP PRIVATE KEY-----\nfake\n-----END-----",
            };
            await CreateRepo(key).SaveAsync(vault);

            var loaded = await CreateRepo(key).LoadAsync();
            Assert.Equal(vault.PgpPublicKeyArmored, loaded.PgpPublicKeyArmored);
            Assert.Equal(vault.PgpPrivateKeyArmored, loaded.PgpPrivateKeyArmored);
        }

        [Fact]
        public async Task Load_FromFreshRepositoryInstance_WithSameKey_Succeeds()
        {
            var key = NewKey();
            await CreateRepo(key).SaveAsync(VaultWith("persisted"));

            // A brand-new instance (new session) with the same blob key must decrypt fine.
            var loaded = await CreateRepo(key).LoadAsync();
            Assert.Single(loaded.Entries);
            Assert.Equal("persisted", loaded.Entries[0].Label);
        }

        // ─── Tamper / wrong-key detection ────────────────────────────────────

        [Fact]
        public async Task LoadAsync_TamperedCiphertext_ThrowsIntegrityException()
        {
            var key = NewKey();
            await CreateRepo(key).SaveAsync(VaultWith("secret"));

            var bytes = await File.ReadAllBytesAsync(VaultPath);
            bytes[^1] ^= 0xFF; // flip the last byte
            await File.WriteAllBytesAsync(VaultPath, bytes);

            await Assert.ThrowsAsync<VaultIntegrityException>(() => CreateRepo(key).LoadAsync());
        }

        [Fact]
        public async Task LoadAsync_WrongBlobKey_ThrowsIntegrityException()
        {
            await CreateRepo(NewKey()).SaveAsync(VaultWith("secret"));

            // A different key (e.g. a wrong passphrase's derived KEK/VK/subkey) must fail
            // the AES-GCM authentication tag check.
            await Assert.ThrowsAsync<VaultIntegrityException>(() => CreateRepo(NewKey()).LoadAsync());
        }

        [Fact]
        public async Task LoadAsync_TruncatedFile_ThrowsIntegrityException()
        {
            var key = NewKey();
            await CreateRepo(key).SaveAsync(VaultWith("secret"));

            await File.WriteAllBytesAsync(VaultPath, new byte[4]); // shorter than nonce+tag

            await Assert.ThrowsAsync<VaultIntegrityException>(() => CreateRepo(key).LoadAsync());
        }

        // ─── Backup & restore (C2, M2) ───────────────────────────────────────

        [Fact]
        public async Task SecondSave_CreatesBackup()
        {
            var key = NewKey();
            var repo = CreateRepo(key);
            await repo.SaveAsync(VaultWith("v1"));
            Assert.False(repo.HasBackup()); // first save: nothing to back up yet

            await repo.SaveAsync(VaultWith("v1", "v2"));
            Assert.True(repo.HasBackup());
        }

        [Fact]
        public async Task RestoreFromBackup_RecoversPreviousGoodState()
        {
            var key = NewKey();
            var repo = CreateRepo(key);
            await repo.SaveAsync(VaultWith("only-v1"));
            await repo.SaveAsync(VaultWith("only-v1", "added-v2"));

            // Corrupt the live vault.
            var bytes = await File.ReadAllBytesAsync(VaultPath);
            bytes[0] ^= 0xFF;
            await File.WriteAllBytesAsync(VaultPath, bytes);

            await Assert.ThrowsAsync<VaultIntegrityException>(() => repo.LoadAsync());

            var restored = await repo.RestoreFromBackupAsync();
            Assert.Single(restored.Entries);
            Assert.Equal("only-v1", restored.Entries[0].Label);

            // And the live vault now loads cleanly again.
            var reloaded = await repo.LoadAsync();
            Assert.Single(reloaded.Entries);
        }

        [Fact]
        public async Task RestoreFromBackup_NoBackup_Throws()
        {
            var repo = CreateRepo();
            await Assert.ThrowsAsync<VaultIntegrityException>(() => repo.RestoreFromBackupAsync());
        }

        public void Dispose()
        {
            try { Directory.Delete(_dataDir, recursive: true); } catch { /* best effort */ }
        }
    }
}
