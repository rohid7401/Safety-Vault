using PasswordManager.Core.Configuration;
using PasswordManager.Core.Exceptions;
using PasswordManager.Core.Models;
using PasswordManager.Infrastructure.Encryption;
using PasswordManager.Infrastructure.Persistence;
using PasswordManager.Tests.Helpers;
using Xunit;

namespace PasswordManager.Tests.Persistence
{
    public class PgpVaultRepositoryTests : IDisposable
    {
        private readonly PgpTestFixture _pgp = new();

        private PgpVaultRepository CreateRepo(string? passphrase = null)
        {
            var options = new VaultOptions
            {
                DataFolderPath = _pgp.DataDir,
                Passphrase = passphrase ?? PgpTestFixture.Passphrase
            };
            return new PgpVaultRepository(new PgpService(), options);
        }

        private static VaultData VaultWith(params string[] labels)
        {
            var vault = new VaultData();
            foreach (var label in labels)
                vault.Entries.Add(new SecureNote { Label = label, Title = label });
            return vault;
        }

        private string VaultPath => Path.Combine(_pgp.DataDir, "vault.data.pgp");
        private string IntegrityPath => Path.Combine(_pgp.DataDir, "vault.integrity.json");

        // ─── Round trip ──────────────────────────────────────────────────────

        [Fact]
        public async Task LoadAsync_NoVault_ReturnsEmpty()
        {
            var repo = CreateRepo();
            var vault = await repo.LoadAsync();
            Assert.Empty(vault.Entries);
        }

        [Fact]
        public async Task SaveThenLoad_RoundTrips()
        {
            var repo = CreateRepo();
            await repo.SaveAsync(VaultWith("alpha", "beta"));

            var loaded = await repo.LoadAsync();
            Assert.Equal(2, loaded.Entries.Count);
            Assert.Contains(loaded.Entries, e => e.Label == "alpha");
            Assert.Contains(loaded.Entries, e => e.Label == "beta");
        }

        [Fact]
        public async Task SaveAsync_WritesIntegritySidecar()
        {
            var repo = CreateRepo();
            await repo.SaveAsync(VaultWith("x"));
            Assert.True(File.Exists(IntegrityPath));
        }

        [Fact]
        public async Task Load_FromFreshRepositoryInstance_VerifiesUsingStoredSalt()
        {
            await CreateRepo().SaveAsync(VaultWith("persisted"));

            // A brand-new instance (new session) must re-derive the MAC key from the sidecar salt.
            var loaded = await CreateRepo().LoadAsync();
            Assert.Single(loaded.Entries);
            Assert.Equal("persisted", loaded.Entries[0].Label);
        }

        // ─── Tamper detection (C1) ───────────────────────────────────────────

        [Fact]
        public async Task LoadAsync_TamperedCiphertext_ThrowsIntegrityException()
        {
            var repo = CreateRepo();
            await repo.SaveAsync(VaultWith("secret"));

            var bytes = await File.ReadAllBytesAsync(VaultPath);
            bytes[^1] ^= 0xFF; // flip the last byte
            await File.WriteAllBytesAsync(VaultPath, bytes);

            await Assert.ThrowsAsync<VaultIntegrityException>(() => CreateRepo().LoadAsync());
        }

        [Fact]
        public async Task LoadAsync_MissingIntegritySidecar_ThrowsIntegrityException()
        {
            var repo = CreateRepo();
            await repo.SaveAsync(VaultWith("secret"));

            File.Delete(IntegrityPath);

            await Assert.ThrowsAsync<VaultIntegrityException>(() => CreateRepo().LoadAsync());
        }

        [Fact]
        public async Task LoadAsync_WrongPassphraseMac_ThrowsIntegrityException()
        {
            await CreateRepo().SaveAsync(VaultWith("secret"));

            // Different passphrase → different MAC key → authentication must fail.
            await Assert.ThrowsAsync<VaultIntegrityException>(
                () => CreateRepo("a-totally-different-passphrase").LoadAsync());
        }

        // ─── Backup & restore (C2, M2) ───────────────────────────────────────

        [Fact]
        public async Task SecondSave_CreatesBackup()
        {
            var repo = CreateRepo();
            await repo.SaveAsync(VaultWith("v1"));
            Assert.False(repo.HasBackup()); // first save: nothing to back up yet

            await repo.SaveAsync(VaultWith("v1", "v2"));
            Assert.True(repo.HasBackup());
        }

        [Fact]
        public async Task RestoreFromBackup_RecoversPreviousGoodState()
        {
            var repo = CreateRepo();
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

        public void Dispose() => _pgp.Dispose();
    }
}
