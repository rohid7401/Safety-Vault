using PasswordManager.Core.Models;
using PasswordManager.Core.Services;
using PasswordManager.Infrastructure.Encryption;
using PasswordManager.Tests.Helpers;
using Xunit;

namespace PasswordManager.Tests.Services
{
    /// <summary>
    /// Integration tests using real PGP key pairs and AES-GCM.
    /// Each test gets a fresh vault directory via PgpTestFixture.
    /// </summary>
    public class PasswordManagerServiceTests : IDisposable
    {
        private readonly PgpTestFixture _pgp = new();

        private Task<PasswordManagerService> CreateServiceAsync() =>
            PasswordManagerService.CreateAsync(
                dataFolderPath: _pgp.DataDir,
                pgpService: new PgpService(),
                aesService: new AesService(),
                pgpPassphrase: PgpTestFixture.Passphrase);

        // ─── Initialization ──────────────────────────────────────────────────

        [Fact]
        public async Task CreateAsync_ValidKeys_ReturnsService()
        {
            await using var svc = await CreateServiceAsync();
            Assert.NotNull(svc);
        }

        [Fact]
        public async Task CreateAsync_CreatesAesKeyFile()
        {
            await using var svc = await CreateServiceAsync();
            Assert.True(File.Exists(Path.Combine(_pgp.DataDir, "vault.key.pgp")));
        }

        [Fact]
        public async Task CreateAsync_WrongPassphrase_ThrowsException()
        {
            await using var _ = await CreateServiceAsync();
            await Assert.ThrowsAnyAsync<Exception>(() =>
                PasswordManagerService.CreateAsync(
                    _pgp.DataDir,
                    new PgpService(),
                    new AesService(),
                    pgpPassphrase: "wrong-passphrase"));
        }

        [Fact]
        public async Task CreateAsync_EmptyPassphrase_ThrowsArgumentException()
        {
            await Assert.ThrowsAsync<ArgumentException>(() =>
                PasswordManagerService.CreateAsync(
                    _pgp.DataDir, new PgpService(), new AesService(), pgpPassphrase: ""));
        }

        [Fact]
        public async Task CreateAsync_MissingPublicKey_ThrowsFileNotFoundException()
        {
            await Assert.ThrowsAsync<FileNotFoundException>(() =>
                PasswordManagerService.CreateAsync(
                    _pgp.DataDir, new PgpService(), new AesService(),
                    pgpPublicKeyPath: Path.Combine(_pgp.DataDir, "nonexistent.asc"),
                    pgpPassphrase: PgpTestFixture.Passphrase));
        }

        // ─── Empty vault ─────────────────────────────────────────────────────

        [Fact]
        public async Task GetAllEntriesAsync_EmptyVault_ReturnsEmptyList()
        {
            await using var svc = await CreateServiceAsync();
            Assert.Empty(await svc.GetAllEntriesAsync());
        }

        // ─── Add ─────────────────────────────────────────────────────────────

        [Fact]
        public async Task AddEntryAsync_PersistsEntry()
        {
            await using var svc = await CreateServiceAsync();
            await svc.AddEntryAsync(new PasswordEntry { Site = "example.com", Username = "alice" }, "secret123");

            var all = await svc.GetAllEntriesAsync();
            Assert.Single(all);
            Assert.Equal("example.com", all[0].Site);
        }

        [Fact]
        public async Task AddEntryAsync_EncryptsPasswordWithGcmFields()
        {
            await using var svc = await CreateServiceAsync();
            var entry = new PasswordEntry { Site = "site.com" };
            await svc.AddEntryAsync(entry, "plaintext");

            var stored = (await svc.GetAllEntriesAsync())[0];
            Assert.NotEqual("plaintext", stored.EncryptedPassword);
            Assert.False(string.IsNullOrEmpty(stored.Nonce));
            Assert.False(string.IsNullOrEmpty(stored.Tag));
        }

        [Fact]
        public async Task AddEntryAsync_MultipleEntries_AllPersist()
        {
            await using var svc = await CreateServiceAsync();
            await svc.AddEntryAsync(new PasswordEntry { Site = "a.com" }, "p1");
            await svc.AddEntryAsync(new PasswordEntry { Site = "b.com" }, "p2");
            await svc.AddEntryAsync(new PasswordEntry { Site = "c.com" }, "p3");

            Assert.Equal(3, (await svc.GetAllEntriesAsync()).Count);
        }

        // ─── Decrypt ─────────────────────────────────────────────────────────

        [Fact]
        public async Task DecryptPassword_ReturnsOriginalPlaintext()
        {
            await using var svc = await CreateServiceAsync();
            var entry = new PasswordEntry { Site = "site.com" };
            await svc.AddEntryAsync(entry, "my-secret-password");

            var stored = (await svc.GetAllEntriesAsync())[0];
            Assert.Equal("my-secret-password", svc.DecryptPassword(stored));
        }

        [Fact]
        public async Task DecryptPassword_UnicodePlaintext_RoundTrips()
        {
            await using var svc = await CreateServiceAsync();
            const string unicode = "P@ñoño-🔐-Ünïcödé-密码";
            var entry = new PasswordEntry { Site = "site.com" };
            await svc.AddEntryAsync(entry, unicode);

            var stored = (await svc.GetAllEntriesAsync())[0];
            Assert.Equal(unicode, svc.DecryptPassword(stored));
        }

        // ─── Get by ID ───────────────────────────────────────────────────────

        [Fact]
        public async Task GetEntryByIdAsync_ExistingId_ReturnsEntry()
        {
            await using var svc = await CreateServiceAsync();
            var entry = new PasswordEntry { Site = "find.me" };
            await svc.AddEntryAsync(entry, "pass");

            var found = await svc.GetEntryByIdAsync(entry.Id);
            Assert.NotNull(found);
            Assert.Equal("find.me", found.Site);
        }

        [Fact]
        public async Task GetEntryByIdAsync_MissingId_ReturnsNull()
        {
            await using var svc = await CreateServiceAsync();
            Assert.Null(await svc.GetEntryByIdAsync(Guid.NewGuid()));
        }

        // ─── Find ────────────────────────────────────────────────────────────

        [Fact]
        public async Task FindEntriesAsync_MatchingPredicate_ReturnsSubset()
        {
            await using var svc = await CreateServiceAsync();
            await svc.AddEntryAsync(new PasswordEntry { Site = "github.com" }, "p1");
            await svc.AddEntryAsync(new PasswordEntry { Site = "gitlab.com" }, "p2");
            await svc.AddEntryAsync(new PasswordEntry { Site = "amazon.com" }, "p3");

            var gitEntries = await svc.FindEntriesAsync(e => e.Site.StartsWith("git"));
            Assert.Equal(2, gitEntries.Count);
        }

        // ─── Update ──────────────────────────────────────────────────────────

        [Fact]
        public async Task UpdateEntryAsync_ModifiesField()
        {
            await using var svc = await CreateServiceAsync();
            var entry = new PasswordEntry { Site = "old.com" };
            await svc.AddEntryAsync(entry, "pass");
            await svc.UpdateEntryAsync(entry.Id, e => e.Site = "new.com");

            Assert.Equal("new.com", (await svc.GetEntryByIdAsync(entry.Id))!.Site);
        }

        [Fact]
        public async Task UpdateEntryAsync_NonExistentId_DoesNotThrow()
        {
            await using var svc = await CreateServiceAsync();
            var ex = await Record.ExceptionAsync(() => svc.UpdateEntryAsync(Guid.NewGuid(), e => e.Site = "x"));
            Assert.Null(ex);
        }

        // ─── Change password ─────────────────────────────────────────────────

        [Fact]
        public async Task ChangePasswordAsync_UpdatesDecryptedPassword()
        {
            await using var svc = await CreateServiceAsync();
            var entry = new PasswordEntry { Site = "site.com" };
            await svc.AddEntryAsync(entry, "old-password");
            await svc.ChangePasswordAsync(entry.Id, "new-password");

            Assert.Equal("new-password", svc.DecryptPassword((await svc.GetEntryByIdAsync(entry.Id))!));
        }

        // ─── Delete ──────────────────────────────────────────────────────────

        [Fact]
        public async Task DeleteEntryAsync_RemovesEntry()
        {
            await using var svc = await CreateServiceAsync();
            var entry = new PasswordEntry { Site = "delete.me" };
            await svc.AddEntryAsync(entry, "pass");
            await svc.DeleteEntryAsync(entry.Id);

            Assert.Empty(await svc.GetAllEntriesAsync());
        }

        [Fact]
        public async Task DeleteEntryAsync_NonExistentId_DoesNotThrow()
        {
            await using var svc = await CreateServiceAsync();
            var ex = await Record.ExceptionAsync(() => svc.DeleteEntryAsync(Guid.NewGuid()));
            Assert.Null(ex);
        }

        // ─── Expiration ──────────────────────────────────────────────────────

        [Fact]
        public async Task SetExpireTimeAsync_PersistsExpiration()
        {
            await using var svc = await CreateServiceAsync();
            var entry = new PasswordEntry { Site = "expiring.com" };
            await svc.AddEntryAsync(entry, "pass");

            var expiry = DateTime.UtcNow.AddDays(30);
            await svc.SetExpireTimeAsync(entry.Id, expiry);

            var stored = await svc.GetEntryByIdAsync(entry.Id);
            Assert.NotNull(stored!.ExpireTime);
            Assert.Equal(expiry, stored.ExpireTime!.Value, TimeSpan.FromSeconds(1));
        }

        // ─── Persistence across sessions ─────────────────────────────────────

        [Fact]
        public async Task Entries_PersistAcrossServiceInstances()
        {
            await using (var svc = await CreateServiceAsync())
                await svc.AddEntryAsync(new PasswordEntry { Site = "persist.com", Username = "bob" }, "abc");

            await using var svc2 = await CreateServiceAsync();
            var all = await svc2.GetAllEntriesAsync();
            Assert.Single(all);
            Assert.Equal("persist.com", all[0].Site);
        }

        // ─── IDisposable ─────────────────────────────────────────────────────

        [Fact]
        public async Task Dispose_ThenGetAllEntries_ThrowsObjectDisposedException()
        {
            var svc = await CreateServiceAsync();
            svc.Dispose();
            await Assert.ThrowsAsync<ObjectDisposedException>(() => svc.GetAllEntriesAsync());
        }

        public void Dispose() => _pgp.Dispose();
    }
}
