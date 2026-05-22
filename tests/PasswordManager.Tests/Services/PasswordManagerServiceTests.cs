using PasswordManager.Core.Configuration;
using PasswordManager.Core.Models;
using PasswordManager.Core.Services;
using PasswordManager.Infrastructure.Encryption;
using PasswordManager.Infrastructure.Persistence;
using PasswordManager.Tests.Helpers;
using Xunit;

namespace PasswordManager.Tests.Services
{
    public class PasswordManagerServiceTests : IDisposable
    {
        private readonly PgpTestFixture _pgp = new();

        private Task<PasswordManagerService> CreateServiceAsync()
        {
            var options = new VaultOptions
            {
                DataFolderPath = _pgp.DataDir,
                Passphrase = PgpTestFixture.Passphrase
            };
            var pgpService = new PgpService();
            var repository = new PgpVaultRepository(pgpService, options);
            return PasswordManagerService.CreateAsync(repository, new AesService(), pgpService, options);
        }

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
            var badOptions = new VaultOptions
            {
                DataFolderPath = _pgp.DataDir,
                Passphrase = "wrong-passphrase"
            };
            var pgp = new PgpService();
            await Assert.ThrowsAnyAsync<Exception>(() =>
                PasswordManagerService.CreateAsync(
                    new PgpVaultRepository(pgp, badOptions), new AesService(), pgp, badOptions));
        }

        [Fact]
        public async Task CreateAsync_EmptyPassphrase_ThrowsArgumentException()
        {
            var options = new VaultOptions { DataFolderPath = _pgp.DataDir, Passphrase = "" };
            var pgp = new PgpService();
            await Assert.ThrowsAsync<ArgumentException>(() =>
                PasswordManagerService.CreateAsync(
                    new PgpVaultRepository(pgp, options), new AesService(), pgp, options));
        }

        [Fact]
        public async Task CreateAsync_MissingPublicKey_ThrowsFileNotFoundException()
        {
            var options = new VaultOptions
            {
                DataFolderPath = _pgp.DataDir,
                PublicKeyPath = Path.Combine(_pgp.DataDir, "nonexistent.asc"),
                Passphrase = PgpTestFixture.Passphrase
            };
            var pgp = new PgpService();
            await Assert.ThrowsAsync<FileNotFoundException>(() =>
                PasswordManagerService.CreateAsync(
                    new PgpVaultRepository(pgp, options), new AesService(), pgp, options));
        }

        // ─── Empty vault ─────────────────────────────────────────────────────

        [Fact]
        public async Task GetAllEntriesAsync_EmptyVault_ReturnsEmptyList()
        {
            await using var svc = await CreateServiceAsync();
            Assert.Empty(await svc.GetAllEntriesAsync());
        }

        // ─── Add password ────────────────────────────────────────────────────

        [Fact]
        public async Task AddPasswordEntryAsync_PersistsEntry()
        {
            await using var svc = await CreateServiceAsync();
            await svc.AddPasswordEntryAsync(new PasswordEntry { Site = "example.com", Username = "alice" }, "secret123");

            var all = await svc.GetAllEntriesAsync();
            Assert.Single(all);
            var pwd = Assert.IsType<PasswordEntry>(all[0]);
            Assert.Equal("example.com", pwd.Site);
        }

        [Fact]
        public async Task AddPasswordEntryAsync_EncryptsWithGcm()
        {
            await using var svc = await CreateServiceAsync();
            await svc.AddPasswordEntryAsync(new PasswordEntry { Site = "s.com" }, "plaintext");

            var pwd = (await svc.GetEntriesAsync<PasswordEntry>())[0];
            Assert.NotEqual("plaintext", pwd.Password.CipherText);
            Assert.False(string.IsNullOrEmpty(pwd.Password.Nonce));
            Assert.False(string.IsNullOrEmpty(pwd.Password.Tag));
        }

        [Fact]
        public async Task AddPasswordEntryAsync_MultipleEntries()
        {
            await using var svc = await CreateServiceAsync();
            await svc.AddPasswordEntryAsync(new PasswordEntry { Site = "a.com" }, "p1");
            await svc.AddPasswordEntryAsync(new PasswordEntry { Site = "b.com" }, "p2");
            await svc.AddPasswordEntryAsync(new PasswordEntry { Site = "c.com" }, "p3");

            Assert.Equal(3, (await svc.GetAllEntriesAsync()).Count);
        }

        // ─── Add secure note ─────────────────────────────────────────────────

        [Fact]
        public async Task AddSecureNoteAsync_PersistsAndDecrypts()
        {
            await using var svc = await CreateServiceAsync();
            var note = new SecureNote { Title = "SSH Key", Label = "servers" };
            await svc.AddSecureNoteAsync(note, "my private key content");

            var notes = await svc.GetEntriesAsync<SecureNote>();
            Assert.Single(notes);
            Assert.Equal("SSH Key", notes[0].Title);
            Assert.Equal("my private key content", svc.DecryptField(notes[0].Content));
        }

        // ─── Add card entry ──────────────────────────────────────────────────

        [Fact]
        public async Task AddCardEntryAsync_PersistsAndDecrypts()
        {
            await using var svc = await CreateServiceAsync();
            var card = new CardEntry
            {
                CardholderName = "John Doe",
                ExpiryMonth = 12,
                ExpiryYear = 2028
            };
            await svc.AddCardEntryAsync(card, "4111111111111111", "123");

            var cards = await svc.GetEntriesAsync<CardEntry>();
            Assert.Single(cards);
            Assert.Equal("John Doe", cards[0].CardholderName);
            Assert.Equal("4111111111111111", svc.DecryptField(cards[0].CardNumber));
            Assert.Equal("123", svc.DecryptField(cards[0].Cvv));
        }

        // ─── Mixed entry types ───────────────────────────────────────────────

        [Fact]
        public async Task GetAllEntriesAsync_ReturnsMixedTypes()
        {
            await using var svc = await CreateServiceAsync();
            await svc.AddPasswordEntryAsync(new PasswordEntry { Site = "git.com" }, "p");
            await svc.AddSecureNoteAsync(new SecureNote { Title = "Note" }, "text");
            await svc.AddCardEntryAsync(new CardEntry { CardholderName = "Jane" }, "4111", "999");

            var all = await svc.GetAllEntriesAsync();
            Assert.Equal(3, all.Count);
            Assert.Single(all.OfType<PasswordEntry>());
            Assert.Single(all.OfType<SecureNote>());
            Assert.Single(all.OfType<CardEntry>());
        }

        [Fact]
        public async Task GetEntriesAsync_FiltersByType()
        {
            await using var svc = await CreateServiceAsync();
            await svc.AddPasswordEntryAsync(new PasswordEntry { Site = "a.com" }, "p1");
            await svc.AddPasswordEntryAsync(new PasswordEntry { Site = "b.com" }, "p2");
            await svc.AddSecureNoteAsync(new SecureNote { Title = "Note" }, "text");

            Assert.Equal(2, (await svc.GetEntriesAsync<PasswordEntry>()).Count);
            Assert.Single(await svc.GetEntriesAsync<SecureNote>());
            Assert.Empty(await svc.GetEntriesAsync<CardEntry>());
        }

        // ─── Tags ────────────────────────────────────────────────────────────

        [Fact]
        public async Task Tags_PersistOnEntries()
        {
            await using var svc = await CreateServiceAsync();
            var entry = new PasswordEntry { Site = "work.com", Tags = { "work", "dev" } };
            await svc.AddPasswordEntryAsync(entry, "pass");

            var stored = (await svc.GetEntriesAsync<PasswordEntry>())[0];
            Assert.Equal(2, stored.Tags.Count);
            Assert.Contains("work", stored.Tags);
            Assert.Contains("dev", stored.Tags);
        }

        [Fact]
        public async Task FindEntriesAsync_ByTag()
        {
            await using var svc = await CreateServiceAsync();
            await svc.AddPasswordEntryAsync(new PasswordEntry { Site = "a.com", Tags = { "personal" } }, "p1");
            await svc.AddPasswordEntryAsync(new PasswordEntry { Site = "b.com", Tags = { "work" } }, "p2");
            await svc.AddSecureNoteAsync(new SecureNote { Title = "N", Tags = { "work" } }, "t");

            var workEntries = await svc.FindEntriesAsync(e => e.Tags.Contains("work"));
            Assert.Equal(2, workEntries.Count);
        }

        // ─── Decrypt ─────────────────────────────────────────────────────────

        [Fact]
        public async Task DecryptPassword_ReturnsOriginalPlaintext()
        {
            await using var svc = await CreateServiceAsync();
            await svc.AddPasswordEntryAsync(new PasswordEntry { Site = "s.com" }, "my-secret-password");

            var pwd = (await svc.GetEntriesAsync<PasswordEntry>())[0];
            Assert.Equal("my-secret-password", svc.DecryptPassword(pwd));
        }

        [Fact]
        public async Task DecryptPassword_UnicodePlaintext_RoundTrips()
        {
            await using var svc = await CreateServiceAsync();
            const string unicode = "P@ñoño-🔐-Ünïcödé-密码";
            await svc.AddPasswordEntryAsync(new PasswordEntry { Site = "s.com" }, unicode);

            var pwd = (await svc.GetEntriesAsync<PasswordEntry>())[0];
            Assert.Equal(unicode, svc.DecryptPassword(pwd));
        }

        // ─── Get by ID ───────────────────────────────────────────────────────

        [Fact]
        public async Task GetEntryByIdAsync_ExistingId_ReturnsEntry()
        {
            await using var svc = await CreateServiceAsync();
            var entry = new PasswordEntry { Site = "find.me" };
            await svc.AddPasswordEntryAsync(entry, "pass");

            var found = await svc.GetEntryByIdAsync(entry.Id);
            Assert.NotNull(found);
            Assert.Equal("find.me", Assert.IsType<PasswordEntry>(found).Site);
        }

        [Fact]
        public async Task GetEntryByIdAsync_MissingId_ReturnsNull()
        {
            await using var svc = await CreateServiceAsync();
            Assert.Null(await svc.GetEntryByIdAsync(Guid.NewGuid()));
        }

        // ─── Find ────────────────────────────────────────────────────────────

        [Fact]
        public async Task FindEntriesAsync_MatchingPredicate()
        {
            await using var svc = await CreateServiceAsync();
            await svc.AddPasswordEntryAsync(new PasswordEntry { Site = "github.com" }, "p1");
            await svc.AddPasswordEntryAsync(new PasswordEntry { Site = "gitlab.com" }, "p2");
            await svc.AddPasswordEntryAsync(new PasswordEntry { Site = "amazon.com" }, "p3");

            var git = await svc.FindEntriesAsync(e => e is PasswordEntry p && p.Site.StartsWith("git"));
            Assert.Equal(2, git.Count);
        }

        // ─── Update ──────────────────────────────────────────────────────────

        [Fact]
        public async Task UpdateEntryAsync_ModifiesField()
        {
            await using var svc = await CreateServiceAsync();
            var entry = new PasswordEntry { Site = "old.com" };
            await svc.AddPasswordEntryAsync(entry, "pass");

            await svc.UpdateEntryAsync(entry.Id, e => ((PasswordEntry)e).Site = "new.com");

            var updated = Assert.IsType<PasswordEntry>(await svc.GetEntryByIdAsync(entry.Id));
            Assert.Equal("new.com", updated.Site);
        }

        [Fact]
        public async Task UpdateEntryAsync_NonExistentId_DoesNotThrow()
        {
            await using var svc = await CreateServiceAsync();
            var ex = await Record.ExceptionAsync(() => svc.UpdateEntryAsync(Guid.NewGuid(), _ => { }));
            Assert.Null(ex);
        }

        // ─── Change password ─────────────────────────────────────────────────

        [Fact]
        public async Task ChangePasswordAsync_UpdatesDecryptedPassword()
        {
            await using var svc = await CreateServiceAsync();
            var entry = new PasswordEntry { Site = "s.com" };
            await svc.AddPasswordEntryAsync(entry, "old-password");
            await svc.ChangePasswordAsync(entry.Id, "new-password");

            var pwd = Assert.IsType<PasswordEntry>(await svc.GetEntryByIdAsync(entry.Id));
            Assert.Equal("new-password", svc.DecryptPassword(pwd));
        }

        // ─── Soft delete ─────────────────────────────────────────────────────

        [Fact]
        public async Task DeleteEntryAsync_SoftDeletesEntry()
        {
            await using var svc = await CreateServiceAsync();
            var entry = new PasswordEntry { Site = "delete.me" };
            await svc.AddPasswordEntryAsync(entry, "pass");

            await svc.DeleteEntryAsync(entry.Id);

            Assert.Empty(await svc.GetAllEntriesAsync());
            var deleted = await svc.GetDeletedEntriesAsync();
            Assert.Single(deleted);
            Assert.Equal(entry.Id, deleted[0].Id);
            Assert.True(deleted[0].IsDeleted);
            Assert.NotNull(deleted[0].DeletedAt);
        }

        [Fact]
        public async Task RestoreEntryAsync_RestoresSoftDeletedEntry()
        {
            await using var svc = await CreateServiceAsync();
            var entry = new PasswordEntry { Site = "restore.me" };
            await svc.AddPasswordEntryAsync(entry, "pass");
            await svc.DeleteEntryAsync(entry.Id);

            await svc.RestoreEntryAsync(entry.Id);

            Assert.Single(await svc.GetAllEntriesAsync());
            Assert.Empty(await svc.GetDeletedEntriesAsync());
        }

        [Fact]
        public async Task PurgeDeletedAsync_PermanentlyRemovesDeletedEntries()
        {
            await using var svc = await CreateServiceAsync();
            await svc.AddPasswordEntryAsync(new PasswordEntry { Site = "keep.me" }, "p1");
            var toDelete = new PasswordEntry { Site = "purge.me" };
            await svc.AddPasswordEntryAsync(toDelete, "p2");
            await svc.DeleteEntryAsync(toDelete.Id);

            await svc.PurgeDeletedAsync();

            Assert.Single(await svc.GetAllEntriesAsync());
            Assert.Empty(await svc.GetDeletedEntriesAsync());
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
            await svc.AddPasswordEntryAsync(entry, "pass");

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
                await svc.AddPasswordEntryAsync(new PasswordEntry { Site = "persist.com", Username = "bob" }, "abc");

            await using var svc2 = await CreateServiceAsync();
            var all = await svc2.GetAllEntriesAsync();
            Assert.Single(all);
            Assert.Equal("persist.com", Assert.IsType<PasswordEntry>(all[0]).Site);
        }

        [Fact]
        public async Task MixedTypes_PersistAcrossServiceInstances()
        {
            await using (var svc = await CreateServiceAsync())
            {
                await svc.AddPasswordEntryAsync(new PasswordEntry { Site = "a.com" }, "p");
                await svc.AddSecureNoteAsync(new SecureNote { Title = "N" }, "text");
                await svc.AddCardEntryAsync(new CardEntry { CardholderName = "J" }, "4111", "123");
            }

            await using var svc2 = await CreateServiceAsync();
            var all = await svc2.GetAllEntriesAsync();
            Assert.Equal(3, all.Count);
            Assert.Single(all.OfType<PasswordEntry>());
            Assert.Single(all.OfType<SecureNote>());
            Assert.Single(all.OfType<CardEntry>());

            var card = all.OfType<CardEntry>().First();
            Assert.Equal("4111", svc2.DecryptField(card.CardNumber));
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
