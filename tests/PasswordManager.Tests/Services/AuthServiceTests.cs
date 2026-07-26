using PasswordManager.Core.Configuration;
using PasswordManager.Core.Models;
using PasswordManager.Core.Services;
using PasswordManager.Infrastructure.Encryption;
using PasswordManager.Infrastructure.Persistence;
using PasswordManager.Infrastructure.Services;
using Xunit;
using PasswordManager.Core.Exceptions;

namespace PasswordManager.Tests.Services
{
    public class AuthServiceTests : IDisposable
    {
        private readonly string _appDataDir =
            Path.Combine(Path.GetTempPath(), "pmgr_test_" + Guid.NewGuid().ToString("N"));

        private const string Passphrase = "correct-horse-battery-staple";

        private AuthService CreateAuthService() =>
            new(new PgpService(), new AuthOptions { AppDataPath = _appDataDir });

        [Fact]
        public async Task RegisterAsync_CreatesVaultKeyring()
        {
            var auth = CreateAuthService();
            var account = await auth.RegisterAsync("alice", "alice@example.com", Passphrase);

            Assert.True(File.Exists(Path.Combine(account.VaultPath, "vault.keyring.json")));
        }

        [Fact]
        public async Task RegisterAsync_SeedsVaultWithOwnPgpKeyPair()
        {
            var auth = CreateAuthService();
            var account = await auth.RegisterAsync("alice", "alice@example.com", Passphrase);

            var vaultKey = VaultKeyRing.Unlock(account.VaultPath, Passphrase);
            var blobKey = VaultKeyRing.DeriveSubkey(vaultKey, VaultKeyRing.BlobKeyInfo);
            using var repo = new KekVaultRepository(blobKey, account.VaultPath);
            var vault = await repo.LoadAsync();

            Assert.False(string.IsNullOrEmpty(vault.PgpPublicKeyArmored));
            Assert.False(string.IsNullOrEmpty(vault.PgpPrivateKeyArmored));
            Assert.Equal(
                await File.ReadAllTextAsync(Path.Combine(account.VaultPath, "public_key.asc")),
                vault.PgpPublicKeyArmored);
        }

        [Fact]
        public async Task LoginAsync_CorrectPassphrase_Succeeds()
        {
            var auth = CreateAuthService();
            await auth.RegisterAsync("alice", "alice@example.com", Passphrase);

            var account = await auth.LoginAsync("alice", Passphrase);
            Assert.Equal("alice", account.Username);
        }

        [Fact]
        public async Task LoginAsync_WrongPassphrase_ThrowsUnauthorizedAccessException()
        {
            var auth = CreateAuthService();
            await auth.RegisterAsync("alice", "alice@example.com", Passphrase);

            var ex = await Assert.ThrowsAsync<LocalizedUnauthorizedAccessException>(
                () => auth.LoginAsync("alice", "wrong-passphrase"));
            Assert.Equal(AppErrorCode.BadCredentials, ex.Code);
        }

        [Fact]
        public async Task LoginAsync_UnknownAccount_ThrowsUnauthorizedAccessException()
        {
            var auth = CreateAuthService();
            var ex = await Assert.ThrowsAsync<LocalizedUnauthorizedAccessException>(
                () => auth.LoginAsync("nobody", Passphrase));
            Assert.Equal(AppErrorCode.BadCredentials, ex.Code);
        }

        // ─── N1: anti-enumeration ────────────────────────────────────────────

        [Fact]
        public async Task LoginAsync_WrongPassphraseAndUnknownAccount_ProduceIdenticalMessage()
        {
            var auth = CreateAuthService();
            await auth.RegisterAsync("alice", "alice@example.com", Passphrase);

            var wrongPass = await Assert.ThrowsAsync<LocalizedUnauthorizedAccessException>(
                () => auth.LoginAsync("alice", "wrong-passphrase"));
            var noAccount = await Assert.ThrowsAsync<LocalizedUnauthorizedAccessException>(
                () => auth.LoginAsync("nobody", Passphrase));

            // Both branches must report the identical code: it is the code, not the prose, that
            // now decides what the user is shown, so a difference here would leak whether the
            // account exists no matter how carefully the two sentences were worded.
            Assert.Equal(AppErrorCode.BadCredentials, wrongPass.Code);
            Assert.Equal(AppErrorCode.BadCredentials, noAccount.Code);
            Assert.Empty(wrongPass.Args);
            Assert.Empty(noAccount.Args);
        }

        [Fact]
        public async Task RegisterAsync_DuplicateUsername_Throws()
        {
            var auth = CreateAuthService();
            await auth.RegisterAsync("alice", "alice@example.com", Passphrase);

            var ex = await Assert.ThrowsAsync<LocalizedInvalidOperationException>(
                () => auth.RegisterAsync("alice", "another@example.com", Passphrase));
            Assert.Equal(AppErrorCode.UsernameTaken, ex.Code);
        }

        // ─── N2: concurrent registrations don't lose accounts ────────────────

        [Fact]
        public async Task RegisterAsync_ConcurrentRegistrations_AllPersist()
        {
            var auth = CreateAuthService();

            // Fire several registrations at once. Without the load-modify-save lock, some
            // would read the same account list and clobber each other on save (lost update).
            var tasks = Enumerable.Range(0, 4)
                .Select(i => auth.RegisterAsync($"user{i}", $"user{i}@example.com", Passphrase))
                .ToArray();
            await Task.WhenAll(tasks);

            var usernames = await auth.ListUsernamesAsync();
            Assert.Equal(4, usernames.Count);
            for (int i = 0; i < 4; i++)
                Assert.Contains($"user{i}", usernames);
        }

        /// <summary>
        /// Reproduces the exact sequence Home.razor's UnlockVaultAsync performs, end to end:
        /// register → add an entry → "close the app" → log in again on a fresh session →
        /// re-derive the same keys → confirm the entry is still there and the PGP files
        /// materialize.
        /// </summary>
        [Fact]
        public async Task FullFlow_RegisterAddEntryThenLoginAgain_EntryPersistsAndPgpFilesExist()
        {
            var auth = CreateAuthService();
            var account = await auth.RegisterAsync("bob", "bob@example.com", Passphrase);

            await using (var svc = await UnlockLikeHomeRazorAsync(account.VaultPath, Passphrase))
            {
                var cred = new Credential();
                cred.Fields.Add(new CredentialField
                {
                    Type = CredentialFieldType.Password,
                    IsSecret = true,
                    SecretValue = svc.EncryptValue("s3cret"),
                });
                await svc.AddServiceEntryAsync(new ServiceEntry { Site = "example.com", Credentials = { cred } });
            }

            // Simulate a fresh app launch: log in again, independently re-deriving everything.
            var reloadedAccount = await auth.LoginAsync("bob", Passphrase);
            await using var svc2 = await UnlockLikeHomeRazorAsync(reloadedAccount.VaultPath, Passphrase);
            await svc2.EnsurePgpKeyFilesAsync(reloadedAccount.VaultPath);

            var entries = await svc2.GetAllEntriesAsync();
            Assert.Single(entries);
            var entry = Assert.IsType<ServiceEntry>(entries[0]);
            Assert.Equal("s3cret", svc2.DecryptSecret(entry.Credentials[0].Fields[0]));

            Assert.True(File.Exists(Path.Combine(reloadedAccount.VaultPath, "public_key.asc")));
            Assert.True(File.Exists(Path.Combine(reloadedAccount.VaultPath, "private_key.asc")));
        }

        private static async Task<PasswordManagerService> UnlockLikeHomeRazorAsync(string vaultPath, string passphrase)
        {
            var vaultKey = VaultKeyRing.Unlock(vaultPath, passphrase);
            var blobKey = VaultKeyRing.DeriveSubkey(vaultKey, VaultKeyRing.BlobKeyInfo);
            var fieldKey = VaultKeyRing.DeriveSubkey(vaultKey, VaultKeyRing.FieldKeyInfo);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(vaultKey);

            var repo = new KekVaultRepository(blobKey, vaultPath);
            return await PasswordManagerService.CreateAsync(repo, new AesService(), fieldKey);
        }

        public void Dispose()
        {
            try { Directory.Delete(_appDataDir, recursive: true); } catch { /* best effort */ }
        }
    }
}
