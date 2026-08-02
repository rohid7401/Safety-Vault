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
            new(new AuthOptions { AppDataPath = _appDataDir });

        [Fact]
        public async Task RegisterAsync_CreatesVaultKeyring()
        {
            var auth = CreateAuthService();
            var account = await auth.RegisterAsync("alice", "alice@example.com", Passphrase);

            Assert.True(File.Exists(Path.Combine(account.VaultPath, "vault.keyring.json")));
        }

        /// <summary>
        /// PGP key generation (RSA-2048, the slowest and most variable-duration part of what
        /// registration used to do) no longer happens here — see
        /// PasswordManagerServiceTests.GenerateOwnPgpIdentityAsync_* for where it lives now.
        /// Most accounts never touch the file-encryption feature it exists for.
        /// </summary>
        [Fact]
        public async Task RegisterAsync_DoesNotGeneratePgpIdentity()
        {
            var auth = CreateAuthService();
            var account = await auth.RegisterAsync("alice", "alice@example.com", Passphrase);

            var vaultKey = VaultKeyRing.Unlock(account.VaultPath, Passphrase);
            var blobKey = VaultKeyRing.DeriveSubkey(vaultKey, VaultKeyRing.BlobKeyInfo);
            using var repo = new KekVaultRepository(blobKey, account.VaultPath);
            var vault = await repo.LoadAsync();

            Assert.True(string.IsNullOrEmpty(vault.PgpPublicKeyArmored));
            Assert.True(string.IsNullOrEmpty(vault.PgpPrivateKeyArmored));
            Assert.False(File.Exists(Path.Combine(account.VaultPath, "public_key.asc")));
            Assert.False(File.Exists(Path.Combine(account.VaultPath, "private_key.asc")));
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

        // ─── Whitespace in identifiers and passphrase ──────────────────────

        [Theory]
        [InlineData("juan perez")]   // inside
        [InlineData(" juan")]        // leading
        [InlineData("juan ")]        // trailing — invisible, the dangerous one
        [InlineData("juan\tperez")]
        public async Task RegisterAsync_UsernameWithWhitespace_Rejected(string username)
        {
            var auth = CreateAuthService();

            var ex = await Assert.ThrowsAsync<LocalizedArgumentException>(
                () => auth.RegisterAsync(username, "a@example.com", Passphrase));

            Assert.Equal(AppErrorCode.UsernameHasSpaces, ex.Code);
        }

        [Theory]
        [InlineData("a b@example.com")]
        [InlineData("a@example.com ")]
        public async Task RegisterAsync_EmailWithWhitespace_Rejected(string email)
        {
            var auth = CreateAuthService();

            var ex = await Assert.ThrowsAsync<LocalizedArgumentException>(
                () => auth.RegisterAsync("alice", email, Passphrase));

            Assert.Equal(AppErrorCode.EmailHasSpaces, ex.Code);
        }

        [Theory]
        [InlineData(" correct-horse-battery")]
        [InlineData("correct-horse-battery ")]
        [InlineData("correct-horse-battery\n")]
        public async Task RegisterAsync_PassphrasePaddedWithWhitespace_Rejected(string passphrase)
        {
            // The failure this prevents: the padding is folded into the key, so the vault only
            // ever opens again for someone who reproduces a character they cannot see.
            var auth = CreateAuthService();

            var ex = await Assert.ThrowsAsync<LocalizedArgumentException>(
                () => auth.RegisterAsync("alice", "a@example.com", passphrase));

            Assert.Equal(AppErrorCode.PassphrasePadded, ex.Code);
        }

        [Fact]
        public async Task RegisterAsync_PassphraseWithSpacesBetweenWords_IsAccepted()
        {
            // Several words is exactly what the app tells people to use, so this must keep working.
            var auth = CreateAuthService();

            var account = await auth.RegisterAsync("alice", "a@example.com", "correct horse battery staple");

            Assert.Equal("alice", account.Username);
            Assert.NotNull(await auth.LoginAsync("alice", "correct horse battery staple"));
        }

        [Theory]
        [InlineData("juana")]
        [InlineData("juana@")]
        [InlineData("@example.com")]
        [InlineData("juana@example")]
        public async Task RegisterAsync_MalformedEmail_Rejected(string email)
        {
            var auth = CreateAuthService();

            var ex = await Assert.ThrowsAsync<LocalizedArgumentException>(
                () => auth.RegisterAsync("alice", email, Passphrase));

            Assert.Equal(AppErrorCode.EmailInvalid, ex.Code);
        }

        [Theory]
        [InlineData(".")]
        [InlineData("..")]
        public async Task RegisterAsync_DottedUsername_Rejected(string username)
        {
            // These survive filename sanitising and would point at the vaults folder or its parent
            // instead of a folder of their own.
            var auth = CreateAuthService();

            var ex = await Assert.ThrowsAsync<LocalizedArgumentException>(
                () => auth.RegisterAsync(username, "a@example.com", Passphrase));

            Assert.Equal(AppErrorCode.UsernameInvalid, ex.Code);
        }

        [Fact]
        public async Task LoginAsync_IdentityTypedWithSurroundingSpaces_StillFindsTheAccount()
        {
            var auth = CreateAuthService();
            await auth.RegisterAsync("alice", "alice@example.com", Passphrase);

            Assert.Equal("alice", (await auth.LoginAsync("  alice  ", Passphrase)).Username);
            Assert.Equal("alice", (await auth.LoginAsync(" alice@example.com ", Passphrase)).Username);
        }

        // ─── Delete account ────────────────────────────────────────────────

        [Fact]
        public async Task DeleteAccountAsync_CorrectPassphrase_RemovesAccountAndVaultFolder()
        {
            var auth = CreateAuthService();
            var account = await auth.RegisterAsync("alice", "alice@example.com", Passphrase);

            await auth.DeleteAccountAsync("alice", Passphrase);

            Assert.False(await auth.AccountExistsAsync("alice"));
            Assert.False(Directory.Exists(account.VaultPath));
        }

        [Fact]
        public async Task DeleteAccountAsync_WrongPassphrase_ThrowsAndKeepsAccount()
        {
            var auth = CreateAuthService();
            await auth.RegisterAsync("alice", "alice@example.com", Passphrase);

            var ex = await Assert.ThrowsAsync<LocalizedUnauthorizedAccessException>(
                () => auth.DeleteAccountAsync("alice", "wrong-passphrase"));

            Assert.Equal(AppErrorCode.BadCredentials, ex.Code);
            Assert.True(await auth.AccountExistsAsync("alice"));
        }

        [Fact]
        public async Task DeleteAccountAsync_UnknownUsername_ThrowsBadCredentials()
        {
            var auth = CreateAuthService();

            var ex = await Assert.ThrowsAsync<LocalizedUnauthorizedAccessException>(
                () => auth.DeleteAccountAsync("nobody", Passphrase));

            Assert.Equal(AppErrorCode.BadCredentials, ex.Code);
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
        /// re-derive the same keys → confirm the entry is still there.
        /// </summary>
        [Fact]
        public async Task FullFlow_RegisterAddEntryThenLoginAgain_EntryPersists()
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

            var entries = await svc2.GetAllEntriesAsync();
            Assert.Single(entries);
            var entry = Assert.IsType<ServiceEntry>(entries[0]);
            Assert.Equal("s3cret", svc2.DecryptSecret(entry.Credentials[0].Fields[0]));
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
