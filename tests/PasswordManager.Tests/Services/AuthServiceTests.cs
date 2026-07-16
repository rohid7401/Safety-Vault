using PasswordManager.Core.Configuration;
using PasswordManager.Infrastructure.Encryption;
using PasswordManager.Infrastructure.Services;
using Xunit;

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
        public async Task RegisterAsync_GeneratesPgpKeyPair()
        {
            var auth = CreateAuthService();
            var account = await auth.RegisterAsync("alice", "alice@example.com", Passphrase);

            Assert.True(File.Exists(Path.Combine(account.VaultPath, "public_key.asc")));
            Assert.True(File.Exists(Path.Combine(account.VaultPath, "private_key.asc")));
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

            await Assert.ThrowsAsync<UnauthorizedAccessException>(
                () => auth.LoginAsync("alice", "wrong-passphrase"));
        }

        [Fact]
        public async Task LoginAsync_UnknownAccount_ThrowsUnauthorizedAccessException()
        {
            var auth = CreateAuthService();
            await Assert.ThrowsAsync<UnauthorizedAccessException>(
                () => auth.LoginAsync("nobody", Passphrase));
        }

        [Fact]
        public async Task RegisterAsync_DuplicateUsername_Throws()
        {
            var auth = CreateAuthService();
            await auth.RegisterAsync("alice", "alice@example.com", Passphrase);

            await Assert.ThrowsAsync<InvalidOperationException>(
                () => auth.RegisterAsync("alice", "another@example.com", Passphrase));
        }

        // ─── N1: anti-enumeration (message only on this branch) ──────────────

        [Fact]
        public async Task LoginAsync_WrongPassphraseAndUnknownAccount_ProduceIdenticalMessage()
        {
            var auth = CreateAuthService();
            await auth.RegisterAsync("alice", "alice@example.com", Passphrase);

            var wrongPass = await Assert.ThrowsAsync<UnauthorizedAccessException>(
                () => auth.LoginAsync("alice", "wrong-passphrase"));
            var noAccount = await Assert.ThrowsAsync<UnauthorizedAccessException>(
                () => auth.LoginAsync("nobody", Passphrase));

            // The message must not reveal whether the account exists.
            Assert.Equal(wrongPass.Message, noAccount.Message);
            Assert.DoesNotContain("account", noAccount.Message, StringComparison.OrdinalIgnoreCase);
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

        public void Dispose()
        {
            try { Directory.Delete(_appDataDir, recursive: true); } catch { /* best effort */ }
        }
    }
}
