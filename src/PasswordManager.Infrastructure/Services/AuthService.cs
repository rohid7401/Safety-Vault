using System.Security.Cryptography;
using System.Text.Json;
using PasswordManager.Core.Configuration;
using PasswordManager.Core.Interfaces;
using PasswordManager.Core.Models;
using PasswordManager.Infrastructure.Encryption;
using PasswordManager.Infrastructure.Persistence;

namespace PasswordManager.Infrastructure.Services
{
    public class AuthService : IAuthService
    {
        private readonly IPgpService _pgpService;
        private readonly AuthOptions _options;

        // N2: serialize the load-modify-save of accounts.json so two concurrent operations
        // (e.g. two quick registrations) can't read the same list and clobber each other's
        // change (lost update). Static so it holds regardless of how many AuthService
        // instances exist in the process.
        private static readonly SemaphoreSlim AccountsLock = new(1, 1);

        public AuthService(IPgpService pgpService, AuthOptions options)
        {
            _pgpService = pgpService;
            _options = options;
            Directory.CreateDirectory(_options.AppDataPath);
            Directory.CreateDirectory(_options.VaultsRootPath);
        }

        public async Task<bool> AnyAccountExistsAsync()
        {
            var all = await LoadAllAsync();
            return all.Count > 0;
        }

        public async Task<bool> AccountExistsAsync(string usernameOrEmail)
        {
            var all = await LoadAllAsync();
            return all.Any(a => Matches(a, usernameOrEmail));
        }

        public async Task<List<string>> ListUsernamesAsync()
        {
            var all = await LoadAllAsync();
            return all.Select(a => a.Username).ToList();
        }

        public async Task<UserAccount> RegisterAsync(string username, string email, string passphrase)
        {
            if (string.IsNullOrWhiteSpace(username))
                throw new ArgumentException("Username is required.");
            if (string.IsNullOrWhiteSpace(email))
                throw new ArgumentException("Email is required.");
            if (string.IsNullOrWhiteSpace(passphrase) || passphrase.Length < 8)
                throw new ArgumentException("Passphrase must be at least 8 characters.");

            await AccountsLock.WaitAsync();
            try
            {
                return await RegisterCoreAsync(username, email, passphrase);
            }
            finally
            {
                AccountsLock.Release();
            }
        }

        private async Task<UserAccount> RegisterCoreAsync(string username, string email, string passphrase)
        {
            var all = await LoadAllAsync();

            if (all.Any(a => string.Equals(a.Username, username, StringComparison.OrdinalIgnoreCase)))
                throw new InvalidOperationException("That username is already registered on this device.");
            if (all.Any(a => string.Equals(a.Email, email, StringComparison.OrdinalIgnoreCase)))
                throw new InvalidOperationException("That email is already registered on this device.");

            var vaultPath = _options.GetVaultPathFor(username);
            if (Directory.Exists(vaultPath) && Directory.EnumerateFileSystemEntries(vaultPath).Any())
                throw new InvalidOperationException(
                    "A vault folder already exists for this username. Please choose a different username.");
            Directory.CreateDirectory(vaultPath);

            // Generate the PGP key pair used only for encrypting files for contacts. The
            // vault itself is never locked by PGP — see the Vault Key setup below.
            var publicKeyPath = Path.Combine(vaultPath, "public_key.asc");
            var privateKeyPath = Path.Combine(vaultPath, "private_key.asc");
            _pgpService.GenerateKeyPair(publicKeyPath, privateKeyPath, passphrase);

            // Set up the Vault Key: a random key wrapped by a passphrase-derived KEK
            // (Argon2id). There is deliberately no separate password hash anywhere (see
            // UserAccount) — the login check IS the KEK successfully unwrapping the Vault Key.
            var vaultKey = VaultKeyRing.Create(vaultPath, passphrase);
            try
            {
                // Seed the vault with the PGP key pair so it travels with the vault to any
                // device that can unlock it — no separate key-file sync needed.
                var seed = new VaultData
                {
                    PgpPublicKeyArmored = await File.ReadAllTextAsync(publicKeyPath),
                    PgpPrivateKeyArmored = await File.ReadAllTextAsync(privateKeyPath),
                };
                var blobKey = VaultKeyRing.DeriveSubkey(vaultKey, VaultKeyRing.BlobKeyInfo);
                // KekVaultRepository takes ownership of blobKey and zeroizes it on Dispose.
                using var repo = new KekVaultRepository(blobKey, vaultPath);
                await repo.SaveAsync(seed);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(vaultKey);
            }

            var account = new UserAccount
            {
                Username = username,
                Email = email,
                CreatedAt = DateTime.UtcNow,
                LastLogin = DateTime.UtcNow,
                VaultPath = vaultPath,
            };

            all.Add(account);
            await SaveAllAsync(all);
            return account;
        }

        public async Task<UserAccount> LoginAsync(string usernameOrEmail, string passphrase)
        {
            var all = await LoadAllAsync();
            var account = all.FirstOrDefault(a => Matches(a, usernameOrEmail));

            // Anti-enumeration (N1): the same message and the same work in both failure
            // branches, so neither the wording nor the response time reveals whether the
            // account exists. The passphrase is verified cryptographically — it must unwrap
            // the Vault Key via its KEK; no separate password hash is consulted.
            const string genericFailure = "Incorrect username/email or passphrase.";

            if (account is null)
            {
                VaultKeyRing.PerformDummyUnlock(passphrase); // match the real path's Argon2id cost
                throw new UnauthorizedAccessException(genericFailure);
            }

            if (!VaultKeyRing.CanUnlock(account.VaultPath, passphrase))
                throw new UnauthorizedAccessException(genericFailure);

            // Update LastLogin under the same lock/atomic-write path as registration (N2),
            // re-reading inside the lock so we don't clobber a concurrent change.
            await AccountsLock.WaitAsync();
            try
            {
                var fresh = await LoadAllAsync();
                var stored = fresh.FirstOrDefault(a => a.Username.Equals(account.Username, StringComparison.OrdinalIgnoreCase));
                if (stored is not null)
                {
                    stored.LastLogin = DateTime.UtcNow;
                    account = stored;
                    await SaveAllAsync(fresh);
                }
            }
            finally
            {
                AccountsLock.Release();
            }

            return account;
        }

        // ─── Internals ───────────────────────────────────────────────────────

        private static bool Matches(UserAccount account, string identity) =>
            string.Equals(account.Username, identity, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(account.Email, identity, StringComparison.OrdinalIgnoreCase);

        private async Task<List<UserAccount>> LoadAllAsync()
        {
            if (!File.Exists(_options.AccountsFilePath))
                return new List<UserAccount>();

            try
            {
                var json = await File.ReadAllTextAsync(_options.AccountsFilePath);
                if (string.IsNullOrWhiteSpace(json))
                    return new List<UserAccount>();

                var accounts = JsonSerializer.Deserialize<List<UserAccount>>(json);
                return accounts ?? new List<UserAccount>();
            }
            catch
            {
                return new List<UserAccount>();
            }
        }

        private async Task SaveAllAsync(List<UserAccount> accounts)
        {
            var json = JsonSerializer.Serialize(accounts, new JsonSerializerOptions { WriteIndented = true });

            // N2: atomic write (temp file + move) so a crash mid-write never leaves a
            // truncated / corrupt accounts.json.
            var path = _options.AccountsFilePath;
            var tmp = path + ".tmp";
            await File.WriteAllTextAsync(tmp, json);
            File.Move(tmp, path, overwrite: true);
        }
    }
}
