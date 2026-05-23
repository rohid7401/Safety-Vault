using System.Security.Cryptography;
using System.Text.Json;
using PasswordManager.Core.Configuration;
using PasswordManager.Core.Interfaces;
using PasswordManager.Core.Models;

namespace PasswordManager.Infrastructure.Services
{
    public class AuthService : IAuthService
    {
        private const int SaltBytes = 16;
        private const int HashBytes = 32;
        private const int Pbkdf2Iterations = 200_000;

        private readonly IPgpService _pgpService;
        private readonly AuthOptions _options;

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

            // 1. Hash passphrase
            var salt = RandomNumberGenerator.GetBytes(SaltBytes);
            var hash = HashPassphrase(passphrase, salt);

            // 2. Generate PGP key pair into the vault
            var publicKeyPath = Path.Combine(vaultPath, "public_key.asc");
            var privateKeyPath = Path.Combine(vaultPath, "private_key.asc");
            _pgpService.GenerateKeyPair(publicKeyPath, privateKeyPath, passphrase);

            // 3. Persist account
            var account = new UserAccount
            {
                Username = username,
                Email = email,
                Salt = Convert.ToBase64String(salt),
                PassphraseHash = Convert.ToBase64String(hash),
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
            var account = all.FirstOrDefault(a => Matches(a, usernameOrEmail))
                ?? throw new UnauthorizedAccessException("No account found with that username or email.");

            var salt = Convert.FromBase64String(account.Salt);
            var expectedHash = Convert.FromBase64String(account.PassphraseHash);
            var actualHash = HashPassphrase(passphrase, salt);

            if (!CryptographicOperations.FixedTimeEquals(expectedHash, actualHash))
                throw new UnauthorizedAccessException("Incorrect passphrase.");

            // Heal vault folder if missing (defensive)
            if (!Directory.Exists(account.VaultPath))
                Directory.CreateDirectory(account.VaultPath);

            account.LastLogin = DateTime.UtcNow;
            await SaveAllAsync(all);
            return account;
        }

        // ─── Internals ───────────────────────────────────────────────────────

        private static byte[] HashPassphrase(string passphrase, byte[] salt) =>
            Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, Pbkdf2Iterations, HashAlgorithmName.SHA256, HashBytes);

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
            await File.WriteAllTextAsync(_options.AccountsFilePath, json);
        }
    }
}
