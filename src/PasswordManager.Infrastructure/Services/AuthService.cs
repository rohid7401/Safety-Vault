using System.Security.Cryptography;
using System.Text.Json;
using PasswordManager.Core.Configuration;
using PasswordManager.Core.Interfaces;
using PasswordManager.Core.Models;
using PasswordManager.Infrastructure.Encryption;
using PasswordManager.Infrastructure.Persistence;
using PasswordManager.Core.Exceptions;

namespace PasswordManager.Infrastructure.Services
{
    public class AuthService : IAuthService
    {
        /// <summary>Shortest passphrase accepted at registration. Shared with the message the
        /// user sees, so the rule and its wording can never drift apart.</summary>
        public const int MinPassphraseLength = 8;

        private readonly AuthOptions _options;

        // N2: serialize the load-modify-save of accounts.json so two concurrent operations
        // (e.g. two quick registrations) can't read the same list and clobber each other's
        // change (lost update). Static so it holds regardless of how many AuthService
        // instances exist in the process.
        private static readonly SemaphoreSlim AccountsLock = new(1, 1);

        public AuthService(AuthOptions options)
        {
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

        public async Task<UserAccount> RegisterAsync(string username, string email, string passphrase,
            IProgress<RegistrationStage>? progress = null)
        {
            if (string.IsNullOrWhiteSpace(username))
                throw new LocalizedArgumentException(AppErrorCode.UsernameRequired);
            if (string.IsNullOrWhiteSpace(email))
                throw new LocalizedArgumentException(AppErrorCode.EmailRequired);

            // Identifiers must carry no whitespace at all. Both are used to look the account up
            // at sign-in, and the username also names the vault's folder — a space anywhere in
            // either produces an account that looks fine and cannot be signed into, with nothing
            // to recover from because the vault is local and there is no reset.
            if (username.Any(char.IsWhiteSpace))
                throw new LocalizedArgumentException(AppErrorCode.UsernameHasSpaces);
            if (email.Any(char.IsWhiteSpace))
                throw new LocalizedArgumentException(AppErrorCode.EmailHasSpaces);
            if (!EmailAddress.IsValid(email))
                throw new LocalizedArgumentException(AppErrorCode.EmailInvalid);

            // "." and ".." survive filename sanitising and would resolve to the vaults folder
            // itself or its parent rather than a folder of their own.
            if (username.Trim('.').Length == 0)
                throw new LocalizedArgumentException(AppErrorCode.UsernameInvalid);

            if (string.IsNullOrWhiteSpace(passphrase) || passphrase.Length < MinPassphraseLength)
                throw new LocalizedArgumentException(AppErrorCode.PassphraseTooShort, MinPassphraseLength);

            // Spaces between words are the point of a passphrase; a space at either end is not.
            // It is invisible, easy for a phone keyboard to add on its own, and it is folded into
            // the key — so the account unlocks only if the same invisible character is reproduced
            // exactly. Rejected at registration rather than trimmed, because silently changing
            // someone's secret is worse than telling them.
            if (passphrase != passphrase.Trim())
                throw new LocalizedArgumentException(AppErrorCode.PassphrasePadded);

            await AccountsLock.WaitAsync();
            try
            {
                return await RegisterCoreAsync(username, email, passphrase, progress);
            }
            finally
            {
                AccountsLock.Release();
            }
        }

        private async Task<UserAccount> RegisterCoreAsync(string username, string email, string passphrase,
            IProgress<RegistrationStage>? progress)
        {
            var all = await LoadAllAsync();

            // Trimmed on both sides so a new "juan" cannot slip past an older, padded "juan ".
            if (all.Any(a => string.Equals(a.Username.Trim(), username.Trim(), StringComparison.OrdinalIgnoreCase)))
                throw new LocalizedInvalidOperationException(AppErrorCode.UsernameTaken);
            if (all.Any(a => string.Equals(a.Email.Trim(), email.Trim(), StringComparison.OrdinalIgnoreCase)))
                throw new LocalizedInvalidOperationException(AppErrorCode.EmailTaken);

            var vaultPath = _options.GetVaultPathFor(username);
            if (Directory.Exists(vaultPath) && Directory.EnumerateFileSystemEntries(vaultPath).Any())
                throw new LocalizedInvalidOperationException(AppErrorCode.VaultFolderExists);
            Directory.CreateDirectory(vaultPath);

            // The PGP key pair (an RSA-2048 generation, the slowest and most variable part of
            // what registration used to do) is no longer created here. It is only ever needed
            // for the "encrypt a file for a contact" feature, so it is now generated on demand
            // the first time that feature is used — see
            // PasswordManagerService.GenerateOwnPgpIdentityAsync. The vault itself is never
            // locked by PGP; see the Vault Key setup below.
            //
            // What is left below is still CPU-bound (Argon2id) and still runs off the calling
            // thread: inline it would block whichever thread called us — on Android that is the
            // UI thread, and the OS puts up "SafetyVault isn't responding" after five seconds.
            await Task.Run(() =>
            {
                // Set up the Vault Key: a random key wrapped by a passphrase-derived KEK
                // (Argon2id). There is deliberately no separate password hash anywhere (see
                // UserAccount) — the login check IS the KEK successfully unwrapping the Vault Key.
                progress?.Report(RegistrationStage.SecuringVault);
                var vaultKey = VaultKeyRing.Create(vaultPath, passphrase);
                try
                {
                    progress?.Report(RegistrationStage.Finishing);
                    var seed = new VaultData();
                    var blobKey = VaultKeyRing.DeriveSubkey(vaultKey, VaultKeyRing.BlobKeyInfo);
                    // KekVaultRepository takes ownership of blobKey and zeroizes it on Dispose.
                    using var repo = new KekVaultRepository(blobKey, vaultPath);
                    repo.SaveAsync(seed).GetAwaiter().GetResult();
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(vaultKey);
                }
            }).ConfigureAwait(false);

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

        public async Task<UserAccount?> FindAccountAsync(string usernameOrEmail)
        {
            var all = await LoadAllAsync();
            return all.FirstOrDefault(a => Matches(a, usernameOrEmail));
        }

        public async Task<UserAccount> LoginAsync(string usernameOrEmail, string passphrase)
        {
            var all = await LoadAllAsync();
            var account = all.FirstOrDefault(a => Matches(a, usernameOrEmail));

            // Anti-enumeration (N1): the same message and the same work in both failure
            // branches, so neither the wording nor the response time reveals whether the
            // account exists. The passphrase is verified cryptographically — it must unwrap
            // the Vault Key via its KEK; no separate password hash is consulted.
            //
            // Both branches are Argon2id, which is slow by design; off the calling thread so a
            // wrong passphrase on a phone does not freeze the screen (see RegisterCoreAsync).
            if (account is null)
            {
                // Match the real path's Argon2id cost.
                await Task.Run(() => VaultKeyRing.PerformDummyUnlock(passphrase)).ConfigureAwait(false);
                throw new LocalizedUnauthorizedAccessException(AppErrorCode.BadCredentials);
            }

            var unlocked = await Task.Run(() => VaultKeyRing.CanUnlock(account.VaultPath, passphrase))
                .ConfigureAwait(false);
            if (!unlocked)
                throw new LocalizedUnauthorizedAccessException(AppErrorCode.BadCredentials);

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

        public async Task DeleteAccountAsync(string username, string passphrase)
        {
            await AccountsLock.WaitAsync();
            try
            {
                var all = await LoadAllAsync();
                var account = all.FirstOrDefault(a =>
                    string.Equals(a.Username.Trim(), username.Trim(), StringComparison.OrdinalIgnoreCase));

                // Same anti-enumeration-shaped check as LoginAsync: an unknown username and a
                // wrong passphrase must fail identically.
                if (account is null)
                {
                    await Task.Run(() => VaultKeyRing.PerformDummyUnlock(passphrase)).ConfigureAwait(false);
                    throw new LocalizedUnauthorizedAccessException(AppErrorCode.BadCredentials);
                }

                var unlocked = await Task.Run(() => VaultKeyRing.CanUnlock(account.VaultPath, passphrase))
                    .ConfigureAwait(false);
                if (!unlocked)
                    throw new LocalizedUnauthorizedAccessException(AppErrorCode.BadCredentials);

                // Delete the vault folder before dropping the account entry: if this throws
                // (e.g. a locked file), the account stays intact and the user can retry, rather
                // than being left logged out with an orphaned, half-deleted vault on disk.
                if (Directory.Exists(account.VaultPath))
                    Directory.Delete(account.VaultPath, recursive: true);

                all.Remove(account);
                await SaveAllAsync(all);
            }
            finally
            {
                AccountsLock.Release();
            }
        }

        // ─── Internals ───────────────────────────────────────────────────────

        /// <summary>
        /// Both sides are trimmed. Registration now refuses whitespace, but an account created
        /// before that could still hold a padded identifier — comparing trimmed lets its owner
        /// sign in by typing the name they can actually see, and can never make a match that
        /// used to work stop working.
        /// </summary>
        private static bool Matches(UserAccount account, string identity)
        {
            var wanted = identity.Trim();
            return string.Equals(account.Username.Trim(), wanted, StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(account.Email.Trim(), wanted, StringComparison.OrdinalIgnoreCase);
        }

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
