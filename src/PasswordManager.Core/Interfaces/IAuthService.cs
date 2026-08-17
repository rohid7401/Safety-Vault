using PasswordManager.Core.Models;

namespace PasswordManager.Core.Interfaces
{
    public interface IAuthService
    {
        /// <summary>
        /// Registers a brand-new account. Auto-creates the underlying vault folder. The
        /// cryptographic work runs off the calling thread, so a UI caller stays responsive;
        /// <paramref name="progress"/> reports which stage is running and is invoked from a
        /// background thread, so a UI handler must marshal before touching component state.
        /// </summary>
        Task<UserAccount> RegisterAsync(string username, string email, string passphrase,
            IProgress<RegistrationStage>? progress = null);

        /// <summary>
        /// Validates credentials against the global accounts file. The Argon2id verification
        /// runs off the calling thread — it is deliberately slow, and on a phone it is more
        /// than enough to trip the OS "app is not responding" watchdog if run inline.
        /// </summary>
        Task<UserAccount> LoginAsync(string usernameOrEmail, string passphrase);

        /// <summary>True if any account with that username or email already exists.</summary>
        Task<bool> AccountExistsAsync(string usernameOrEmail);

        /// <summary>True if there is at least one registered account on this machine.</summary>
        Task<bool> AnyAccountExistsAsync();

        /// <summary>Lists the usernames of registered accounts (no secrets).</summary>
        Task<List<string>> ListUsernamesAsync();

        /// <summary>
        /// The stored account for a username, or null. Carries no secret — the vault folder and
        /// the dates, nothing that unlocks anything — so it needs no passphrase to call. Quick
        /// unlock uses it to find which vault a hardware slot belongs to before anything is typed.
        /// </summary>
        Task<UserAccount?> FindAccountAsync(string usernameOrEmail);

        /// <summary>
        /// Permanently deletes an account and its vault folder — the account entry, the
        /// keyring, and every credential/note/card it held. Re-verifies the passphrase first
        /// (the same check as <see cref="LoginAsync"/>) so this cannot be triggered by anything
        /// short of proving ownership again, even from an already-unlocked session. Irreversible.
        /// </summary>
        Task DeleteAccountAsync(string username, string passphrase);
    }
}
