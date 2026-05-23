using PasswordManager.Core.Models;

namespace PasswordManager.Core.Interfaces
{
    public interface IAuthService
    {
        /// <summary>Registers a brand-new account. Auto-creates the underlying vault folder.</summary>
        Task<UserAccount> RegisterAsync(string username, string email, string passphrase);

        /// <summary>Validates credentials against the global accounts file.</summary>
        Task<UserAccount> LoginAsync(string usernameOrEmail, string passphrase);

        /// <summary>True if any account with that username or email already exists.</summary>
        Task<bool> AccountExistsAsync(string usernameOrEmail);

        /// <summary>True if there is at least one registered account on this machine.</summary>
        Task<bool> AnyAccountExistsAsync();

        /// <summary>Lists the usernames of registered accounts (no secrets).</summary>
        Task<List<string>> ListUsernamesAsync();
    }
}
