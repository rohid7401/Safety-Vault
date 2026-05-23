using PasswordManager.Core.Models;

namespace PasswordManager.Core.Interfaces
{
    public interface IKeyDirectoryService
    {
        /// <summary>Resolves the local key directory path inside the vault folder.</summary>
        string GetKeyDirectoryPath(string vaultPath);

        /// <summary>Lists every public key stored in the key directory.</summary>
        Task<List<PgpKeyInfo>> ListKeysAsync(string vaultPath);

        /// <summary>Imports a public key file into the directory, copying it under a stable name.</summary>
        Task<PgpKeyInfo> ImportKeyAsync(string vaultPath, string sourceKeyPath, string ownerLabel);

        /// <summary>Removes a key from the directory.</summary>
        Task RemoveKeyAsync(string vaultPath, string fileName);

        /// <summary>Publishes the vault's own public key into the directory under the user's label.</summary>
        Task<PgpKeyInfo> PublishOwnKeyAsync(string vaultPath, string ownPublicKeyPath, string ownerLabel);
    }
}
