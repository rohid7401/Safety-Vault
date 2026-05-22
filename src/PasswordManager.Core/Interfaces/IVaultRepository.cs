using PasswordManager.Core.Models;

namespace PasswordManager.Core.Interfaces
{
    public interface IVaultRepository
    {
        Task<VaultData> LoadAsync();
        Task SaveAsync(VaultData vault);
    }
}
