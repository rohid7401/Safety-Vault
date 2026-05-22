using System.Text.Json;
using PasswordManager.Core.Configuration;
using PasswordManager.Core.Interfaces;
using PasswordManager.Core.Models;

namespace PasswordManager.Infrastructure.Persistence
{
    public class PgpVaultRepository : IVaultRepository
    {
        private readonly IPgpService _pgpService;
        private readonly string _vaultPath;
        private readonly string _publicKeyPath;
        private readonly string _privateKeyPath;
        private readonly string _passphrase;

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            WriteIndented = true
        };

        public PgpVaultRepository(IPgpService pgpService, VaultOptions options)
        {
            _pgpService = pgpService;
            _vaultPath = Path.Combine(options.DataFolderPath, "vault.data.pgp");
            _publicKeyPath = options.ResolvedPublicKeyPath;
            _privateKeyPath = options.ResolvedPrivateKeyPath;
            _passphrase = options.Passphrase;
        }

        public async Task<VaultData> LoadAsync()
        {
            if (!File.Exists(_vaultPath))
                return new VaultData();

            var encryptedBytes = await File.ReadAllBytesAsync(_vaultPath);
            var jsonBytes = _pgpService.DecryptBytes(encryptedBytes, _privateKeyPath, _passphrase);
            return JsonSerializer.Deserialize<VaultData>(jsonBytes, JsonOptions) ?? new VaultData();
        }

        public async Task SaveAsync(VaultData vault)
        {
            vault.Version = VaultData.CurrentVersion;
            var jsonBytes = JsonSerializer.SerializeToUtf8Bytes(vault, JsonOptions);
            var encryptedBytes = _pgpService.EncryptBytes(jsonBytes, _publicKeyPath);
            await File.WriteAllBytesAsync(_vaultPath, encryptedBytes);
        }
    }
}
