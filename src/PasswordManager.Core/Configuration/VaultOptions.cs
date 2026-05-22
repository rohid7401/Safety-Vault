namespace PasswordManager.Core.Configuration
{
    public class VaultOptions
    {
        public string DataFolderPath { get; set; } = string.Empty;
        public string? PublicKeyPath { get; set; }
        public string? PrivateKeyPath { get; set; }
        public string Passphrase { get; set; } = string.Empty;

        public string ResolvedPublicKeyPath =>
            PublicKeyPath ?? Path.Combine(DataFolderPath, "public_key.asc");

        public string ResolvedPrivateKeyPath =>
            PrivateKeyPath ?? Path.Combine(DataFolderPath, "private_key.asc");
    }
}
