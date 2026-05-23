namespace PasswordManager.Core.Configuration
{
    /// <summary>
    /// Where SecureVault stores user accounts and their auto-created vaults.
    /// Set during DI from the host (e.g. MAUI passes FileSystem.AppDataDirectory).
    /// </summary>
    public class AuthOptions
    {
        /// <summary>Root folder for the application data (accounts file + vaults).</summary>
        public string AppDataPath { get; set; } = string.Empty;

        public string AccountsFilePath => Path.Combine(AppDataPath, "accounts.json");
        public string VaultsRootPath => Path.Combine(AppDataPath, "Vaults");

        public string GetVaultPathFor(string username) =>
            Path.Combine(VaultsRootPath, Sanitize(username));

        private static string Sanitize(string name)
        {
            var invalid = Path.GetInvalidFileNameChars();
            return string.Concat(name.Select(c => invalid.Contains(c) ? '_' : c));
        }
    }
}
