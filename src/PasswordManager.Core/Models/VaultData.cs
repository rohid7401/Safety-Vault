namespace PasswordManager.Core.Models
{
    public class VaultData
    {
        public int Version { get; set; } = VaultData.CurrentVersion;
        public string Algorithm { get; set; } = "AES-GCM-256";
        public List<VaultEntry> Entries { get; set; } = new();

        /// <summary>
        /// The account's own PGP key pair, armored. Stored inside the vault (protected by
        /// the same Vault Key as everything else) so it travels with the vault to any
        /// device that can unlock it with the passphrase, instead of being a device-local
        /// file that would need separate syncing. Used only for the "encrypt a file for a
        /// contact" feature — never for vault storage encryption itself.
        /// </summary>
        public string? PgpPublicKeyArmored { get; set; }
        public string? PgpPrivateKeyArmored { get; set; }

        // v5 replaces the fixed PasswordEntry with ServiceEntry (flexible multi-credential
        // entries). The old "password" discriminator is no longer registered, so pre-v5 vaults
        // holding PasswordEntry rows must be migrated via plaintext CSV export → import.
        public const int CurrentVersion = 5;
    }
}
